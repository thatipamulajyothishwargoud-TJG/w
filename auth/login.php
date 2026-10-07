<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
sendNoCacheHeaders();
checkIpBlock();
startSecureSession();

$portals = [
    'employee' => ['label' => 'Employee', 'role' => 'employee', 'route' => '/auth/employee-login.php'],
    'hr' => ['label' => 'HR Manager', 'role' => 'hr_admin', 'route' => '/auth/hr-login.php'],
    'admin' => ['label' => 'Administrator', 'role' => 'super_admin', 'route' => '/auth/administrator-login.php'],
];
$portalValue = $_GET['portal'] ?? $_POST['portal'] ?? '';
$portal = is_string($portalValue) ? $portalValue : '';
if (!isset($portals[$portal])) $portal = '';
$portalMismatchRoute = '';

if (!empty($_SESSION['user_id'])) {
    $dest = roleDashboardPath((string)($_SESSION['role'] ?? 'employee'));
    header('Location: ' . APP_URL . $dest); exit;
}

$error = ''; $timeout = isset($_GET['timeout']);

guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
checkHoneypot();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken();
    $ip    = getClientIpSecure();
    $email = sanitizeEmail($_POST['email'] ?? '');
    $pass  = $_POST['password'] ?? '';

    if (rateLimitExceeded('login_ip:' . $ip, 10, 900)) {
        $error = 'Too many login attempts from your IP. Please wait 15 minutes.';
        auditLog('rate_limit_login', null, null, ['ip' => $ip]);
    } elseif ($email && rateLimitExceeded('login_email:' . $email, 5, 900)) {
        $error = 'Too many failed attempts for this account. Please wait 15 minutes.';
    } elseif (!$email || !$pass) {
        $error = 'Email and password are required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Invalid email format.';
    } else {
        $db   = getDB();
        $stmt = $db->prepare(
            "SELECT id,full_name,email,password_hash,role,status,email_verified,failed_logins,locked_until,force_password_change
             FROM users WHERE LOWER(email)=LOWER(?) LIMIT 1"
        );
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        $dummy = '$2y$12$invalidhashpaddingtomatchbcryptlengthXXXXXXXXXXXXXXXXXX';
        $ok    = password_verify($pass, $user ? ($user['password_hash'] ?? $dummy) : $dummy);

        if (!$user || !$ok) {
            if ($user) {
                $fails = (int)$user['failed_logins'] + 1;
                if ($fails >= 5) {
                    $lock = date('Y-m-d H:i:s', strtotime('+15 minutes'));
                    $db->prepare("UPDATE users SET failed_logins=?,status='locked',locked_until=? WHERE id=?")->execute([$fails,$lock,$user['id']]);
                    $error = 'Account locked after 5 failed attempts. Try again in 15 minutes.';
                } else {
                    $db->prepare("UPDATE users SET failed_logins=? WHERE id=?")->execute([$fails,$user['id']]);
                    // Deliberately identical to the "no such account" message below —
                    // an "N attempts remaining" suffix here would let an attacker
                    // fingerprint which emails are registered from a single failed login.
                    $error = 'Invalid email or password.';
                }
            } else {
                $error = 'Invalid email or password.';
            }
            auditLog('login_failed', 'users', $user['id'] ?? null, ['ip' => $ip]);
        } elseif ($portal !== '' && $user['role'] !== $portals[$portal]['role']) {
            $rolePortal = match ($user['role']) {
                'employee' => 'employee',
                'hr_admin' => 'hr',
                default => 'admin',
            };
            $portalMismatchRoute = $portals[$rolePortal]['route'];
            $error = 'This account belongs to the ' . $portals[$rolePortal]['label'] . ' portal. Use its sign-in page.';
        } elseif ($user['status'] === 'deactivated') {
            $error = 'This account has been deactivated. Contact HR.';
        } elseif ($user['status'] === 'locked' && $user['locked_until'] && strtotime($user['locked_until']) > time()) {
            $mins = ceil((strtotime($user['locked_until']) - time()) / 60);
            $error = "Account locked. Try again in {$mins} minute(s).";
        } elseif (!$user['email_verified']
                  && !in_array($user['role'], ['hr_admin', 'super_admin'], true)
                  && empty($user['force_password_change'])) {
            // Admin-created accounts (force_password_change=1) skip this gate —
            // their email is auto-verified silently on first login below.
            $error      = 'Please verify your email before signing in.';
                    $resendLink = APP_URL . '/auth/resend_verify.php?email=' . urlencode($user['email']);
        } else {
            // Successful logins must not accumulate as failed-attempt limits.
            // Preserve the IP's previous failures while removing this valid attempt.
            $db->prepare("UPDATE rate_limit SET attempts=GREATEST(attempts-1,0) WHERE `key`=?")->execute(['login_ip:' . $ip]);
            $db->prepare("DELETE FROM rate_limit WHERE `key`=?")->execute(['login_email:' . $email]);
            // For admin-created accounts: auto-verify email on first login, then force password change.
            $db->prepare(
                "UPDATE users
                 SET failed_logins = 0,
                     status = 'active',
                     locked_until = NULL,
                     email_verified = CASE
                         WHEN role IN ('hr_admin', 'super_admin') THEN 1
                         WHEN force_password_change = 1 THEN 1
                         ELSE email_verified
                     END,
                     verify_token = CASE
                         WHEN force_password_change = 1 THEN NULL
                         ELSE verify_token
                     END,
                     verify_token_expiry = CASE
                         WHEN force_password_change = 1 THEN NULL
                         ELSE verify_token_expiry
                     END
                 WHERE id = ?"
            )->execute([$user['id']]);
            session_regenerate_id(true);
            // Track last login time and IP (Layer 2 audit trail)
            $lastLoginIp = '';
            try {
                $ipRow = $db->prepare("SELECT last_login_ip FROM users WHERE id = ? LIMIT 1");
                $ipRow->execute([$user['id']]);
                $lastLoginIp = (string)($ipRow->fetchColumn() ?: '');
                $db->prepare("UPDATE users SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?")
                   ->execute([$ip, $user['id']]);
            } catch (\Throwable) { /* non-fatal */ }
            $_SESSION['user_id']     = (int)$user['id'];
            $_SESSION['role']        = $user['role'];
            $_SESSION['name']        = $user['full_name'];
            $_SESSION['email']       = $user['email'];
            $_SESSION['last_active'] = time();
            $_SESSION['_regenerated_at'] = time();
            $_SESSION['_initiated']  = true;
            markReAuthenticated(); // fresh login counts as re-auth
            // Track session in DB for concurrent-session management
            ensureSessionsTableHasUserAgent();
            trackSession((int)$user['id'], $ip);
            enforceConcurrentSessionLimit((int)$user['id'], 3);
            // Alert user if logging in from a new IP address
            sendNewLoginAlert((int)$user['id'], $ip, $user['email'], $user['full_name'], $lastLoginIp);
            // Flag users who must change their temporary password immediately
            if (!empty($user['force_password_change'])) {
                $_SESSION['force_password_change'] = 1;
            }
            auditLog('login_success', 'users', (int)$user['id'], ['ip' => $ip]);
            // Redirect to forced password change if needed
            if (!empty($_SESSION['force_password_change'])) {
                header('Location: ' . APP_URL . '/auth/change_password.php'); exit;
            }
            if (userProfileRequiresCompletion((int)$user['id'])) {
                header('Location: ' . APP_URL . '/employee/profile.php?complete=1'); exit;
            }
            $next = $_GET['next'] ?? '';
            $dest = roleDashboardPath((string)$user['role']);
            if ($next && preg_match('#^/[a-zA-Z0-9/_\-.]+\.php$#', $next) && strpos($next,'//') === false && strpos($next,'..') === false) {
                $hrAdminDashboard = $user['role'] === 'hr_admin' && $next === '/admin/dashboard.php';
                if ($portal === '' && !$hrAdminDashboard) $dest = $next;
            }
            header('Location: ' . APP_URL . $dest); exit;
        }
    }
}

$portalTitle = $portal !== '' ? $portals[$portal]['label'] . ' Sign In' : 'Sign In';
pageHead($portalTitle);
?>
<body class="reference-login">
<div class="auth-shell">
  <div class="auth-panel">
    <div class="reference-login-art" data-reference-sculpture aria-hidden="true"></div>
    <div class="auth-panel-logo"><img src="/assets/img/logo.png" alt="CloudFen"></div>
    <a class="reference-home-link" href="/">Home ↗</a>
    <h2>A new level of work.<br><span>Built around people.</span></h2>
    <p>People, time, and progress.<br>Connected in one workspace.</p>
    <div class="auth-features">
      <div class="auth-feature-item"><span class="feat-dot">📁</span> Document submission &amp; review</div>
      <div class="auth-feature-item"><span class="feat-dot">⏱️</span> Timesheet tracking &amp; approvals</div>
      <div class="auth-feature-item"><span class="feat-dot">🔔</span> Real-time notifications</div>
      <div class="auth-feature-item"><span class="feat-dot">🔒</span> I-9 &amp; work authorization alerts</div>
    </div>
  </div>
  <div class="auth-form-wrap">
    <h1><?= e($portalTitle) ?></h1>
    <p class="sub"><?= $portal !== '' ? 'Sign in to your ' . e($portals[$portal]['label']) . ' workspace.' : 'Choose your workspace to continue.' ?> Questions? <a href="<?= e(getHrContactUrl()) ?>">Contact HR</a></p>
    <nav class="portal-login-grid" aria-label="Choose a sign-in portal">
      <?php foreach ($portals as $key => $item): ?>
      <a href="<?= e($item['route']) ?>" class="portal-login-option<?= $portal === $key ? ' is-active' : '' ?>"<?= $portal === $key ? ' aria-current="page"' : '' ?>>
        <strong><?= e($item['label']) ?></strong><span><?= $key === 'employee' ? 'My work &amp; profile' : ($key === 'hr' ? 'People operations' : 'Workspace controls') ?></span>
      </a>
      <?php endforeach; ?>
    </nav>
    <?php if ($timeout): ?><div class="alert alert-warn">⏱️ Session expired. Please sign in again.</div><?php endif; ?>
    <?php if (isset($_GET['security'])): ?><div class="alert alert-warn">🔒 Session invalidated for security. Please sign in again.</div><?php endif; ?>
    <?php if (isset($_GET['deactivated'])): ?><div class="alert alert-warn">🔒 This account has been deactivated. Contact HR.</div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-error">⚠️ <?= e($error) ?><?php if ($portalMismatchRoute): ?> <a href="<?= e($portalMismatchRoute) ?>" style="font-weight:700;">Go to that portal →</a><?php endif; ?><?php if (!empty($resendLink)): ?> <a href="<?= e($resendLink) ?>" style="color:var(--cyan);font-weight:700;">Resend verification email →</a><?php endif; ?></div><?php endif; ?>
    <?php if (defined('APP_DEMO_MODE') && APP_DEMO_MODE): ?>
    <p class="demo-login-note">Fictional demo workspace. Choose a demo profile, then enter the demo password.</p>
    <div class="demo-role-picker" role="group" aria-label="Choose demo sign-in role">
      <?php if ($portal === '' || $portal === 'employee'): ?><button type="button" data-email="demo.ava.bennett@example.invalid" aria-pressed="false">Employee demo</button><?php endif; ?>
      <?php if ($portal === '' || $portal === 'hr'): ?><button type="button" data-email="demo.hr@example.invalid" aria-pressed="false">HR Manager demo</button><?php endif; ?>
      <?php if ($portal === '' || $portal === 'admin'): ?><button type="button" data-email="demo.admin@example.invalid" aria-pressed="false">Administrator demo</button><?php endif; ?>
    </div>
    <?php endif; ?>
    <form method="POST" autocomplete="off" data-loading>
      <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
      <?php if ($portal !== ''): ?><input type="hidden" name="portal" value="<?= e($portal) ?>"><?php endif; ?>
      <?= honeypotField() ?>
      <div class="form-group">
        <label>Email Address</label>
        <input type="email" name="email" class="form-control" placeholder="you@email.com"
               required autofocus value="<?= e($_POST['email'] ?? '') ?>" autocomplete="username">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" class="form-control" placeholder="••••••••" required autocomplete="current-password">
      </div>
      <div style="text-align:right;margin-bottom:20px;">
        <a href="/auth/forgot.php" style="font-size:.88rem;color:var(--cyan);font-weight:600;">Forgot password?</a>
      </div>
      <button type="submit" class="btn btn-primary btn-block">
        <span class="btn-text">Sign In →</span>
      </button>
    </form>
  </div>
</div>
<?php
$threeVer  = @filemtime(__DIR__ . '/../assets/js/vendor/three.min.js') ?: time();
$login3dVer = @filemtime(__DIR__ . '/../assets/js/login-3d.js') ?: time();
?>


<?php pageFooter(); ?><script src="/assets/js/demo-login.js"></script>
</body>
</html>
