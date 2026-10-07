<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
checkIpBlock();
startSecureSession();

if (!empty($_SESSION['user_id'])) {
    header('Location: ' . APP_URL . roleDashboardPath((string)($_SESSION['role'] ?? 'employee'))); exit;
}

$msg = ''; $type = '';

$prefillEmail = sanitizeEmail($_GET['email'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken();
    $ip    = getClientIpSecure();
    $email = sanitizeEmail($_POST['email'] ?? '');

    if (rateLimitExceeded('resend_verify:' . $ip, 3, 900)) {
        $msg = 'Too many requests. Please wait 15 minutes.'; $type = 'error';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $msg = 'Please enter a valid email address.'; $type = 'error';
    } else {
        $db   = getDB();
        $stmt = $db->prepare(
            "SELECT id, full_name, email_verified FROM users
             WHERE LOWER(email) = LOWER(?) AND status != 'deactivated' LIMIT 1"
        );
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user && !$user['email_verified']) {
            // Generate fresh token (72h)
            $token  = bin2hex(random_bytes(32));
            $expiry = date('Y-m-d H:i:s', strtotime('+72 hours'));
            $db->prepare(
                "UPDATE users SET verify_token = ?, verify_token_expiry = ? WHERE id = ?"
            )->execute([$token, $expiry, $user['id']]);

            $appUrl = rtrim(APP_URL, '/');
            $link   = $appUrl . '/auth/verify.php?token=' . urlencode($token);
            $btnStyle = "background:#1fa0c0;color:#000;padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;";
            $body = emailTemplate('Verify Your Email', "
                <p>Hi <strong>" . htmlspecialchars($user['full_name'], ENT_QUOTES, 'UTF-8') . "</strong>,</p>
                <p>Click the button below to verify your email and activate your CloudFen HR Portal account.</p>
                <p><a href='" . htmlspecialchars($link, ENT_QUOTES, 'UTF-8') . "' style='{$btnStyle}'>✅ Verify My Email →</a></p>
                <p style='margin-top:12px;font-size:12px;color:#666;word-break:break-all;'>Or copy this link:<br>" . htmlspecialchars($link, ENT_QUOTES, 'UTF-8') . "</p>
                <p style='color:#888;font-size:13px;margin-top:16px;'>This link expires in <strong>72 hours</strong>. If you did not request this, ignore it.</p>
            ");
            sendMail($email, 'Verify Your Email - CloudFen HR Portal', $body);
            auditLog('verification_resent', 'users', (int)$user['id'], ['ip' => $ip]);
        }

        // Always show same message to prevent email enumeration
        $msg  = 'If an unverified account exists for that email, a new verification link has been sent. Check your inbox and spam folder.';
        $type = 'success';
    }
}

pageHead('Resend Verification');
?>
<body>
<div class="auth-shell">
  <div class="auth-panel">
    <div class="auth-panel-logo"><img src="/assets/img/logo.png" alt="CloudFen"></div>
    <h2>Verify Your<br><span>Email</span></h2>
    <p>Enter your email address and we'll send you a new verification link valid for 72 hours.</p>
  </div>
  <div class="auth-form-wrap">
    <h1>Resend Verification</h1>
    <p class="sub"><a href="/auth/login.php">← Back to Sign In</a></p>

    <?php if ($type === 'success'): ?>
      <div style="text-align:center;padding:28px 0;">
        <div style="font-size:3rem;margin-bottom:16px;">📬</div>
        <div class="alert alert-success">✅ <?= e($msg) ?></div>
        <a href="/auth/login.php" class="btn btn-primary" style="margin-top:20px;display:inline-block;">← Return to Sign In</a>
      </div>
    <?php else: ?>
      <?php if ($msg): ?><div class="alert alert-error">⚠️ <?= e($msg) ?></div><?php endif; ?>
      <form method="POST" data-loading>
        <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
        <div class="form-group">
          <label>Email Address</label>
          <input type="email" name="email" class="form-control"
                 placeholder="you@email.com"
                 required autofocus value="<?= e($prefillEmail) ?>" autocomplete="email">
        </div>
        <button type="submit" class="btn btn-primary btn-block">
          <span class="btn-text">Send Verification Link →</span>
        </button>
      </form>
    <?php endif; ?>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
