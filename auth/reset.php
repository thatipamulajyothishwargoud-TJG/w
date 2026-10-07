<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
sendNoCacheHeaders();
checkIpBlock();
startSecureSession();
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
checkHoneypot();

$token   = trim($_GET['token'] ?? '');
$msg     = ''; $type = ''; $success = false;
$validToken = false; $tokenUser = null;

if (!$token || strlen($token) !== 64) {
    $msg = 'Invalid or missing reset token.'; $type = 'error';
} else {
    try {
        $db   = getDB();
        $stmt = $db->prepare(
            "SELECT id, full_name, email FROM users
             WHERE reset_token = ? AND reset_token_expiry > NOW()
             AND status NOT IN ('deactivated') LIMIT 1"
        );
        $stmt->execute([$token]);
        $tokenUser = $stmt->fetch();
        if ($tokenUser) $validToken = true;
        else { $msg = 'This reset link has expired or is invalid. Please request a new one.'; $type = 'error'; }
    } catch (\Throwable $e) {
        error_log('Reset token check error: ' . $e->getMessage());
        $msg = 'A server error occurred. Please try again.'; $type = 'error';
    }
}

if ($validToken && $_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true); // rotate token after use
    $pass1 = $_POST['password']  ?? '';
    $pass2 = $_POST['password2'] ?? '';

    if ($pass1 !== $pass2) {
        $msg = 'Passwords do not match.'; $type = 'error';
    } else {
        $pwErrors = validatePassword($pass1);
        if ($pwErrors) {
            $msg = implode(' ', $pwErrors); $type = 'error';
        } else {
            // Atomically claim + invalidate the token right before writing the
            // new password, instead of trusting the GET-time $tokenUser lookup —
            // that lookup happens well before the user finishes the form, leaving
            // the token valid (and replayable by a second request) for the whole
            // time in between.
            $claimedUser = claimPasswordResetToken($token);
            if (!$claimedUser) {
                $validToken = false;
                $msg = 'This reset link has already been used or has expired. Please request a new one.'; $type = 'error';
            } else {
                $hash = password_hash($pass1, PASSWORD_BCRYPT, ['cost' => 12]);
                try {
                    $db->prepare(
                        "UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expiry=NULL,
                         failed_logins=0, status='active' WHERE id=?"
                    )->execute([$hash, (int)$claimedUser['id']]);
                    auditLog('password_reset_success', 'users', (int)$claimedUser['id'], ['ip' => getClientIpSecure()]);
                    $success = true;
                    $msg = 'Password updated successfully! You can now sign in.'; $type = 'success';
                } catch (\Throwable $e) {
                    error_log('Password reset save error: ' . $e->getMessage());
                    $msg = 'Error updating password. Please try again.'; $type = 'error';
                }
            }
        }
    }
}

pageHead('Reset Password');
?>
<body>
<div class="auth-shell">
  <div class="auth-panel">
    <div class="auth-panel-logo"><img src="/assets/img/logo.png" alt="CloudFen"></div>
    <h2>Set a New<br><span>Password</span></h2>
    <p>Choose a strong password — at least 12 characters with uppercase, lowercase, a number, and a special character.</p>
  </div>
  <div class="auth-form-wrap">
    <h1>New Password</h1>
    <p class="sub"><a href="/auth/login.php">← Back to Sign In</a></p>

    <?php if ($success): ?>
      <div style="text-align:center;padding:28px 0;">
        <div class="reset-success-icon">🔓</div>
        <div class="alert alert-success">✅ <?= e($msg) ?></div>
        <a href="/auth/login.php" class="btn btn-primary mt-6">Sign In Now →</a>
      </div>
    <?php elseif (!$validToken): ?>
      <div class="alert alert-error">⚠️ <?= e($msg) ?></div>
      <a href="/auth/forgot.php" class="btn btn-primary">Request New Reset Link →</a>
    <?php else: ?>
      <?php if ($msg && $type === 'error'): ?><div class="alert alert-error">⚠️ <?= e($msg) ?></div><?php endif; ?>
      <form method="POST" data-loading>
        <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
        <div class="form-group">
          <label>New Password</label>
          <input type="password" name="password" class="form-control" placeholder="Min 12 chars, upper/lower/number/special" required minlength="12" autocomplete="new-password">
        </div>
        <div class="form-group">
          <label>Confirm New Password</label>
          <input type="password" name="password2" class="form-control" placeholder="Repeat your password" required minlength="12" autocomplete="new-password">
        </div>
        <button type="submit" class="btn btn-primary btn-block">
          <span class="btn-text">Set New Password →</span>
        </button>
      </form>
    <?php endif; ?>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>