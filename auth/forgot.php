<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
sendNoCacheHeaders();
checkIpBlock();
startSecureSession();

// Redirect logged-in users
if (!empty($_SESSION['user_id'])) {
    header('Location: ' . APP_URL . roleDashboardPath((string)($_SESSION['role'] ?? 'employee'))); exit;
}

$db = getDB();
$msg = ''; $type = ''; $sent = false;

guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
checkHoneypot();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true); // rotate token after use
    $ip    = getClientIpSecure();
    $email = sanitizeEmail($_POST['email'] ?? '');

    if (rateLimitExceeded('forgot:' . $ip, 3, 900)) {
        $msg = 'Too many reset requests. Please wait 15 minutes.'; $type = 'error';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $msg = 'Please enter a valid email address.'; $type = 'error';
    } else {
        try {
            // timingSafeEmailLookup always takes the same time whether the email
            // exists or not — prevents user-enumeration via response timing.
            $user = timingSafeEmailLookup($email);
            if ($user && $user['status'] === 'deactivated') $user = null;

            if ($user) {
                $token  = bin2hex(random_bytes(32));
                $expiry = date('Y-m-d H:i:s', strtotime('+2 hours'));

                $db->prepare(
                    "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?"
                )->execute([$token, $expiry, $user['id']]);

                $link    = APP_URL . '/auth/reset.php?token=' . urlencode($token);
                $btnStyle = "background:#1fa0c0;color:#000;padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:8px;";
                $body    = "<p>Hi " . e($user['full_name']) . ",</p>
                            <p>We received a request to reset your <strong>CloudFen HR Portal</strong> password.</p>
                            <p>Click the button below to set a new password. This link expires in <strong>2 hours</strong>.</p>
                            <p><a href='" . e($link) . "' style='{$btnStyle}'>🔑 Reset My Password</a></p>
                            <p style='margin-top:20px;'>Or copy this link:<br><code style='font-size:12px;color:#666;word-break:break-all;'>" . e($link) . "</code></p>
                            <p style='color:#888;font-size:13px;margin-top:20px;'>If you did not request this, ignore this email — your password will not change.</p>";

                $mailSent = sendMail($email, 'Reset Your CloudFen Password', emailTemplate('Password Reset Request', $body));
                auditLog('password_reset_requested', 'users', (int)$user['id'], ['ip' => $ip, 'mail_sent' => $mailSent]);

                if (!$mailSent) {
                    // Log but still show generic success to prevent enumeration
                    error_log("CloudFen: Password reset email failed to send to: {$email}");
                }
            }
        } catch (\Throwable $e) {
            error_log('Forgot password error: ' . $e->getMessage());
        }
        // Always same message regardless of whether email exists
        $sent = true;
        $msg  = 'If an account exists for that email address, a password reset link has been sent. Check your inbox and spam folder.';
        $type = 'success';
    }
}

pageHead('Forgot Password');
?>
<body>
<div class="auth-shell">
  <div class="auth-panel">
    <div class="auth-panel-logo"><img src="/assets/img/logo.png" alt="CloudFen"></div>
    <h2>Reset Your<br><span>Password</span></h2>
    <p>Enter your registered email and we'll send you a secure reset link valid for 2 hours.</p>
    <div class="auth-features" style="margin-top:32px;">
      <div class="auth-feature-item"><span class="feat-dot">🔐</span> Secure 2-hour reset window</div>
      <div class="auth-feature-item"><span class="feat-dot">📧</span> Check inbox and spam folder</div>
      <div class="auth-feature-item"><span class="feat-dot">🔒</span> Password never revealed</div>
    </div>
  </div>
  <div class="auth-form-wrap">
    <h1>Forgot Password?</h1>
    <p class="sub"><a href="/auth/login.php">← Back to Sign In</a></p>

    <?php if ($sent): ?>
      <div style="text-align:center;padding:28px 0;">
        <div class="reset-success-icon">📬</div>
        <div class="alert alert-success" style="text-align:left;">✅ <?= e($msg) ?></div>
        <p style="font-size:.88rem;color:#777;margin-top:12px;line-height:1.6;">
          Didn't receive it? Check your <strong>spam folder</strong>, or
          <a href="/auth/forgot.php">try again</a>.
        </p>
        <a href="/auth/login.php" class="btn btn-primary mt-6">← Return to Sign In</a>
      </div>
    <?php else: ?>
      <?php if ($msg && $type === 'error'): ?>
        <div class="alert alert-error">⚠️ <?= e($msg) ?></div>
      <?php endif; ?>
      <form method="POST" data-loading>
        <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
        <div class="form-group">
          <label>Email Address</label>
          <input type="email" name="email" class="form-control"
                 placeholder="you@email.com"
                 required maxlength="180" autofocus autocomplete="email"
                 value="<?= e($_POST['email'] ?? '') ?>">
        </div>
        <button type="submit" class="btn btn-primary btn-block">
          <span class="btn-text">Send Reset Link →</span>
        </button>
      </form>
    <?php endif; ?>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
