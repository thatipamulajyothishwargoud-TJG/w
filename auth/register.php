<?php
/**
 * CloudFen HR Portal — Register
 * Public self-registration is DISABLED.
 * Only HR Admin / Super Admin can create accounts via /admin/super/users.php
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
checkIpBlock();
startSecureSession();

// Redirect already-logged-in users
if (!empty($_SESSION['user_id'])) {
    header('Location: ' . APP_URL . '/employee/dashboard.php');
    exit;
}

pageHead('Registration Disabled');
?>
<body>
<div class="auth-shell">
  <div class="auth-panel">
    <div class="auth-panel-logo"><img src="/assets/img/logo.png" alt="CloudFen" style="height:32px;width:auto;"></div>
    <h2>HR Portal<br>Employee Onboarding</h2>
    <p>Securely manage your employment documents, timesheets, and compliance — all in one place.</p>
  </div>
  <div class="auth-form-wrap" style="align-items:center;">
    <div class="reg-disabled-box">
      <span class="lock-icon">🔒</span>
      <h2>Account Creation Restricted</h2>
      <p>
        Self-registration is not available on this portal.<br>
        Your HR administrator will create your account and send
        you an invitation email with login credentials.
      </p>
      <div style="margin-top:28px;">
        <a href="/auth/login.php" class="btn btn-primary">← Back to Sign In</a>
      </div>
      <p style="margin-top:20px;font-size:.82rem;color:var(--gray-400);">
        Need help? Contact HR at
        <a href="<?= e(getHrContactUrl()) ?>" style="color:var(--sky);">cloudfen.com/contact.html</a>
      </p>
    </div>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
