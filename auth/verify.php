<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
checkIpBlock();

// Token: allow only hex characters (SHA-256 output is 64 hex chars)
$token = preg_replace('/[^a-f0-9]/', '', $_GET['token'] ?? '');

$message = ''; $type = 'error';

if (strlen($token) === 64) {
    $db   = getDB();
    $stmt = $db->prepare(
        "SELECT id, email, full_name
         FROM users
         WHERE verify_token = ? AND verify_token_expiry > NOW() AND email_verified = 0
         LIMIT 1"
    );
    $stmt->execute([$token]);
    $user = $stmt->fetch();

    if ($user) {
        // Activate account — clear token atomically
        $db->prepare(
            "UPDATE users
             SET email_verified = 1, status = 'active',
                 verify_token = NULL, verify_token_expiry = NULL
             WHERE id = ?"
        )->execute([$user['id']]);

        auditLog('email_verified', 'users', (int)$user['id'], ['email' => $user['email']]);
        $message = 'Email verified! You can now <a href="/auth/login.php" style="color:var(--sky,#2b8fd4);font-weight:700;">sign in →</a>';
        $type    = 'success';
    } else {
        $message = 'This verification link is invalid or has expired (links are valid for 72 hours). Please register again or contact HR.';
    }
} else {
    $message = 'No valid verification token provided.';
}

pageHead('Verify Email');
?>
<body style="display:flex;align-items:center;justify-content:center;min-height:100vh;background:var(--gray-50,#f8fafc);">
<div style="max-width:480px;width:100%;padding:20px;">
  <div class="card">
    <div class="card-body" style="text-align:center;padding:48px 32px;">
      <div style="font-size:3rem;margin-bottom:20px;"><?= $type === 'success' ? '✅' : '❌' ?></div>
      <h2 style="color:var(--navy,#0c2340);margin-bottom:12px;">Email Verification</h2>
      <p style="color:var(--gray-600,#475569);line-height:1.7;"><?= $message ?></p>
    </div>
  </div>
</div>
</body>
</html>
