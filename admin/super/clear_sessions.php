<?php
/**
 * CloudFen HR Portal — Session & Temp Data Cleanup
 * Access: Super Admin only. Run once, then delete this file.
 *
 * What it clears:
 *  1. All active PHP server-side sessions (forces re-login for everyone)
 *  2. Rate-limit table rows (unblocks forgot-password throttle)
 *  3. Expired password-reset tokens in the users table
 *  4. Expired / stale remember-me tokens (if applicable)
 */
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/helpers.php';
require_once __DIR__ . '/../../includes/security.php';
require_once __DIR__ . '/../../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('super_admin');

/* Destructive action — require an explicit POST + CSRF token so it can't be
   triggered by a forged cross-site request (e.g. an <img> tag) against a
   logged-in super_admin. GET just shows a confirmation form. */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $csrfToken = htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8');
    ?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Confirm Session Cleanup — CloudFen</title>
  <style>
    body { font-family: 'Helvetica Neue', sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 40px; }
    h1   { color: #20a0c0; }
    .box { background: #141414; border: 1px solid #2a2a2a; border-radius: 12px; padding: 24px; max-width: 700px; }
    .warn { background: #2a1a00; border: 1px solid #c05020; border-radius: 8px; padding: 14px; margin-top: 16px; color: #ffa060; font-size: .9em; }
    button { background:#20a0c0; color:#0a0a0a; border:none; border-radius:8px; padding:10px 18px; font-weight:600; cursor:pointer; margin-top:18px; }
    a { color: #20a0c0; }
  </style>
</head>
<body>
<div class="box">
  <h1>🧹 Session &amp; Temp Data Cleanup</h1>
  <p>This will log out every other logged-in user, clear rate-limit throttling, and clear expired password-reset tokens.</p>
  <div class="warn">⚠️ This action is immediate and cannot be undone.</div>
  <form method="POST">
    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
    <button type="submit">Confirm &amp; Run Cleanup</button>
  </form>
  <p style="margin-top:24px;"><a href="/admin/super/settings.php">← Back to Settings</a></p>
</div>
</body>
</html>
<?php
    exit;
}

verifyCsrfToken();

$results = [];
$errors  = [];

/* ── 1. PHP SESSION FILES ─────────────────────────────────── */
$sessionPath = session_save_path();
if (empty($sessionPath) || !is_dir($sessionPath)) {
    // Common fallbacks
    foreach (['/tmp', sys_get_temp_dir(), '/var/lib/php/sessions'] as $p) {
        if (is_dir($p)) { $sessionPath = $p; break; }
    }
}

$cleared = 0;
$skipped = 0;
$foreign = 0;
if (is_dir($sessionPath)) {
    $mySessionId = session_id();
    foreach (glob($sessionPath . '/sess_*') ?: [] as $file) {
        // Don't kill our own session
        if (basename($file) === 'sess_' . $mySessionId) { $skipped++; continue; }
        // PHP's session file store is often shared per cPanel account, not per
        // app — on shared hosting this directory can hold another site's
        // sessions too. Only delete files carrying this app's session marker
        // (see startSecureSession()) so an unrelated app isn't logged out.
        $content = @file_get_contents($file);
        if ($content === false || strpos($content, 'cloudfen_hr_v1') === false) { $foreign++; continue; }
        if (@unlink($file)) $cleared++;
    }
    $results[] = "✅ PHP sessions cleared: {$cleared} files removed (skipped own: {$skipped}, skipped non-CloudFen: {$foreign})";
} else {
    $errors[] = "⚠️ Session path not found or not readable: " . htmlspecialchars($sessionPath ?? 'unknown');
}

/* ── 2. RATE LIMIT TABLE ──────────────────────────────────── */
try {
    $db = getDB();
    $stmt = $db->query("DELETE FROM rate_limit WHERE 1");
    $rows = $stmt->rowCount();
    $results[] = "✅ Rate-limit table cleared: {$rows} rows removed";
} catch (\Throwable $e) {
    $errors[] = "⚠️ Rate-limit clear failed: " . htmlspecialchars($e->getMessage());
}

/* ── 3. EXPIRED PASSWORD-RESET TOKENS ────────────────────── */
try {
    $db   = getDB();
    $stmt = $db->prepare(
        "UPDATE users SET reset_token = NULL, reset_token_expiry = NULL
         WHERE reset_token IS NOT NULL AND reset_token_expiry < NOW()"
    );
    $stmt->execute();
    $results[] = "✅ Expired reset tokens cleared: {$stmt->rowCount()} rows";
} catch (\Throwable $e) {
    $errors[] = "⚠️ Reset token clear failed: " . htmlspecialchars($e->getMessage());
}

/* ── 4. AUDIT LOG ─────────────────────────────────────────── */
auditLog('admin_clear_sessions', 'system', (int)$user['id'], [
    'cleared_sessions' => $cleared ?? 0,
    'ip' => getClientIpSecure(),
]);

/* ── OUTPUT ───────────────────────────────────────────────── */
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Session Cleanup — CloudFen</title>
  <style>
    body { font-family: 'Helvetica Neue', sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 40px; }
    h1   { color: #20a0c0; }
    .ok  { color: #4ade80; margin: 8px 0; }
    .err { color: #f87171; margin: 8px 0; }
    .box { background: #141414; border: 1px solid #2a2a2a; border-radius: 12px; padding: 24px; max-width: 700px; }
    .warn { background: #2a1a00; border: 1px solid #c05020; border-radius: 8px; padding: 14px; margin-top: 24px; color: #ffa060; font-size: .9em; }
    a    { color: #20a0c0; }
  </style>
</head>
<body>
<div class="box">
  <h1>🧹 Session & Temp Data Cleanup</h1>

  <?php foreach ($results as $r): ?>
    <p class="ok"><?= $r ?></p>
  <?php endforeach; ?>

  <?php foreach ($errors as $e): ?>
    <p class="err"><?= $e ?></p>
  <?php endforeach; ?>

  <div class="warn">
    ⚠️ <strong>Security notice:</strong> All other users have been logged out.
    Delete this file from the server after use —
    <code>admin/super/clear_sessions.php</code>
    should not remain permanently accessible.
  </div>

  <p style="margin-top:24px;">
    <a href="/admin/super/settings.php">← Back to Settings</a>
  </p>
</div>
<?php pageFooter(); ?>
</body>
</html>
