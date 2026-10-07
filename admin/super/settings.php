<?php
/**
 * Super Admin — App Settings & Cron
 * Manage app_settings table, rotate cron webhook token, manually trigger cron.
 */
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/helpers.php';
require_once __DIR__ . '/../../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('super_admin');
$db   = getDB();

$msg = ''; $msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true); // rotate token after use
    $action = validateEnum($_POST['action'] ?? '', ['rotate_cron_secret', 'update_setting', 'trigger_cron', 'update_mail_settings', 'send_test_email']);

    if ($action === 'rotate_cron_secret') {
        $newSecret = bin2hex(random_bytes(32));
        $db->prepare(
            "INSERT INTO app_settings (setting_key, setting_value) VALUES ('cron_secret', ?)
             ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)"
        )->execute([$newSecret]);
        auditLog('cron_secret_rotated', 'app_settings', null);
        $msg = '✅ Cron secret rotated successfully. Update your cron webhook URL.'; $msgType = 'success';
    }

    if ($action === 'update_setting') {
        $key   = sanitizeString($_POST['setting_key']   ?? '', 80);
        $value = sanitizeString($_POST['setting_value'] ?? '', 1000);
        if ($key) {
            $db->prepare(
                "INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?)
                 ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)"
            )->execute([$key, $value]);
            auditLog('setting_updated', 'app_settings', null, ['key' => $key]);
            $msg = 'Setting "' . e($key) . '" updated.'; $msgType = 'success';
        }
    }

    if ($action === 'update_mail_settings') {
        $upsert = $db->prepare(
            "INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)"
        );

        $transport = validateEnum($_POST['mail_transport'] ?? '', ['', 'api', 'smtp', 'mail']) ?? '';
        $provider  = validateEnum($_POST['mail_provider']  ?? '', ['', 'brevo']) ?? '';
        $encryption = validateEnum($_POST['smtp_encryption'] ?? '', ['tls', 'ssl', 'none']) ?? 'tls';

        $upsert->execute(['mail_transport', $transport]);
        $upsert->execute(['mail_provider', $provider]);
        $upsert->execute(['mail_from', sanitizeEmail($_POST['mail_from'] ?? '')]);
        $upsert->execute(['mail_from_name', sanitizeString($_POST['mail_from_name'] ?? '', 120)]);
        $upsert->execute(['smtp_host', sanitizeString($_POST['smtp_host'] ?? '', 255)]);
        $upsert->execute(['smtp_port', (string)(sanitizeInt($_POST['smtp_port'] ?? 587, 1, 65535) ?? 587)]);
        $upsert->execute(['smtp_username', sanitizeString($_POST['smtp_username'] ?? '', 255)]);
        $upsert->execute(['smtp_encryption', $encryption]);
        $upsert->execute(['smtp_auth', !empty($_POST['smtp_auth']) ? 'true' : 'false']);

        // Secret fields: only overwrite when the admin actually typed a new value,
        // so redisplaying the masked placeholder never blanks out a saved secret.
        $newBrevoKey = trim((string)($_POST['brevo_api_key'] ?? ''));
        if ($newBrevoKey !== '') {
            $upsert->execute(['brevo_api_key', substr($newBrevoKey, 0, 255)]);
        }
        $newSmtpPass = (string)($_POST['smtp_password'] ?? '');
        if ($newSmtpPass !== '') {
            $upsert->execute(['smtp_password', substr($newSmtpPass, 0, 255)]);
        }

        auditLog('mail_settings_updated', 'app_settings', null, ['transport' => $transport, 'provider' => $provider]);
        $msg = '✅ Mail settings saved.'; $msgType = 'success';
    }

    if ($action === 'send_test_email') {
        $testTo = sanitizeEmail($_POST['test_email'] ?? '');
        if (!filter_var($testTo, FILTER_VALIDATE_EMAIL)) {
            $msg = 'Enter a valid email address to send the test to.'; $msgType = 'error';
        } else {
            $sentOk = sendMail(
                $testTo,
                'CloudFen HR Portal — Test Email',
                emailTemplate('Test Email', '<p>This is a test email from your CloudFen HR Portal mail settings.</p>')
            );
            auditLog('test_email_sent', 'app_settings', null, ['to' => $testTo, 'success' => $sentOk]);
            if ($sentOk) {
                $msg = "✅ Test email sent to {$testTo}."; $msgType = 'success';
            } else {
                $msg = '❌ Test email failed: ' . getLastMailError(); $msgType = 'error';
            }
        }
    }

    if ($action === 'trigger_cron') {
        // Trigger cron by including the runner
        $cronSecret = $db->query(
            "SELECT setting_value FROM app_settings WHERE setting_key = 'cron_secret' LIMIT 1"
        )->fetchColumn();
        auditLog('cron_manually_triggered', 'cron', null);
        // We log it; actual URL trigger requires HTTP call — show the URL
        $msg = '✅ Cron marked for manual trigger. Use the cron URL below to execute it.'; $msgType = 'success';
    }
}

// Fetch all settings
$settings = $db->query(
    "SELECT setting_key, setting_value, updated_at FROM app_settings ORDER BY setting_key ASC"
)->fetchAll();

$settingsMap = [];
foreach ($settings as $s) $settingsMap[$s['setting_key']] = $s;

$cronSecret = $settingsMap['cron_secret']['setting_value'] ?? '';

// Mail settings have their own dedicated card below, so keep them out of the
// generic raw key-value editor to avoid two conflicting UIs for the same keys.
$MAIL_SETTING_KEYS = [
    'mail_transport', 'mail_provider', 'mail_from', 'mail_from_name',
    'brevo_api_key', 'smtp_host', 'smtp_port', 'smtp_username',
    'smtp_password', 'smtp_encryption', 'smtp_auth',
];
$genericSettings = array_filter($settings, fn($s) => !in_array($s['setting_key'], $MAIL_SETTING_KEYS, true));

$mailTransport  = $settingsMap['mail_transport']['setting_value']  ?? '';
$mailProvider   = $settingsMap['mail_provider']['setting_value']   ?? '';
$mailFrom       = $settingsMap['mail_from']['setting_value']       ?? (defined('MAIL_FROM') ? MAIL_FROM : '');
$mailFromName   = $settingsMap['mail_from_name']['setting_value'] ?? (defined('MAIL_FROM_NAME') ? MAIL_FROM_NAME : '');
$hasBrevoKey    = !empty($settingsMap['brevo_api_key']['setting_value']);
$smtpHost       = $settingsMap['smtp_host']['setting_value']       ?? '';
$smtpPort       = $settingsMap['smtp_port']['setting_value']       ?? '587';
$smtpUsername   = $settingsMap['smtp_username']['setting_value']   ?? '';
$hasSmtpPass    = !empty($settingsMap['smtp_password']['setting_value']);
$smtpEncryption = $settingsMap['smtp_encryption']['setting_value'] ?? 'tls';
$smtpAuth       = ($settingsMap['smtp_auth']['setting_value'] ?? 'true') !== 'false';
$effectiveTransport = $mailTransport !== '' ? $mailTransport : ($hasBrevoKey ? 'api' : ($smtpHost !== '' ? 'smtp' : 'mail'));

// Recent cron logs
$cronLogs = $db->query(
    "SELECT triggered_by, triggered_ip, emails_sent, duration_ms, errors, ran_at
     FROM cron_log ORDER BY ran_at DESC LIMIT 15"
)->fetchAll();

pageHead('App Settings');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'sa_settings'); ?>
  <div class="main-content">
    <?php renderTopbar('App Settings & Cron', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <div>
          <h1>⚙️ App Settings &amp; Cron</h1>
          <p>Manage system settings, rotate the cron secret, and view automated task history.</p>
        </div>
        <span style="padding:5px 14px;border-radius:20px;font-size:.82rem;font-weight:700;background:rgba(168,85,247,.12);color:#7c3aed;">⬡ Super Admin Panel</span>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <!-- Mail / email provider settings -->
      <div class="card" style="margin-bottom:24px;">
        <div class="card-header"><h3>📧 Mail &amp; Email Provider</h3></div>
        <div class="card-body">
          <p style="font-size:.88rem;color:var(--gray-600);margin-bottom:16px;">
            Currently sending via <strong><?= e(strtoupper($effectiveTransport)) ?></strong><?= $mailProvider ? ' (' . e($mailProvider) . ')' : '' ?>.
            Leave a secret field blank to keep its current saved value.
          </p>
          <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
            <input type="hidden" name="action"     value="update_mail_settings">

            <div class="grid-2" style="gap:16px;">
              <div class="form-group">
                <label>Transport</label>
                <select name="mail_transport" class="form-control">
                  <option value=""     <?= $mailTransport === ''     ? 'selected' : '' ?>>Auto-detect</option>
                  <option value="api"  <?= $mailTransport === 'api'  ? 'selected' : '' ?>>API (Brevo)</option>
                  <option value="smtp" <?= $mailTransport === 'smtp' ? 'selected' : '' ?>>SMTP</option>
                  <option value="mail" <?= $mailTransport === 'mail' ? 'selected' : '' ?>>PHP mail()</option>
                </select>
              </div>
              <div class="form-group">
                <label>Provider</label>
                <select name="mail_provider" class="form-control">
                  <option value=""      <?= $mailProvider === ''      ? 'selected' : '' ?>>—</option>
                  <option value="brevo" <?= $mailProvider === 'brevo' ? 'selected' : '' ?>>Brevo</option>
                </select>
              </div>
              <div class="form-group">
                <label>From Email</label>
                <input type="email" name="mail_from" class="form-control" maxlength="180" value="<?= e($mailFrom) ?>">
              </div>
              <div class="form-group">
                <label>From Name</label>
                <input type="text" name="mail_from_name" class="form-control" maxlength="120" value="<?= e($mailFromName) ?>">
              </div>
              <div class="form-group">
                <label>Brevo API Key <?= $hasBrevoKey ? '<span style="color:var(--gray-400);font-weight:400;">(saved — enter a new value to replace)</span>' : '' ?></label>
                <input type="password" name="brevo_api_key" class="form-control" maxlength="255"
                       placeholder="<?= $hasBrevoKey ? '••••••••••••••••' : 'Paste Brevo API key' ?>" autocomplete="off">
              </div>
              <div></div>
              <div class="form-group">
                <label>SMTP Host</label>
                <input type="text" name="smtp_host" class="form-control" maxlength="255" value="<?= e($smtpHost) ?>" placeholder="smtp.example.com">
              </div>
              <div class="form-group">
                <label>SMTP Port</label>
                <input type="number" name="smtp_port" class="form-control" min="1" max="65535" value="<?= e($smtpPort) ?>">
              </div>
              <div class="form-group">
                <label>SMTP Username</label>
                <input type="text" name="smtp_username" class="form-control" maxlength="255" value="<?= e($smtpUsername) ?>" autocomplete="off">
              </div>
              <div class="form-group">
                <label>SMTP Password <?= $hasSmtpPass ? '<span style="color:var(--gray-400);font-weight:400;">(saved)</span>' : '' ?></label>
                <input type="password" name="smtp_password" class="form-control" maxlength="255"
                       placeholder="<?= $hasSmtpPass ? '••••••••••••••••' : 'SMTP password' ?>" autocomplete="off">
              </div>
              <div class="form-group">
                <label>SMTP Encryption</label>
                <select name="smtp_encryption" class="form-control">
                  <option value="tls"  <?= $smtpEncryption === 'tls'  ? 'selected' : '' ?>>TLS</option>
                  <option value="ssl"  <?= $smtpEncryption === 'ssl'  ? 'selected' : '' ?>>SSL</option>
                  <option value="none" <?= $smtpEncryption === 'none' ? 'selected' : '' ?>>None</option>
                </select>
              </div>
              <div class="form-group" style="display:flex;align-items:center;gap:8px;margin-top:24px;">
                <input type="checkbox" name="smtp_auth" id="smtp_auth" value="1" <?= $smtpAuth ? 'checked' : '' ?>>
                <label for="smtp_auth" style="margin:0;">SMTP requires authentication</label>
              </div>
            </div>

            <button type="submit" class="btn btn-primary btn-sm" style="margin-top:8px;">💾 Save Mail Settings</button>
          </form>

          <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--gray-100);">
            <form method="POST" style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
              <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
              <input type="hidden" name="action"     value="send_test_email">
              <div class="form-group" style="margin:0;flex:1;min-width:200px;">
                <label>Send Test Email To</label>
                <input type="email" name="test_email" class="form-control" maxlength="180" placeholder="you@email.com" required>
              </div>
              <button type="submit" class="btn btn-outline btn-sm">✉️ Send Test Email</button>
            </form>
          </div>
        </div>
      </div>

      <div class="grid-2" style="gap:24px;align-items:start;">

        <!-- Cron secret -->
        <div class="card">
          <div class="card-header"><h3>🔐 Cron Webhook Token</h3></div>
          <div class="card-body">
            <p style="font-size:.88rem;color:var(--gray-600);margin-bottom:16px;">
              The cron webhook URL is used to trigger daily tasks (expiry alerts, etc.). Keep this secret.
            </p>
            <?php if ($cronSecret): ?>
              <div style="background:var(--gray-50);border:1px solid var(--gray-200);border-radius:8px;padding:12px 16px;margin-bottom:16px;">
                <div style="font-size:.75rem;color:var(--gray-400);margin-bottom:4px;">Current Cron URL</div>
                <code style="font-size:.8rem;word-break:break-all;color:var(--navy);">
                  <?= defined('APP_URL') ? e(APP_URL) : '[APP_URL]' ?>/cron/runner.php?token=<?= e($cronSecret) ?>
                </code>
              </div>
            <?php endif; ?>
            <form method="POST" onsubmit="return confirm('Rotate cron secret? You must update your hosting cron job URL after this.')">
              <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
              <input type="hidden" name="action"     value="rotate_cron_secret">
              <button type="submit" class="btn btn-danger btn-sm">🔄 Rotate Secret</button>
            </form>
            <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--gray-100);">
              <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                <input type="hidden" name="action"     value="trigger_cron">
                <button type="submit" class="btn btn-outline btn-sm">▶ Log Manual Cron Trigger</button>
              </form>
            </div>
          </div>
        </div>

        <!-- Settings key-value editor -->
        <div class="card">
          <div class="card-header"><h3>🗂️ App Settings Table</h3></div>
          <div class="card-body" style="padding:0;">
            <?php foreach ($genericSettings as $s): ?>
              <div style="padding:12px 20px;border-bottom:1px solid var(--gray-100);display:flex;align-items:center;gap:12px;">
                <div style="flex:1;min-width:0;">
                  <div style="font-size:.8rem;font-weight:700;color:var(--gray-600);text-transform:uppercase;letter-spacing:.04em;"><?= e($s['setting_key']) ?></div>
                  <div style="font-family:monospace;font-size:.82rem;color:var(--navy);margin-top:2px;word-break:break-all;">
                    <?= $s['setting_key'] === 'cron_secret'
                        ? '<span style="color:var(--gray-400);">•••••••••••••• (hidden)</span>'
                        : e($s['setting_value'] ?? '') ?>
                  </div>
                  <div style="font-size:.72rem;color:var(--gray-400);margin-top:2px;">Updated <?= e(date('M j, Y g:i a', strtotime($s['updated_at']))) ?></div>
                </div>
                <?php if ($s['setting_key'] !== 'cron_secret'): ?>
                  <form method="POST" style="display:flex;gap:6px;flex-shrink:0;">
                    <input type="hidden" name="csrf_token"    value="<?= generateCsrfToken() ?>">
                    <input type="hidden" name="action"        value="update_setting">
                    <input type="hidden" name="setting_key"   value="<?= e($s['setting_key']) ?>">
                    <input type="text"   name="setting_value" class="form-control"
                           style="font-size:.8rem;padding:5px 8px;width:130px;"
                           value="<?= e($s['setting_value'] ?? '') ?>" maxlength="1000">
                    <button type="submit" class="btn btn-outline btn-sm">Save</button>
                  </form>
                <?php endif; ?>
              </div>
            <?php endforeach; ?>
            <?php if (!$genericSettings): ?>
              <div style="padding:24px;text-align:center;color:var(--gray-400);">No settings found.</div>
            <?php endif; ?>
          </div>
        </div>

      </div>

      <!-- Cron log -->
      <div class="card" style="margin-top:24px;">
        <div class="card-header"><h3>⏰ Recent Cron Runs</h3></div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Ran At</th>
                <th>Triggered By</th>
                <th>IP</th>
                <th>Emails Sent</th>
                <th>Duration (ms)</th>
                <th>Errors</th>
              </tr>
            </thead>
            <tbody>
              <?php if (!$cronLogs): ?>
                <tr><td colspan="6" style="text-align:center;color:var(--gray-400);padding:24px;">No cron runs logged yet.</td></tr>
              <?php endif; ?>
              <?php foreach ($cronLogs as $log): ?>
                <tr>
                  <td style="font-size:.82rem;"><?= e(date('M j, Y g:i a', strtotime($log['ran_at']))) ?></td>
                  <td><span class="badge badge-info" style="font-size:.72rem;"><?= e($log['triggered_by']) ?></span></td>
                  <td style="font-family:monospace;font-size:.8rem;"><?= e($log['triggered_ip'] ?? '—') ?></td>
                  <td style="text-align:center;"><?= (int)$log['emails_sent'] ?></td>
                  <td style="text-align:center;"><?= $log['duration_ms'] !== null ? e(number_format((int)$log['duration_ms'])) . ' ms' : '—' ?></td>
                  <td style="font-size:.78rem;color:var(--rose);"><?= $log['errors'] ? e(mb_substr($log['errors'],0,80)) : '✅' ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>

    </div>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
