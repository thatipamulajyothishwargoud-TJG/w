<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('super_admin');
$db   = getDB();

$msg = ''; $msgType = '';

// ── Handle secret rotation ────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken();
    $action = validateEnum($_POST['action'] ?? '', ['rotate_secret', 'run_now']);

    if ($action === 'rotate_secret') {
        $newSecret = bin2hex(random_bytes(32)); // 64 hex chars
        $db->prepare(
            "INSERT INTO app_settings (setting_key, setting_value)
             VALUES ('cron_secret', ?)
             ON DUPLICATE KEY UPDATE setting_value = ?"
        )->execute([$newSecret, $newSecret]);
        auditLog('cron_secret_rotated', 'app_settings', null);
        $msg = 'Cron secret rotated. Update your cron-job.org URL with the new token below.';
        $msgType = 'success';
    }

    if ($action === 'run_now') {
        // Manually trigger — redirect to runner with manual flag
        $secretStmt = $db->prepare("SELECT setting_value FROM app_settings WHERE setting_key = 'cron_secret'");
        $secretStmt->execute();
        $secret = $secretStmt->fetchColumn();
        if ($secret && $secret !== 'CHANGE_THIS_SECRET_BEFORE_GOING_LIVE') {
            $runUrl = APP_URL . '/cron/runner.php?token=' . urlencode($secret) . '&manual=1';
            header('Location: ' . $runUrl);
            exit;
        }
        $msg = 'Please set a cron secret first.'; $msgType = 'error';
    }
}

// ── Load data ─────────────────────────────────────────────────────────────────
$secretStmt = $db->prepare("SELECT setting_value FROM app_settings WHERE setting_key = 'cron_secret'");
$secretStmt->execute();
$cronSecret = (string)($secretStmt->fetchColumn() ?? '');
$isDefaultSecret = ($cronSecret === 'CHANGE_THIS_SECRET_BEFORE_GOING_LIVE' || empty($cronSecret));

$cronUrl = APP_URL . '/cron/runner.php?token=' . urlencode($cronSecret);

// Last 20 cron runs
$logsStmt = $db->query(
    "SELECT id, triggered_by, triggered_ip, tasks_run, emails_sent, errors, duration_ms, ran_at
     FROM cron_log ORDER BY ran_at DESC LIMIT 20"
);
$logs = $logsStmt->fetchAll();

// Next expected run
$lastRun = $logs[0]['ran_at'] ?? null;
$nextRun = $lastRun ? date('M j, Y', strtotime($lastRun . ' +1 day')) . ' ~8:00 AM' : 'Not yet run';

pageHead('Cron Status');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'cron'); ?>
  <div class="main-content">
    <?php renderTopbar('Automated Tasks', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <h1>⏰ Automated Tasks</h1>
        <p>Configure and monitor the daily task runner — document expiry alerts, timesheet reminders, and cleanup.</p>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <?php if ($isDefaultSecret): ?>
        <div class="alert alert-warn" style="margin-bottom:24px;">
          ⚠️ <strong>Action required:</strong> The cron secret has not been set up yet. Click "Generate New Secret" below, then follow the setup steps.
        </div>
      <?php endif; ?>

      <!-- Status cards -->
      <div class="stats-grid" style="margin-bottom:28px;">
        <div class="stat-card">
          <div class="stat-icon <?= $isDefaultSecret ? 'rose' : 'mint' ?>"><?= $isDefaultSecret ? '⚠️' : '✅' ?></div>
          <div>
            <div class="stat-value" style="font-size:1rem;"><?= $isDefaultSecret ? 'Not Configured' : 'Active' ?></div>
            <div class="stat-label">Cron Status</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon blue">🕐</div>
          <div>
            <div class="stat-value" style="font-size:.95rem;"><?= $lastRun ? e(date('M j, g:i a', strtotime($lastRun))) : 'Never' ?></div>
            <div class="stat-label">Last Run</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon amber">📅</div>
          <div>
            <div class="stat-value" style="font-size:.95rem;"><?= e($nextRun) ?></div>
            <div class="stat-label">Next Expected Run</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon blue">📧</div>
          <div>
            <div class="stat-value"><?= (int)array_sum(array_column($logs, 'emails_sent')) ?></div>
            <div class="stat-label">Emails Sent (Total)</div>
          </div>
        </div>
      </div>

      <div class="grid-2" style="gap:24px;align-items:start;">

        <!-- Setup instructions -->
        <div style="display:flex;flex-direction:column;gap:20px;">

          <!-- Secret management -->
          <div class="card">
            <div class="card-header"><h3>🔑 Cron Secret Token</h3></div>
            <div class="card-body">
              <?php if (!$isDefaultSecret): ?>
                <div style="margin-bottom:16px;">
                  <div style="font-size:.82rem;font-weight:600;color:var(--gray-600);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px;">Your Cron URL</div>
                  <div style="background:var(--gray-50);border:1px solid var(--gray-200);border-radius:var(--radius);padding:12px 14px;font-family:monospace;font-size:.78rem;color:var(--navy);word-break:break-all;line-height:1.6;">
                    <?= e($cronUrl) ?>
                  </div>
                  <div style="font-size:.78rem;color:var(--gray-400);margin-top:6px;">Copy this URL into cron-job.org (see setup steps →)</div>
                </div>
              <?php endif; ?>

              <form method="POST" style="display:flex;gap:10px;flex-wrap:wrap;">
                <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                <input type="hidden" name="action"     value="rotate_secret">
                <button type="submit" class="btn btn-<?= $isDefaultSecret ? 'primary' : 'outline' ?>"
                        onclick="return <?= $isDefaultSecret ? 'true' : "confirm('Rotating the secret will break your existing cron-job.org setup. You will need to update the URL there. Continue?')" ?>">
                  <?= $isDefaultSecret ? '🔑 Generate New Secret' : '🔄 Rotate Secret' ?>
                </button>
              </form>
            </div>
          </div>

          <!-- Manual run -->
          <div class="card">
            <div class="card-header"><h3>▶️ Manual Run</h3></div>
            <div class="card-body">
              <p style="font-size:.88rem;color:var(--gray-400);margin-bottom:16px;">
                Run all tasks immediately — expiry checks, reminders, and cleanup. Useful for testing or if the scheduled run was missed.
              </p>
              <?php if (!$isDefaultSecret): ?>
                <form method="POST">
                  <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                  <input type="hidden" name="action"     value="run_now">
                  <button type="submit" class="btn btn-navy">▶ Run All Tasks Now</button>
                </form>
              <?php else: ?>
                <div class="alert alert-warn" style="font-size:.85rem;margin:0;">Set up the cron secret first before running.</div>
              <?php endif; ?>
            </div>
          </div>

        </div>

        <!-- Setup guide -->
        <div class="card">
          <div class="card-header"><h3>📋 Setup Guide — cron-job.org</h3></div>
          <div class="card-body">
            <p style="font-size:.88rem;color:var(--gray-400);margin-bottom:16px;">
              Since Turbify doesn't provide cron jobs, we use <strong>cron-job.org</strong> — a free external service that visits your URL once a day to trigger tasks. It's used by thousands of websites for exactly this purpose.
            </p>

            <div style="display:flex;flex-direction:column;gap:12px;">

              <!-- METHOD 1 -->
              <div style="background:rgba(26,184,154,.07);border:1px solid rgba(26,184,154,.2);border-radius:10px;padding:14px 16px;margin-bottom:10px;">
                <div style="font-weight:700;font-size:.9rem;color:var(--mint);margin-bottom:4px;">✅ Method 1 — Pseudo-Cron (Built-in, Zero Config)</div>
                <div style="font-size:.83rem;color:var(--gray-400);">Already active. The portal fires tasks automatically when any user loads a page and 23 hours have passed since the last run. No setup required.</div>
              </div>

              <!-- METHOD 2 -->
              <div style="background:rgba(43,143,212,.06);border:1px solid rgba(43,143,212,.15);border-radius:10px;padding:14px 16px;margin-bottom:10px;">
                <div style="font-weight:700;font-size:.9rem;color:var(--sky);margin-bottom:8px;">🌐 Method 2 — cron-job.org (Free, Most Reliable)</div>

              <div style="display:flex;gap:12px;align-items:flex-start;">
                <div style="width:28px;height:28px;border-radius:50%;background:var(--sky);color:#fff;display:flex;align-items:center;justify-content:center;font-size:.8rem;font-weight:700;flex-shrink:0;">1</div>
                <div>
                  <div style="font-weight:600;font-size:.9rem;color:var(--navy);">Generate your secret token</div>
                  <div style="font-size:.83rem;color:var(--gray-400);">Click "Generate New Secret" on the left. This creates a unique token only you know.</div>
                </div>
              </div>

              <div style="display:flex;gap:12px;align-items:flex-start;">
                <div style="width:28px;height:28px;border-radius:50%;background:var(--sky);color:#fff;display:flex;align-items:center;justify-content:middle;font-size:.8rem;font-weight:700;flex-shrink:0;justify-content:center;">2</div>
                <div>
                  <div style="font-weight:600;font-size:.9rem;color:var(--navy);">Create a free account at cron-job.org</div>
                  <div style="font-size:.83rem;color:var(--gray-400);">Go to <strong>cron-job.org</strong> → Sign up free → no credit card needed.</div>
                </div>
              </div>

              <div style="display:flex;gap:12px;align-items:flex-start;">
                <div style="width:28px;height:28px;border-radius:50%;background:var(--sky);color:#fff;display:flex;align-items:center;justify-content:center;font-size:.8rem;font-weight:700;flex-shrink:0;">3</div>
                <div>
                  <div style="font-weight:600;font-size:.9rem;color:var(--navy);">Create a new cron job</div>
                  <div style="font-size:.83rem;color:var(--gray-400);margin-bottom:6px;">Dashboard → Create cronjob → fill in:</div>
                  <div style="background:var(--gray-50);border:1px solid var(--gray-200);border-radius:8px;padding:10px 12px;font-size:.78rem;font-family:monospace;line-height:1.9;">
                    Title:    CloudFen Daily Tasks<br>
                    URL:      <span style="color:var(--sky);">[copy the Cron URL from the left panel]</span><br>
                    Schedule: Every day at 08:00<br>
                    Timezone: Your timezone
                  </div>
                </div>
              </div>

              <div style="display:flex;gap:12px;align-items:flex-start;">
                <div style="width:28px;height:28px;border-radius:50%;background:var(--mint);color:#fff;display:flex;align-items:center;justify-content:center;font-size:.8rem;font-weight:700;flex-shrink:0;">4</div>
                <div>
                  <div style="font-weight:600;font-size:.9rem;color:var(--navy);">Click Create — you're done</div>
                  <div style="font-size:.83rem;color:var(--gray-400);">cron-job.org will visit your URL every morning. Come back here to see the run history below.</div>
                </div>
              </div>

            </div>

            <div class="alert alert-info" style="margin-top:16px;font-size:.83rem;">
              ℹ️ cron-job.org is free for up to 5 jobs, runs every 5 minutes minimum, and monitors if your job fails. You'll get an email alert if a run fails.
            </div>
              </div><!-- /Method 2 -->

              <!-- METHOD 3 -->
              <div style="background:rgba(168,85,247,.06);border:1px solid rgba(168,85,247,.15);border-radius:10px;padding:14px 16px;">
                <div style="font-weight:700;font-size:.9rem;color:#7c3aed;margin-bottom:4px;">🔔 Method 3 — UptimeRobot / Better Uptime</div>
                <div style="font-size:.83rem;color:var(--gray-400);">If you already use an uptime monitor, add a new HTTP(S) monitor pointing to your cron URL (same token URL as Method 2). Set the check interval to 1440 minutes (daily).</div>
              </div>

          </div><!-- /Methods card body -->
        </div>

      </div>

      <!-- Run History -->
      <div class="card" style="margin-top:24px;">
        <div class="card-header"><h3>📊 Run History (Last 20)</h3></div>
        <div class="card-body" style="padding:0;">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Date &amp; Time</th>
                  <th>Triggered By</th>
                  <th>Emails Sent</th>
                  <th>Duration</th>
                  <th>Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                <?php if (!$logs): ?>
                  <tr><td colspan="6" style="text-align:center;padding:32px;color:var(--gray-400);">No runs yet. Set up cron-job.org to get started.</td></tr>
                <?php endif; ?>
                <?php foreach ($logs as $log): ?>
                  <?php
                  $tasks  = json_decode($log['tasks_run'] ?? '[]', true) ?: [];
                  $errs   = json_decode($log['errors']   ?? 'null', true);
                  $hasErr = !empty($errs);
                  ?>
                  <tr>
                    <td style="white-space:nowrap;font-size:.85rem;"><?= e(date('M j, Y g:i a', strtotime($log['ran_at']))) ?></td>
                    <td>
                      <span class="badge badge-<?= $log['triggered_by'] === 'manual_hr' ? 'info' : 'approved' ?>">
                        <?= $log['triggered_by'] === 'manual_hr' ? '👤 Manual' : '🤖 Auto' ?>
                      </span>
                    </td>
                    <td><?= (int)$log['emails_sent'] ?></td>
                    <td style="font-size:.83rem;color:var(--gray-400);"><?= (int)$log['duration_ms'] ?>ms</td>
                    <td>
                      <span class="badge badge-<?= $hasErr ? 'rejected' : 'approved' ?>">
                        <?= $hasErr ? '⚠ Errors' : '✓ OK' ?>
                      </span>
                    </td>
                    <td style="font-size:.78rem;color:var(--gray-400);max-width:220px;">
                      <?php if ($tasks): ?>
                        <?= e(implode(' · ', array_slice($tasks, 0, 3))) ?>
                        <?php if (count($tasks) > 3): ?> +<?= count($tasks) - 3 ?> more<?php endif; ?>
                      <?php else: ?>
                        —
                      <?php endif; ?>
                      <?php if ($hasErr && is_array($errs)): ?>
                        <div style="color:var(--rose);margin-top:2px;"><?= e(implode('; ', array_slice($errs, 0, 1))) ?></div>
                      <?php endif; ?>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>

    </div>
  </div>
</div>
</body>
</html>
