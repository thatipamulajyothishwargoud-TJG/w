<?php
/**
 * CloudFen HR Portal — Client Timesheet Upload
 * HR / SuperAdmin can upload client-approved timesheets (PDF/Excel)
 * to match against employee timesheets.
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

$msg = ''; $msgType = '';

// ── Handle Upload ──────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['upload_client_ts'])) {
    verifyCsrfToken();
    $ip         = getClientIpSecure();
    $weekStart  = sanitizeDate($_POST['week_start'] ?? '');
    $clientName = sanitizeString($_POST['client_name'] ?? '', 120);
    $notes      = sanitizeString($_POST['notes'] ?? '', 1000);

    if (!$weekStart || !$clientName) {
        $msg = 'Week start date and client name are required.'; $msgType = 'error';
    } elseif (!isset($_FILES['ts_file']) || $_FILES['ts_file']['error'] !== UPLOAD_ERR_OK) {
        $msg = 'No file uploaded or upload error.'; $msgType = 'error';
    } else {
        // Validate: PDF, XLS, XLSX, CSV only
        $allowedMimes = [
            'application/pdf',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/csv', 'text/plain',
        ];
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $detectedMime = $finfo->file($_FILES['ts_file']['tmp_name']);
        $ext = strtolower(pathinfo($_FILES['ts_file']['name'], PATHINFO_EXTENSION));
        $allowedExts = ['pdf', 'xls', 'xlsx', 'csv'];

        if (!in_array($detectedMime, $allowedMimes, true) && !in_array($ext, $allowedExts, true)) {
            $msg = 'Only PDF, Excel, or CSV files are allowed.'; $msgType = 'error';
        } elseif ($_FILES['ts_file']['size'] > 10 * 1024 * 1024) {
            $msg = 'File must be under 10 MB.'; $msgType = 'error';
        } else {
            // ── Virus scan ───────────────────────────────────────
            $avResult = scanFileForVirus($_FILES['ts_file']['tmp_name']);
            if (!$avResult['clean']) {
                $msg = $avResult['reason']; $msgType = 'error';
            } else {
            $dir = getUploadBasePath() . 'client_timesheets' . DIRECTORY_SEPARATOR;
            if (!is_dir($dir)) {
                mkdir($dir, 0750, true);
                file_put_contents($dir . '.htaccess', "Deny from all\n");
            }
            $safeName = 'client_ts_' . preg_replace('/[^a-z0-9_]/', '_', strtolower($clientName))
                      . '_' . $weekStart . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
            if (move_uploaded_file($_FILES['ts_file']['tmp_name'], $dir . $safeName)) {
                try {
                    $db->prepare(
                        "INSERT INTO client_timesheets (client_name, week_start, file_name, file_path, file_size, notes, uploaded_by)
                         VALUES (?, ?, ?, ?, ?, ?, ?)"
                    )->execute([$clientName, $weekStart, $safeName, $dir . $safeName, (int)$_FILES['ts_file']['size'], $notes ?: null, (int)$user['id']]);
                } catch (\Throwable $e) {
                    @unlink($dir . $safeName);
                    error_log('Client timesheet DB error: ' . $e->getMessage());
                    $msg = 'File saved but database record could not be created.'; $msgType = 'error';
                    goto clientTimesheetUploadDone;
                }
                // Log to audit
                auditLog('client_timesheet_uploaded', 'client_timesheets', null, [
                    'client'     => $clientName,
                    'week_start' => $weekStart,
                    'file'       => $safeName,
                    'ip'         => $ip,
                ]);
                // Notify all HR staff
                $hrQ = $db->query("SELECT id FROM users WHERE role IN ('hr_admin','super_admin') AND status='active'");
                foreach ($hrQ->fetchAll() as $hr) {
                    if ((int)$hr['id'] === (int)$user['id']) continue;
                    createNotification((int)$hr['id'], 'client_ts_uploaded',
                        '📤 Client Timesheet Uploaded',
                        e($user['name']) . " uploaded a client timesheet for {$clientName} — week of {$weekStart}.",
                        '/admin/client_timesheets.php');
                }
                $msg = "Client timesheet for \"{$clientName}\" (week of {$weekStart}) uploaded successfully.";
                $msgType = 'success';
            } else {
                $msg = 'File could not be saved. Check server permissions.'; $msgType = 'error';
            }
            clientTimesheetUploadDone:
            } // end AV clean check
        }
    }
}

// ── Load recent uploads from audit log ───────────────────────────────────
$recentQ = $db->query(
    "SELECT al.details, al.created_at, u.full_name
     FROM audit_log al
     LEFT JOIN users u ON u.id = al.user_id
     WHERE al.action = 'client_timesheet_uploaded'
     ORDER BY al.created_at DESC LIMIT 30"
);
$recent = $recentQ->fetchAll();

pageHead('Client Timesheets', $msgType, $msgType === 'success' ? 'Upload Successful' : ($msgType === 'error' ? 'Error' : ''), $msg);
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id'=>$user['id'],'name'=>$user['name'],'role'=>$user['role']], 'client_ts'); ?>
  <div class="main-content">
    <?php renderTopbar('Client Timesheet Upload', $user); ?>
    <div class="page-body">
      <div class="page-header">
        <h1>📤 Client Timesheet Upload</h1>
        <p>Upload client-approved timesheets for record-keeping and payroll reconciliation.</p>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType==='error'?'error':'success' ?>" data-auto-dismiss="5000">
          <?= $msgType==='success'?'✅':'⚠️' ?> <?= e($msg) ?>
        </div>
      <?php endif; ?>

      <div class="grid-2" style="align-items:start;gap:24px;">

        <!-- Upload Form -->
        <div class="card">
          <div class="card-header"><h3>Upload Client Timesheet</h3></div>
          <div class="card-body">
            <form method="POST" enctype="multipart/form-data" data-upload action="/admin/client_timesheets.php">
              <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
              <div class="form-group">
                <label>Client / Company Name *</label>
                <input type="text" name="client_name" class="form-control" required maxlength="120"
                       placeholder="e.g. Acme Corp" value="<?= e($_POST['client_name'] ?? '') ?>">
              </div>
              <div class="form-group">
                <label>Week Start (Monday) *</label>
                <input type="date" name="week_start" class="form-control" required
                       value="<?= e($_POST['week_start'] ?? date('Y-m-d', strtotime('monday this week'))) ?>">
              </div>
              <div class="form-group">
                <label>Notes</label>
                <textarea name="notes" class="form-control" rows="2"
                          placeholder="Optional notes (PO number, project code...)" maxlength="1000"><?= e($_POST['notes'] ?? '') ?></textarea>
              </div>
              <div class="form-group">
                <label>Timesheet File *</label>
                <div class="upload-zone" id="client-upload-zone">
                  <input type="file" name="ts_file" id="ts-file-input" accept=".pdf,.xls,.xlsx,.csv" required>
                  <div class="upload-icon">📄</div>
                  <h4>Drop file here or click to browse</h4>
                  <p>PDF, Excel (.xlsx / .xls), or CSV — max 10 MB</p>
                  <p class="selected-filename" style="margin-top:8px;font-weight:600;color:var(--sky);"></p>
                </div>
                <div class="upload-progress-wrap">
                  <div class="upload-progress-bar">
                    <div class="upload-progress-fill" style="width:0%;"></div>
                  </div>
                  <div class="upload-progress-label">
                    <span>Uploading...</span>
                    <span class="upload-progress-pct">0%</span>
                  </div>
                </div>
              </div>
              <button type="submit" name="upload_client_ts" class="btn btn-primary btn-block">
                <span class="btn-text">📤 Upload Timesheet</span>
              </button>
            </form>
          </div>
        </div>

        <!-- Recent Uploads -->
        <div class="card">
          <div class="card-header">
            <h3>Recent Client Timesheets</h3>
            <span class="badge badge-info"><?= count($recent) ?> records</span>
          </div>
          <div class="card-body" style="padding:0;">
            <?php if (!$recent): ?>
              <div style="padding:40px;text-align:center;color:var(--gray-400);">
                <div style="font-size:2.5rem;margin-bottom:12px;">📂</div>
                <p>No client timesheets uploaded yet.</p>
              </div>
            <?php endif; ?>
            <?php foreach ($recent as $r):
              $det = json_decode($r['details'], true) ?? [];
            ?>
              <div class="doc-item" style="padding:14px 20px;">
                <div class="doc-item-icon" style="background:rgba(43,143,212,.1);">📄</div>
                <div class="doc-item-info">
                  <div class="doc-item-name"><?= e($det['client'] ?? '—') ?></div>
                  <div class="doc-item-meta">
                    Week of <?= e($det['week_start'] ?? '—') ?>
                    &bull; Uploaded by <?= e($r['full_name'] ?? 'System') ?>
                    &bull; <?= e(date('M j, Y g:i a', strtotime($r['created_at']))) ?>
                  </div>
                  <?php if (!empty($det['file'])): ?>
                    <div style="font-size:.75rem;color:var(--gray-400);font-family:monospace;margin-top:2px;"><?= e($det['file']) ?></div>
                  <?php endif; ?>
                </div>
                <span class="badge badge-approved">Stored</span>
              </div>
            <?php endforeach; ?>
          </div>
        </div>

      </div><!-- /grid-2 -->
    </div><!-- /page-body -->
  </div><!-- /main-content -->
</div><!-- /app-shell -->
<?php pageFooter(); ?>
</body>
</html>
