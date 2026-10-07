<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin','super_admin');
$db   = getDB();
$isSA = $user['role'] === 'super_admin';
$canAccessApprovalTimesheets = $isSA || userCanAccessTimesheetsModule((int)$user['id'], (string)$user['role']);
$timesheetRestrictionMessage = getComplianceRestrictionMessage();

$ALLOWED_STATUSES = array('pending','approved','rejected','all');
$msg = ''; $msgType = '';

// CSV Export — before any HTML output
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    if (!$canAccessApprovalTimesheets) {
        http_response_code(403);
        die('Access denied.');
    }
    verifyCsrf();
    $weekFilter = sanitizeDate($_GET['week_filter'] ?? '') ?? '';
    $whereExp   = $weekFilter ? 'AND t.week_start = ?' : '';
    $params     = $weekFilter ? [$weekFilter] : [];

    $exp = $db->prepare(
        "SELECT u.full_name, u.email, u.employee_type,
                t.week_start, t.mon_hours, t.tue_hours, t.wed_hours, t.thu_hours,
                t.fri_hours, t.sat_hours, t.sun_hours, t.total_hours,
                t.status, t.notes, t.project_code
         FROM timesheets t JOIN users u ON u.id = t.user_id
         WHERE t.status = 'approved' $whereExp
         ORDER BY t.week_start DESC, u.full_name ASC"
    );
    $exp->execute($params);
    $rows = $exp->fetchAll();

    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="cloudfen_timesheets_' . date('Ymd') . '.csv"');
    header('X-Content-Type-Options: nosniff');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['Employee Name','Email','Type','Week Start','Mon','Tue','Wed','Thu','Fri','Sat','Sun','Total Hours','Status','Notes','Project Code']);
    foreach ($rows as $r) fputcsv($out, array_values($r));
    fclose($out);
    auditLog('timesheets_exported', 'timesheets', null, array('count' => count($rows)));
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$canAccessApprovalTimesheets) {
        $msg = $timesheetRestrictionMessage;
        $msgType = 'error';
        goto renderTimesheetsPage;
    }
    verifyCsrfToken();
    $action = validateEnum($_POST['action'] ?? '', ['approve','reject','bulk_approve','delete_attachment']);

    if (in_array($action, ['approve', 'reject', 'bulk_approve'], true) && !$isSA) {
        $msg = 'Only Super Admin can approve or reject submitted timesheets.';
        $msgType = 'error';
        $action = null;
    }

    // ── Delete attachment (super_admin only) ─────────────────
    if ($action === 'delete_attachment' && $isSA) {
        $attId = sanitizeInt($_POST['att_id'] ?? 0, 1);
        if ($attId) {
            $attStmt = $db->prepare("SELECT * FROM timesheet_attachments WHERE id=? LIMIT 1");
            $attStmt->execute([$attId]);
            $attRow = $attStmt->fetch();
            if ($attRow) {
                // Path-traversal guard before deleting
                $uploadBase = getUploadBasePath();
                $realBase   = realpath($uploadBase);
                $realPath   = realpath($attRow['file_path']);
                $uploadRoot = $realBase ? rtrim($realBase, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR : '';
                if ($realBase && $realPath && ($realPath === $realBase || strpos($realPath, $uploadRoot) === 0)) {
                    @unlink($realPath);
                }
                $db->prepare("DELETE FROM timesheet_attachments WHERE id=?")->execute([$attId]);
                auditLog('timesheet_file_deleted', 'timesheet_attachments', $attId);
                $msg = 'Attachment deleted.'; $msgType = 'success';
            }
        }

    } elseif ($action === 'bulk_approve' && !empty($_POST['ts_ids'])) {
        // Validate all IDs are integers, then verify each belongs to a real employee (not HR)
        $rawIds = (array)$_POST['ts_ids'];
        $safeIds = array_filter(array_map(function($id) { return sanitizeInt($id, 1); }, $rawIds));

        if ($safeIds) {
            $inClauseResult = buildInClause($safeIds, 'int'); $placeholders = $inClauseResult[0]; $params = $inClauseResult[1];
            // Only approve timesheets that are 'pending' — prevents double-approve.
            // Excludes the reviewer's own timesheet — a reviewer must not self-approve.
            $db->prepare(
                "UPDATE timesheets SET status = 'approved', reviewed_by = ?, reviewed_at = NOW()
                 WHERE id IN ({$placeholders}) AND status = 'pending' AND user_id != ?"
            )->execute(array_merge([$user['id']], $params, [$user['id']]));

            foreach ($safeIds as $tsId) {
                $r = $db->prepare(
                    "SELECT t.*, u.email, u.full_name FROM timesheets t
                     JOIN users u ON u.id = t.user_id WHERE t.id = ?"
                );
                $r->execute([$tsId]);
                $ts = $r->fetch();
                if ($ts && $ts['status'] === 'approved') {
                    $wl = e(date('M j', strtotime($ts['week_start'])));
                    createNotification((int)$ts['user_id'], 'ts_approved', '✅ Timesheet Approved',
                        "Your timesheet for week of {$wl} has been approved.", '/employee/timesheets.php');
                    sendMail($ts['email'], 'Timesheet Approved - CloudFen HR Portal',
                        emailTemplate('Timesheet Approved', "<p>Your timesheet for <strong>{$wl}</strong> has been approved.</p>"));
                    auditLog('timesheet_approved', 'timesheets', $tsId);
                }
            }
            $msg = count($safeIds) . ' timesheet(s) approved.'; $msgType = 'success';
        }

    } elseif (in_array($action, ['approve','reject'], true)) {
        $tsId   = sanitizeInt($_POST['ts_id'] ?? 0, 1);
        $reason = sanitizeString($_POST['reason'] ?? '', 1000);

        if (!$tsId) { $msg = 'Invalid timesheet.'; $msgType = 'error'; }
        elseif ($action === 'reject' && !$reason) { $msg = 'Rejection reason required.'; $msgType = 'error'; }
        else {
            $newStatus = $action === 'approve' ? 'approved' : 'rejected';
            // Reviewer cannot approve/reject their own timesheet.
            $reviewStmt = $db->prepare(
                "UPDATE timesheets SET status = ?, rejection_reason = ?, reviewed_by = ?, reviewed_at = NOW()
                 WHERE id = ? AND status = 'pending' AND user_id != ?"
            );
            $reviewStmt->execute([$newStatus, $reason ?: null, $user['id'], $tsId, $user['id']]);
            if ($reviewStmt->rowCount() === 0) {
                $msg = 'Unable to update this timesheet — it may already be reviewed, or you cannot review your own timesheet.';
                $msgType = 'error';
                goto ts_review_skip;
            }

            $r = $db->prepare(
                "SELECT t.*, u.email, u.full_name FROM timesheets t
                 JOIN users u ON u.id = t.user_id WHERE t.id = ?"
            );
            $r->execute([$tsId]);
            $ts = $r->fetch();
            if ($ts) {
                $wl = e(date('M j, Y', strtotime($ts['week_start'])));
                if ($action === 'approve') {
                    createNotification((int)$ts['user_id'], 'ts_approved', '✅ Timesheet Approved',
                        "Your timesheet for {$wl} approved.", '/employee/timesheets.php');
                    sendMail($ts['email'], 'Timesheet Approved - CloudFen HR Portal',
                        emailTemplate('Timesheet Approved', "<p>Your timesheet for <strong>{$wl}</strong> has been <span style='color:#1ab89a;font-weight:700;'>approved</span>.</p>"));
                } else {
                    createNotification((int)$ts['user_id'], 'ts_rejected', '❌ Timesheet Rejected',
                        "Your timesheet for {$wl} was rejected. Reason: " . e($reason), '/employee/timesheets.php');
                    sendMail($ts['email'], 'Timesheet Rejected - CloudFen HR Portal',
                        emailTemplate('Timesheet Rejected',
                            "<p>Your timesheet for <strong>{$wl}</strong> was rejected.</p><p><strong>Reason:</strong> " . e($reason) . "</p>"));
                }
                auditLog('timesheet_' . $action, 'timesheets', $tsId, array('reason' => $reason));
            }
            $msg = "Timesheet {$newStatus}."; $msgType = 'success';

            ts_review_skip:
            ; // no-op — goto target
        }
    }
}

// Filters — all validated
$defaultStatus = $isSA ? 'pending' : 'all';
$inputBag     = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
$filterStatus = validateEnum($inputBag['status'] ?? $defaultStatus, $ALLOWED_STATUSES) ?? $defaultStatus;
$weekFilter   = sanitizeDate($inputBag['week_filter'] ?? '') ?? '';
$empFilter    = sanitizeInt($inputBag['emp_id'] ?? 0, 1) ?? 0;
$focusTsId    = sanitizeInt($inputBag['ts_id'] ?? 0, 1) ?? 0;

$where = array('1=1'); $params = [];
// hr_admin sees only employees; super_admin also sees hr_admin timesheets
if (!$isSA) { $where[] = "u.role = 'employee'"; }
if ($filterStatus !== 'all') { $where[] = 't.status = ?'; $params[] = $filterStatus; }
if ($weekFilter)              { $where[] = 't.week_start = ?'; $params[] = $weekFilter; }
if ($empFilter)               { $where[] = 't.user_id = ?'; $params[] = $empFilter; }

$tsListQ = $db->prepare(
    "SELECT t.*, u.full_name, u.employee_type
     FROM timesheets t JOIN users u ON u.id = t.user_id
     WHERE " . implode(' AND ', $where) . "
     ORDER BY t.submitted_at ASC, t.created_at ASC LIMIT 100"
);
$tsListQ->execute($params);
$tsList = $tsListQ->fetchAll();

if (!$focusTsId && $tsList) {
    $focusTsId = (int)$tsList[0]['id'];
}

$days        = array('mon','tue','wed','thu','fri','sat','sun');
$dLabels     = array('Mon','Tue','Wed','Thu','Fri','Sat','Sun');
$focusTS = null;
$focusAttachments = [];
$focusEntries = [];
if ($focusTsId) {
    $focusWhere = $isSA ? '' : " AND u.role = 'employee'";
    $fs = $db->prepare(
        "SELECT t.*, u.full_name, u.email, u.employee_type
         FROM timesheets t JOIN users u ON u.id = t.user_id WHERE t.id = ?" . $focusWhere
    );
    $fs->execute([$focusTsId]);
    $focusTS = $fs->fetch();

    // Load attachments for this timesheet (visible to HR & super_admin)
    try {
        $aStmt = $db->prepare(
            "SELECT ta.id, ta.file_name, ta.file_size, ta.mime_type, ta.created_at, u.full_name AS uploader
             FROM timesheet_attachments ta
             JOIN users u ON u.id = ta.user_id
             WHERE ta.timesheet_id = ?
             ORDER BY ta.created_at ASC"
        );
        $aStmt->execute([$focusTsId]);
        $focusAttachments = $aStmt->fetchAll();
    } catch (\Throwable $e) { $focusAttachments = []; }

    if ($focusTS) {
        try {
            $entryStmt = $db->prepare(
                "SELECT project, task, hours, description
                 FROM timesheet_entries
                 WHERE timesheet_id = ?
                 ORDER BY id ASC"
            );
            $entryStmt->execute([$focusTsId]);
            foreach ($entryStmt->fetchAll() as $entry) {
                $meta = json_decode($entry['description'] ?? '{}', true) ?: [];
                $dayIdx = max(0, min(6, (int)($meta['day_index'] ?? 0)));
                $focusEntries[] = [
                    'day_idx'    => $dayIdx,
                    'day_label'  => $dLabels[$dayIdx] ?? 'Day',
                    'day_date'   => date('M j', strtotime($focusTS['week_start'] . ' +' . $dayIdx . ' days')),
                    'schedule'   => $meta['schedule'] ?? '',
                    'pay_code'   => $entry['task'] ?? '',
                    'activity'   => $entry['project'] ?? '',
                    'actual_in'  => $meta['actual_in'] ?? '',
                    'actual_out' => $meta['actual_out'] ?? '',
                    'hours'      => (float)($entry['hours'] ?? 0),
                ];
            }
        } catch (\Throwable $e) {
            $focusEntries = [];
        }
    }
}

// Employee dropdown: super_admin sees all; hr_admin sees only employees
$empRoleFilter = $isSA ? "u.role IN ('employee', 'hr_admin', 'super_admin')" : "u.role = 'employee'";
$employees   = $db->query(
    "SELECT DISTINCT u.id, u.full_name, u.role
     FROM users u
     INNER JOIN timesheets t ON t.user_id = u.id
     WHERE $empRoleFilter
     ORDER BY u.full_name ASC"
)->fetchAll();
$pendingIds  = array_column(array_filter($tsList, function($t) { return $t['status'] === 'pending'; }), 'id');
$days        = array('mon','tue','wed','thu','fri','sat','sun');
$dLabels     = array('Mon','Tue','Wed','Thu','Fri','Sat','Sun');
$currentQuery = array('status' => $filterStatus);
if ($weekFilter) { $currentQuery['week_filter'] = $weekFilter; }
if ($empFilter) { $currentQuery['emp_id'] = $empFilter; }
if ($focusTsId) { $currentQuery['ts_id'] = $focusTsId; }

if (!$canAccessApprovalTimesheets) {
    $msg = $timesheetRestrictionMessage;
    $msgType = 'error';
    $tsList = [];
    $employees = [];
    $pendingIds = [];
    $focusTS = null;
}

renderTimesheetsPage:
pageHead('Timesheets');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id'=>$user['id'],'name'=>$user['name'],'role'=>$user['role']], 'timesheets'); ?>
  <div class="main-content">
    <?php renderTopbar('Timesheet Approvals', $user); ?>
    <!-- Sub-tabs: View Submitted Timesheets / Timesheet Approvals / My Timesheets (hr_admin only) -->
    <div style="padding:0 28px;border-bottom:1px solid var(--border);background:var(--surface);display:flex;gap:0;">
      <a href="/admin/submitted_timesheets.php" style="padding:13px 22px;font-size:.88rem;font-weight:600;text-decoration:none;color:var(--gray-400);border-bottom:2px solid transparent;display:inline-block;">View Submitted Timesheets</a>
      <a href="/admin/timesheets.php" style="padding:13px 22px;font-size:.88rem;font-weight:600;text-decoration:none;color:var(--cyan);border-bottom:2px solid var(--cyan);display:inline-block;">Timesheet Approvals</a>
      <?php if (!$isSA): ?>
      <a href="/employee/timesheets.php" style="padding:13px 22px;font-size:.88rem;font-weight:600;text-decoration:none;color:var(--gray-400);border-bottom:2px solid transparent;display:inline-block;">My Timesheets</a>
      <?php endif; ?>
    </div>
    <div class="page-body">
      <div class="page-header flex-between">
        <div><h1>⏱️ Timesheets</h1><p><?= $isSA ? 'Review and approve submitted timesheets across the portal.' : 'View all submitted timesheets across the portal.' ?></p></div>
        <?php if ($canAccessApprovalTimesheets): ?>
        <a href="?export=csv&csrf_token=<?= generateCsrfToken() ?>&week_filter=<?= e($weekFilter) ?>" class="btn btn-outline">📥 Export CSV</a>
        <?php endif; ?>
      </div>

      <?php if ($msg): ?><div class="alert alert-<?= $msgType==='error'?'error':'success' ?>"><?= e($msg) ?></div><?php endif; ?>
      <?php if (!$canAccessApprovalTimesheets): ?>
        <div class="alert alert-warn" style="margin-bottom:20px;"><?= e($timesheetRestrictionMessage) ?></div>
      <?php else: ?>

      <div class="card" style="margin-bottom:20px;">
        <div class="card-body" style="padding:16px 24px;">
          <form method="GET" style="display:flex;gap:12px;flex-wrap:wrap;align-items:center;">
            <select name="status" class="form-control" style="width:160px;" onchange="this.form.submit()">
              <option value="pending"  <?= $filterStatus==='pending'  ?'selected':'' ?>>Pending</option>
              <option value="approved" <?= $filterStatus==='approved' ?'selected':'' ?>>Approved</option>
              <option value="rejected" <?= $filterStatus==='rejected' ?'selected':'' ?>>Rejected</option>
              <option value="all"      <?= $filterStatus==='all'      ?'selected':'' ?>>All</option>
            </select>
            <input type="date" name="week_filter" class="form-control" style="width:180px;" value="<?= e($weekFilter) ?>" onchange="this.form.submit()">
            <select name="emp_id" class="form-control" style="width:200px;" onchange="this.form.submit()">
              <option value="">All Users</option>
              <?php foreach ($employees as $emp): ?>
                <option value="<?= (int)$emp['id'] ?>" <?= $empFilter===(int)$emp['id']?'selected':'' ?>><?= e($emp['full_name']) . ($isSA && in_array($emp['role'] ?? '', ['hr_admin','super_admin']) ? ' [' . str_replace('_',' ', ucwords($emp['role'],'_')) . ']' : '') ?></option>
              <?php endforeach; ?>
            </select>
            <span style="color:var(--text-3);font-size:.85rem;"><?= count($tsList) ?> record(s)</span>
          </form>
          <?php if ($isSA && $pendingIds && $filterStatus === 'pending'): ?>
          <form method="POST" style="margin-top:12px;">
            <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
            <input type="hidden" name="status" value="<?= e($filterStatus) ?>">
            <input type="hidden" name="week_filter" value="<?= e($weekFilter) ?>">
            <input type="hidden" name="emp_id" value="<?= (int)$empFilter ?>">
            <input type="hidden" name="ts_id" value="<?= (int)$focusTsId ?>">
            <input type="hidden" name="action" value="bulk_approve">
            <?php foreach ($pendingIds as $pid): ?><input type="hidden" name="ts_ids[]" value="<?= (int)$pid ?>"><?php endforeach; ?>
            <button type="submit" class="btn btn-success btn-sm" onclick="return confirm('Approve all <?= count($pendingIds) ?> pending timesheet(s)?')">
              ✓ Bulk Approve All (<?= count($pendingIds) ?>)
            </button>
          </form>
          <?php endif; ?>
        </div>
      </div>

      <div class="grid-2" style="gap:24px;align-items:start;">
        <div class="card">
          <div class="card-header"><h3>Timesheets</h3></div>
          <div class="card-body" style="padding:0;">
            <?php if (!$tsList): ?>
              <div style="padding:40px;text-align:center;color:var(--text-3);">No timesheets found.</div>
            <?php endif; ?>
            <?php foreach ($tsList as $t): ?>
              <?php $itemQuery = $currentQuery; $itemQuery['ts_id'] = (int)$t['id']; ?>
              <a href="?<?= e(http_build_query($itemQuery)) ?>"
                 style="display:flex;align-items:center;gap:12px;padding:13px 20px;border-bottom:1px solid var(--surface-3);text-decoration:none;background:<?= $focusTsId===(int)$t['id']?'var(--surface-2)':'transparent' ?>;">
                <div style="flex:1;min-width:0;">
                  <div style="font-weight:600;font-size:.9rem;color:var(--text-1);">
                    <?= e($t['full_name']) ?>
                    <?php if ($t['is_overtime']): ?><span class="badge badge-pending" style="font-size:.68rem;margin-left:4px;">⚠️ OT</span><?php endif; ?>
                  </div>
                  <div style="font-size:.78rem;color:var(--text-3);">Week of <?= e(date('M j, Y', strtotime($t['week_start']))) ?> &bull; <?= e(number_format((float)$t['total_hours'],1)) ?> hrs</div>
                </div>
                <span class="badge badge-<?= e($t['status']) ?>"><?= e(ucfirst($t['status'])) ?></span>
              </a>
            <?php endforeach; ?>
          </div>
        </div>

        <div>
          <?php if ($focusTS): ?>
          <div class="card">
            <div class="card-header">
              <div>
                <h3><?= e($focusTS['full_name']) ?></h3>
                <div style="font-size:.82rem;color:var(--text-3);">Week of <?= e(date('M j, Y', strtotime($focusTS['week_start']))) ?> &bull; <?= e($focusTS['employee_type']) ?></div>
              </div>
              <span class="badge badge-<?= e($focusTS['status']) ?>"><?= e(ucfirst($focusTS['status'])) ?><?php if ($focusTS['is_overtime']): ?> ⚠️<?php endif; ?></span>
            </div>
            <div class="card-body">
              <div class="ts-review-metrics">
                <div class="ts-review-metric">
                  <span class="label">Total Hours</span>
                  <strong><?= e(number_format((float)$focusTS['total_hours'],1)) ?></strong>
                </div>
                <div class="ts-review-metric">
                  <span class="label">Daily Average</span>
                  <strong><?= e(number_format((float)$focusTS['total_hours'] / 7, 1)) ?></strong>
                </div>
                <div class="ts-review-metric">
                  <span class="label">Submitted</span>
                  <strong><?= e($focusTS['submitted_at'] ? date('M j g:i A', strtotime($focusTS['submitted_at'])) : 'Draft') ?></strong>
                </div>
                <div class="ts-review-metric">
                  <span class="label">Rows</span>
                  <strong><?= count($focusEntries) ?></strong>
                </div>
              </div>
              <div class="ts-grid" style="pointer-events:none;">
                <?php foreach ($days as $i => $d): ?>
                  <div class="ts-day">
                    <div class="ts-day-label"><?= e($dLabels[$i]) ?></div>
                    <input type="number" value="<?= e(number_format((float)$focusTS[$d.'_hours'],1)) ?>" disabled>
                  </div>
                <?php endforeach; ?>
              </div>
              <div class="ts-total">
                <div class="ts-total-num <?= $focusTS['is_overtime']?'ts-overtime':'' ?>"><?= e(number_format((float)$focusTS['total_hours'],1)) ?></div>
                <div class="ts-total-label">Total Hours</div>
              </div>
              <?php if ($focusTS['project_code']): ?><?php
                    // Try to look up the project in the projects table for a details link
                    $linkedProject = null;
                    try {
                        if (tableExists('projects')) {
                            $pStmt = $db->prepare(
                                "SELECT id, project_name, client_name FROM projects
                                 WHERE project_name LIKE ? OR id = ? LIMIT 1"
                            );
                            $pStmt->execute(['%' . $focusTS['project_code'] . '%', (int)$focusTS['project_code']]);
                            $linkedProject = $pStmt->fetch();
                        }
                    } catch (\Throwable $e) { /* silent */ }
                ?>
                <div style="margin-top:12px;font-size:.88rem;">
                  <strong>Project:</strong> <?= e($focusTS['project_code']) ?>
                  <?php if ($linkedProject): ?>
                    &nbsp;<a href="/admin/project_details.php?project_id=<?= (int)$linkedProject['id'] ?>" style="font-size:.78rem;color:var(--cyan);text-decoration:none;font-weight:600;">🔗 View Project Details</a>
                  <?php else: ?>
                    &nbsp;<a href="/admin/project_details.php" style="font-size:.78rem;color:var(--cyan);text-decoration:none;font-weight:600;">🔗 View All Projects</a>
                  <?php endif; ?>
                </div>
              <?php endif; ?>
              <?php if ($focusTS['notes']): ?>
                <div class="alert alert-info" style="margin-top:12px;font-size:.88rem;"><strong>Note:</strong> <?= e($focusTS['notes']) ?></div>
              <?php endif; ?>
              <?php if ($focusTS['rejection_reason']): ?>
                <?php $isFlagMsg = str_starts_with($focusTS['rejection_reason'], '⚠️ HR Review Required'); ?>
                <div class="alert alert-<?= $isFlagMsg ? 'warn' : 'error' ?>" style="margin-top:12px;font-size:.88rem;">
                  <strong><?= $isFlagMsg ? '⚠️ HR Action Required:' : 'Previous rejection:' ?></strong>
                  <?= e($focusTS['rejection_reason']) ?>
                </div>
              <?php endif; ?>

              <!-- ── Submitted Rows ──────────────────────────────────── -->
              <div style="margin-top:20px;margin-bottom:18px;">
                <div style="font-size:.82rem;font-weight:700;text-transform:uppercase;color:var(--text-2);letter-spacing:.04em;margin-bottom:8px;">📋 Submitted Rows</div>
                <?php if ($focusEntries): ?>
                  <div class="table-wrap">
                    <table class="ts-review-table">
                      <thead>
                        <tr>
                          <th>Day</th>
                          <th>Schedule</th>
                          <th>Pay Code</th>
                          <th>Activity</th>
                          <th>Actual In</th>
                          <th>Actual Out</th>
                          <th>Hours</th>
                        </tr>
                      </thead>
                      <tbody>
                        <?php foreach ($focusEntries as $entry): ?>
                        <tr>
                          <td><strong><?= e($entry['day_label']) ?></strong><br><span style="color:var(--text-3);font-size:.74rem;"><?= e($entry['day_date']) ?></span></td>
                          <td><?= e($entry['schedule'] ?: '—') ?></td>
                          <td><?= e($entry['pay_code'] ?: '—') ?></td>
                          <td>
                            <?= e($entry['activity'] ?: '—') ?>
                            <?php if ($entry['activity']): ?>
                              <?php
                                $entryProject = null;
                                try {
                                    if (tableExists('projects')) {
                                        $epStmt = $db->prepare("SELECT id FROM projects WHERE project_name LIKE ? LIMIT 1");
                                        $epStmt->execute(['%' . $entry['activity'] . '%']);
                                        $entryProject = $epStmt->fetch();
                                    }
                                } catch (\Throwable $e) {}
                              ?>
                              <?php if ($entryProject): ?>
                                <br><a href="/admin/project_details.php?project_id=<?= (int)$entryProject['id'] ?>" style="font-size:.72rem;color:var(--cyan);text-decoration:none;">🔗 Details</a>
                              <?php endif; ?>
                            <?php endif; ?>
                          </td>
                          <td><?= e($entry['actual_in'] ?: '—') ?></td>
                          <td><?= e($entry['actual_out'] ?: '—') ?></td>
                          <td><strong><?= e(number_format((float)$entry['hours'], 1)) ?></strong></td>
                        </tr>
                        <?php endforeach; ?>
                      </tbody>
                    </table>
                  </div>
                <?php else: ?>
                  <div style="font-size:.84rem;color:var(--text-3);padding:10px 0;">No row-level entry details were submitted for this timesheet.</div>
                <?php endif; ?>
              </div>

              <!-- ── Attachments (visible to HR & Super Admin) ───────── -->
              <div style="margin-top:20px;">
                <div style="font-size:.82rem;font-weight:700;text-transform:uppercase;color:var(--text-2);letter-spacing:.04em;margin-bottom:8px;">📎 Attachments</div>

                <?php if ($focusAttachments): ?>
                  <?php foreach ($focusAttachments as $att): ?>
                    <?php
                      $kb      = round($att['file_size'] / 1024, 1);
                      $icon    = $att['mime_type'] === 'application/pdf' ? '📄' : '🖼️';
                      $safeN   = e($att['file_name']);
                      $safeSz  = e($kb . ' KB');
                      $safeUp  = e($att['uploader']);
                      $safeDate= e(date('M j, Y g:i A', strtotime($att['created_at'])));
                    ?>
                    <div style="display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--surface-3);border-radius:7px;margin-bottom:6px;background:var(--surface-2);">
                      <span style="font-size:1.3rem;"><?= $icon ?></span>
                      <div style="flex:1;min-width:0;">
                        <div style="font-size:.88rem;font-weight:600;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><?= $safeN ?></div>
                        <div style="font-size:.76rem;color:var(--text-3);"><?= $safeSz ?> &bull; Uploaded by <?= $safeUp ?> on <?= $safeDate ?></div>
                      </div>
                      <a href="/api/download_attachment.php?id=<?= (int)$att['id'] ?>" class="btn btn-outline btn-sm" style="white-space:nowrap;">⬇️ Download</a>
                      <?php if ($user['role'] === 'super_admin'): ?>
                      <form method="POST" style="margin:0;" onsubmit="return confirm('Delete this attachment?');">
                        <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                        <input type="hidden" name="status" value="<?= e($filterStatus) ?>">
                        <input type="hidden" name="week_filter" value="<?= e($weekFilter) ?>">
                        <input type="hidden" name="emp_id" value="<?= (int)$empFilter ?>">
                        <input type="hidden" name="ts_id" value="<?= (int)$focusTsId ?>">
                        <input type="hidden" name="action" value="delete_attachment">
                        <input type="hidden" name="att_id" value="<?= (int)$att['id'] ?>">
                        <button type="submit" class="btn btn-danger btn-sm">🗑</button>
                      </form>
                      <?php endif; ?>
                    </div>
                  <?php endforeach; ?>
                <?php else: ?>
                  <div style="font-size:.84rem;color:var(--text-3);padding:10px 0;">No attachments uploaded for this timesheet.</div>
                <?php endif; ?>
              </div>
              <!-- ─────────────────────────────────────────────────────── -->
              <?php if ($isSA && $focusTS['status'] === 'pending'): ?>
              <form method="POST" style="margin-top:20px;">
                <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                <input type="hidden" name="status" value="<?= e($filterStatus) ?>">
                <input type="hidden" name="week_filter" value="<?= e($weekFilter) ?>">
                <input type="hidden" name="emp_id" value="<?= (int)$empFilter ?>">
                <input type="hidden" name="ts_id" value="<?= (int)$focusTS['id'] ?>">
                <input type="hidden" name="action" id="ts-act">
                <div id="ts-reason-wrap" style="display:none;margin-bottom:12px;">
                  <label style="font-size:.82rem;font-weight:600;text-transform:uppercase;color:var(--text-2);">Rejection Reason *</label>
                  <textarea name="reason" class="form-control" rows="2" maxlength="1000" placeholder="Explain why..."></textarea>
                </div>
                <div style="display:flex;gap:10px;">
                  <button type="button" class="btn btn-success" id="btn-approve" onclick="tsAction('approve', this)"><span class="btn-text">✓ Approve</span></button>
                  <button type="button" class="btn btn-danger"  id="btn-reject"  onclick="tsAction('reject', this)"><span class="btn-text">✗ Reject</span></button>
                </div>
                <button type="submit" class="btn btn-navy btn-block" id="ts-confirm" style="display:none;margin-top:10px;" onclick="this.classList.add('btn-loading')"><span class="btn-text">Confirm →</span></button>
              </form>
              <?php elseif (!$isSA && $focusTS['status'] === 'pending'): ?>
              <div class="alert alert-info" style="margin-top:20px;font-size:.88rem;">This submitted timesheet is awaiting Super Admin review.</div>
              <?php endif; ?>
            </div>
          </div>
          <?php else: ?>
            <div class="card"><div class="card-body" style="text-align:center;padding:60px 24px;color:var(--text-3);">
              <div style="font-size:3rem;margin-bottom:12px;">👈</div><p>Select a timesheet to review.</p>
            </div></div>
          <?php endif; ?>
        </div>
      </div>
      <?php endif; ?>
    </div>
  </div>
</div>
<script>
function tsAction(action, clickedBtn) {
  document.getElementById('ts-act').value = action;
  document.getElementById('ts-reason-wrap').style.display = action === 'reject' ? 'block' : 'none';
  // Reset both action buttons, highlight active one
  ['btn-approve','btn-reject'].forEach(function(id) {
    var b = document.getElementById(id);
    if (b) b.classList.remove('btn-loading');
  });
  const confirmBtn = document.getElementById('ts-confirm');
  confirmBtn.style.display = 'block';
  var label = action === 'approve' ? '✓ Confirm Approval' : '✗ Confirm Rejection';
  confirmBtn.querySelector('.btn-text').textContent = label;
  confirmBtn.className = 'btn btn-block ' + (action === 'approve' ? 'btn-success' : 'btn-danger');
  confirmBtn.style.marginTop = '10px';
}
</script>
<style>
.ts-review-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(132px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
}
.ts-review-metric {
  padding: 12px 14px;
  border: 1px solid var(--surface-3);
  border-radius: 10px;
  background: var(--surface-2);
}
.ts-review-metric .label {
  display: block;
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--text-3);
  margin-bottom: 4px;
}
.ts-review-metric strong {
  color: var(--text-1);
  font-size: .92rem;
}
.ts-review-table th,
.ts-review-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--surface-3);
  text-align: left;
  font-size: .8rem;
  vertical-align: top;
}
.ts-review-table th {
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: .05em;
  font-size: .7rem;
  background: var(--surface-2);
}
</style>
<?php pageFooter(); ?>
</body></html>
