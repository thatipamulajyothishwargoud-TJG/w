<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();
$isSA = $user['role'] === 'super_admin';
$isHR = $user['role'] === 'hr_admin';
$canAccessSubmittedTimesheets = $isSA || userCanAccessTimesheetsModule((int)$user['id'], (string)$user['role']);
$timesheetRestrictionMessage = getComplianceRestrictionMessage();

$ALLOWED_STATUSES = array('pending', 'approved', 'rejected', 'all');

// CSV Export — before any HTML output
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    if (!$canAccessSubmittedTimesheets) {
        http_response_code(403);
        die('Access denied.');
    }
    verifyCsrf();
    $weekFilter = sanitizeDate($_GET['week_filter'] ?? '') ?? '';
    $empFilter  = sanitizeInt($_GET['emp_id'] ?? 0, 1) ?? 0;
    $filterSt   = validateEnum($_GET['status'] ?? 'all', $ALLOWED_STATUSES) ?? 'all';

    $where = ["t.status != 'draft'"]; $params = [];
    if (!$isSA) { $where[] = "u.role = 'employee'"; }
    if ($filterSt !== 'all') { $where[] = 't.status = ?'; $params[] = $filterSt; }
    if ($weekFilter)         { $where[] = 't.week_start = ?'; $params[] = $weekFilter; }
    if ($empFilter)          { $where[] = 't.user_id = ?'; $params[] = $empFilter; }

    $exp = $db->prepare(
        "SELECT u.full_name, u.email, u.employee_type,
                t.week_start, t.mon_hours, t.tue_hours, t.wed_hours, t.thu_hours,
                t.fri_hours, t.sat_hours, t.sun_hours, t.total_hours,
                t.status, t.notes, t.project_code, t.submitted_at
         FROM timesheets t JOIN users u ON u.id = t.user_id
         WHERE " . implode(' AND ', $where) . "
         ORDER BY t.submitted_at DESC, u.full_name ASC"
    );
    $exp->execute($params);
    $rows = $exp->fetchAll();

    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="cloudfen_submitted_timesheets_' . date('Ymd') . '.csv"');
    header('X-Content-Type-Options: nosniff');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['Employee Name', 'Email', 'Type', 'Week Start', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun', 'Total Hours', 'Status', 'Notes', 'Project Code', 'Submitted At']);
    foreach ($rows as $r) fputcsv($out, array_values($r));
    fclose($out);
    auditLog('submitted_timesheets_exported', 'timesheets', null, array('count' => count($rows)));
    exit;
}

// ── Filters ──────────────────────────────────────────────────
$inputBag    = $_GET;
$filterStatus = validateEnum($inputBag['status'] ?? 'all', $ALLOWED_STATUSES) ?? 'all';
$weekFilter   = sanitizeDate($inputBag['week_filter'] ?? '') ?? '';
$empFilter    = sanitizeInt($inputBag['emp_id'] ?? 0, 1) ?? 0;

// Build query — exclude drafts; HR sees only employees, super_admin sees all
$where = ["t.status != 'draft'"]; $params = [];
if (!$isSA) { $where[] = "u.role = 'employee'"; }
if ($filterStatus !== 'all') { $where[] = 't.status = ?'; $params[] = $filterStatus; }
if ($weekFilter)              { $where[] = 't.week_start = ?'; $params[] = $weekFilter; }
if ($empFilter)               { $where[] = 't.user_id = ?'; $params[] = $empFilter; }

$tsListQ = $db->prepare(
    "SELECT t.id, t.user_id, t.week_start, t.total_hours, t.status,
            t.submitted_at, t.project_code, t.notes, t.is_overtime,
            t.mon_hours, t.tue_hours, t.wed_hours, t.thu_hours,
            t.fri_hours, t.sat_hours, t.sun_hours,
            u.full_name, u.employee_type, u.role AS user_role,
            (SELECT COUNT(*) FROM timesheet_attachments ta WHERE ta.timesheet_id = t.id) AS attachment_count
     FROM timesheets t JOIN users u ON u.id = t.user_id
     WHERE " . implode(' AND ', $where) . "
     ORDER BY t.submitted_at DESC, t.created_at DESC LIMIT 200"
);
$tsListQ->execute($params);
$tsList = $tsListQ->fetchAll();

// Employee dropdown
$empRoleFilter = $isSA
    ? "u.role IN ('employee', 'hr_admin', 'super_admin')"
    : "u.role = 'employee'";
$empList = $db->query(
    "SELECT DISTINCT u.id, u.full_name, u.role
     FROM timesheets t JOIN users u ON u.id = t.user_id
     WHERE {$empRoleFilter} AND t.status != 'draft'
     ORDER BY u.full_name ASC"
)->fetchAll();

// Stats
$totalCountQ = $db->prepare("SELECT COUNT(*) FROM timesheets t JOIN users u ON u.id = t.user_id WHERE " . implode(' AND ', $where));
$totalCountQ->execute($params);
$total    = (int)$totalCountQ->fetchColumn();
$pending  = count(array_filter($tsList, fn($t) => $t['status'] === 'pending'));
$approved = count(array_filter($tsList, fn($t) => $t['status'] === 'approved'));
$rejected = count(array_filter($tsList, fn($t) => $t['status'] === 'rejected'));

// CSRF for export
$csrfToken = generateCsrfToken();

pageHead('View Submitted Timesheets');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'submitted_timesheets'); ?>
  <div class="main-content">
    <?php renderTopbar('View Submitted Timesheets', $user); ?>
    <!-- Sub-tabs: View Submitted Timesheets / Timesheet Approvals / My Timesheets (hr_admin only) -->
    <div style="padding:0 28px;border-bottom:1px solid var(--border);background:var(--surface);display:flex;gap:0;">
      <a href="/admin/submitted_timesheets.php" style="padding:13px 22px;font-size:.88rem;font-weight:600;text-decoration:none;color:var(--cyan);border-bottom:2px solid var(--cyan);display:inline-block;">View Submitted Timesheets</a>
      <a href="/admin/timesheets.php" style="padding:13px 22px;font-size:.88rem;font-weight:600;text-decoration:none;color:var(--gray-400);border-bottom:2px solid transparent;display:inline-block;">Timesheet Approvals</a>
      <?php if ($isHR): ?>
      <a href="/employee/timesheets.php" style="padding:13px 22px;font-size:.88rem;font-weight:600;text-decoration:none;color:var(--gray-400);border-bottom:2px solid transparent;display:inline-block;">My Timesheets</a>
      <?php endif; ?>
    </div>
    <div class="page-body">

      <div class="page-header flex-between">
        <div>
          <h1>📋 Submitted Timesheets</h1>
          <p><?= $isSA ? 'All employee submitted timesheets across the portal.' : 'View all submitted employee timesheets.' ?></p>
        </div>
        <?php if ($canAccessSubmittedTimesheets): ?>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end;">
          <?php
            $exportParams = http_build_query(array_filter([
                'export'      => 'csv',
                'csrf_token'  => $csrfToken,
                'status'      => $filterStatus !== 'all' ? $filterStatus : '',
                'week_filter' => $weekFilter,
                'emp_id'      => $empFilter ?: '',
            ]));
          ?>
          <a href="?<?= $exportParams ?>" class="btn btn-outline btn-sm">⬇ Export CSV</a>
        </div>
        <?php endif; ?>
      </div>

      <?php if (!$canAccessSubmittedTimesheets): ?>
        <div class="alert alert-warn"><?= e($timesheetRestrictionMessage) ?></div>
      <?php else: ?>

      <!-- Stats Row -->
      <div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px;">
        <div class="card" style="flex:1;min-width:130px;">
          <div class="card-body" style="padding:14px 18px;text-align:center;">
            <div style="font-size:1.7rem;font-weight:700;color:var(--text-1);"><?= $total ?></div>
            <div style="font-size:.8rem;color:var(--text-3);margin-top:2px;">Total Submitted</div>
          </div>
        </div>
        <div class="card" style="flex:1;min-width:130px;">
          <div class="card-body" style="padding:14px 18px;text-align:center;">
            <div style="font-size:1.7rem;font-weight:700;color:var(--yellow);"><?= $pending ?></div>
            <div style="font-size:.8rem;color:var(--text-3);margin-top:2px;">Pending</div>
          </div>
        </div>
        <div class="card" style="flex:1;min-width:130px;">
          <div class="card-body" style="padding:14px 18px;text-align:center;">
            <div style="font-size:1.7rem;font-weight:700;color:var(--green);"><?= $approved ?></div>
            <div style="font-size:.8rem;color:var(--text-3);margin-top:2px;">Approved</div>
          </div>
        </div>
        <div class="card" style="flex:1;min-width:130px;">
          <div class="card-body" style="padding:14px 18px;text-align:center;">
            <div style="font-size:1.7rem;font-weight:700;color:var(--red);"><?= $rejected ?></div>
            <div style="font-size:.8rem;color:var(--text-3);margin-top:2px;">Rejected</div>
          </div>
        </div>
      </div>

      <!-- Filters -->
      <div class="card" style="margin-bottom:18px;">
        <div class="card-body" style="padding:14px 20px;">
          <form method="GET" action="" style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;">
            <div>
              <label style="display:block;font-size:.78rem;color:var(--text-3);margin-bottom:4px;font-weight:600;">Status</label>
              <select name="status" class="form-control" style="width:140px;" onchange="this.form.submit()">
                <option value="all"      <?= $filterStatus === 'all'      ? 'selected' : '' ?>>All Statuses</option>
                <option value="pending"  <?= $filterStatus === 'pending'  ? 'selected' : '' ?>>Pending</option>
                <option value="approved" <?= $filterStatus === 'approved' ? 'selected' : '' ?>>Approved</option>
                <option value="rejected" <?= $filterStatus === 'rejected' ? 'selected' : '' ?>>Rejected</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:.78rem;color:var(--text-3);margin-bottom:4px;font-weight:600;">Week Starting</label>
              <input type="date" name="week_filter" class="form-control" value="<?= e($weekFilter) ?>" onchange="this.form.submit()" style="width:160px;">
            </div>
            <div>
              <label style="display:block;font-size:.78rem;color:var(--text-3);margin-bottom:4px;font-weight:600;">Employee</label>
              <select name="emp_id" class="form-control" style="width:200px;" onchange="this.form.submit()">
                <option value="">All Employees</option>
                <?php foreach ($empList as $emp): ?>
                  <option value="<?= (int)$emp['id'] ?>" <?= $empFilter === (int)$emp['id'] ? 'selected' : '' ?>>
                    <?= e($emp['full_name']) ?><?= ($isSA && in_array($emp['role'] ?? '', ['hr_admin', 'super_admin'])) ? ' [' . str_replace('_', ' ', ucwords($emp['role'], '_')) . ']' : '' ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </div>
            <?php if ($filterStatus !== 'all' || $weekFilter || $empFilter): ?>
              <div style="display:flex;align-items:flex-end;">
                <a href="?" class="btn btn-outline btn-sm" style="margin-bottom:0;">✕ Clear Filters</a>
              </div>
            <?php endif; ?>
          </form>
        </div>
      </div>

      <!-- Timesheets Table -->
      <div class="card">
        <div class="card-body" style="padding:0;">
          <?php if (empty($tsList)): ?>
            <div style="padding:48px;text-align:center;color:var(--text-3);">
              <div style="font-size:2.5rem;margin-bottom:10px;">📭</div>
              <div style="font-size:1rem;font-weight:600;margin-bottom:6px;">No submitted timesheets found</div>
              <div style="font-size:.85rem;">Try adjusting your filters above.</div>
            </div>
          <?php else: ?>
            <div style="overflow-x:auto;">
              <table class="data-table" style="width:100%;border-collapse:collapse;">
                <thead>
                  <tr>
                    <th style="padding:11px 16px;text-align:left;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Employee</th>
                    <th style="padding:11px 16px;text-align:left;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Week Starting</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Mon</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Tue</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Wed</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Thu</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Fri</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Sat</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Sun</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Total Hrs</th>
                    <th style="padding:11px 16px;text-align:left;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Status</th>
                    <th style="padding:11px 16px;text-align:left;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Submitted</th>
                    <th style="padding:11px 16px;text-align:left;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Project</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">📎 Files</th>
                    <th style="padding:11px 16px;text-align:center;font-size:.78rem;font-weight:700;color:var(--text-3);border-bottom:1px solid var(--border);white-space:nowrap;">Action</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($tsList as $i => $t): ?>
                    <tr style="border-bottom:1px solid var(--border);<?= $i % 2 === 1 ? 'background:rgba(255,255,255,.015);' : '' ?>">
                      <td style="padding:11px 16px;">
                        <div style="font-weight:600;font-size:.9rem;color:var(--text-1);"><?= e($t['full_name']) ?></div>
                        <?php if ($t['employee_type']): ?>
                          <div style="font-size:.76rem;color:var(--text-3);margin-top:1px;"><?= e(ucwords(str_replace('_', ' ', $t['employee_type']))) ?></div>
                        <?php endif; ?>
                        <?php if ($isSA && in_array($t['user_role'] ?? '', ['hr_admin', 'super_admin'])): ?>
                          <div style="font-size:.72rem;color:var(--cyan);margin-top:1px;">[<?= e(str_replace('_', ' ', ucwords($t['user_role'], '_'))) ?>]</div>
                        <?php endif; ?>
                      </td>
                      <td style="padding:11px 16px;font-size:.88rem;color:var(--text-2);white-space:nowrap;">
                        <?= e(date('M j, Y', strtotime($t['week_start']))) ?>
                      </td>
                      <?php
                        $days = ['mon_hours','tue_hours','wed_hours','thu_hours','fri_hours','sat_hours','sun_hours'];
                        foreach ($days as $d):
                          $hrs = (float)($t[$d] ?? 0);
                      ?>
                      <td style="padding:11px 16px;text-align:center;font-size:.86rem;color:<?= $hrs > 0 ? 'var(--text-1)' : 'var(--text-3)' ?>;">
                        <?= $hrs > 0 ? number_format($hrs, 1) : '—' ?>
                      </td>
                      <?php endforeach; ?>
                      <td style="padding:11px 16px;text-align:center;">
                        <strong style="font-size:.95rem;color:<?= $t['is_overtime'] ? 'var(--yellow)' : 'var(--text-1)' ?>;">
                          <?= number_format((float)$t['total_hours'], 1) ?>
                        </strong>
                        <?php if ($t['is_overtime']): ?>
                          <span style="font-size:.68rem;color:var(--yellow);display:block;">⚠️ OT</span>
                        <?php endif; ?>
                      </td>
                      <td style="padding:11px 16px;">
                        <span class="badge badge-<?= e($t['status']) ?>"><?= e(ucfirst($t['status'])) ?></span>
                      </td>
                      <td style="padding:11px 16px;font-size:.83rem;color:var(--text-3);white-space:nowrap;">
                        <?= $t['submitted_at'] ? e(date('M j, Y g:i A', strtotime($t['submitted_at']))) : '<span style="color:var(--text-3);">—</span>' ?>
                      </td>
                      <td style="padding:11px 16px;font-size:.83rem;color:var(--text-2);">
                        <?= $t['project_code'] ? e($t['project_code']) : '<span style="color:var(--text-3);">—</span>' ?>
                      </td>
                      <td style="padding:11px 16px;text-align:center;">
                        <?php if ((int)($t['attachment_count'] ?? 0) > 0): ?>
                          <span style="display:inline-flex;align-items:center;gap:4px;font-size:.82rem;font-weight:600;color:var(--cyan);">
                            📎 <?= (int)$t['attachment_count'] ?>
                          </span>
                        <?php else: ?>
                          <span style="font-size:.78rem;color:var(--text-3);">—</span>
                        <?php endif; ?>
                      </td>
                      <td style="padding:11px 16px;text-align:center;">
                        <a href="/admin/timesheets.php?ts_id=<?= (int)$t['id'] ?>&status=all"
                           class="btn btn-outline btn-sm" style="white-space:nowrap;">View →</a>
                      </td>
                    </tr>
                    <?php if ($t['notes']): ?>
                    <tr style="border-bottom:1px solid var(--border);background:rgba(31,160,192,.04);">
                      <td colspan="15" style="padding:6px 16px 10px 32px;font-size:.82rem;color:var(--text-3);">
                        <span style="font-weight:600;color:var(--text-2);">Notes:</span> <?= e($t['notes']) ?>
                      </td>
                    </tr>
                    <?php endif; ?>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
            <div style="padding:12px 20px;font-size:.8rem;color:var(--text-3);border-top:1px solid var(--border);">
              Showing <?= count($tsList) ?> timesheet(s)<?= count($tsList) >= 200 ? ' (limit 200 — use filters or export CSV for full data)' : '' ?>.
            </div>
          <?php endif; ?>
        </div>
      </div>
      <?php endif; ?>

    </div><!-- /page-body -->
  </div><!-- /main-content -->
</div><!-- /app-shell -->
<?php pageFooter(); ?>
</body>
</html>
