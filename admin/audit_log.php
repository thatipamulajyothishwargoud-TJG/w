<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

$ALLOWED_ACTIONS = [
    'login_success', 'login_failed', 'logout', 'csrf_failure',
    'rate_limit_login', 'rate_limit_login_email',
    'user_registered', 'email_verified', 'password_reset_requested', 'password_reset_completed',
    'password_changed', 'profile_updated', 'start_date_updated',
    'document_uploaded', 'document_approve', 'document_reject',
    'document_more_info', 'document_viewed',
    'timesheet_save', 'timesheet_submit', 'timesheet_approve', 'timesheet_reject',
    'timesheets_exported',
    'employee_deactivate', 'employee_reactivate',
    'hr_note_added', 'unauthorized_access',
    'onboarding_complete',
];

// Pagination — sanitized
$page   = max(1, sanitizeInt($_GET['page'] ?? 1, 1, 9999) ?? 1);
$limit  = 50;
$offset = ($page - 1) * $limit;

// Filters — both validated
$search = sanitizeString($_GET['search'] ?? '', 80);
$actionFilter = isset($_GET['action_filter'])
    ? (validateEnum($_GET['action_filter'], $ALLOWED_ACTIONS) ?? '')
    : '';

$where  = array('1=1');
$params = [];

if ($search) {
    $where[]  = '(u.full_name LIKE ? OR a.ip_address LIKE ?)';
    $params[] = '%' . $search . '%';
    $params[] = '%' . $search . '%';
}
if ($actionFilter) {
    $where[]  = 'a.action = ?';
    $params[] = $actionFilter;
}

$whereSQL = implode(' AND ', $where);

// Total count
$totalStmt = $db->prepare(
    "SELECT COUNT(*) FROM audit_log a LEFT JOIN users u ON u.id = a.user_id WHERE $whereSQL"
);
$totalStmt->execute($params);
$total = (int)$totalStmt->fetchColumn();
$pages = max(1, (int)ceil($total / $limit));
$page  = min($page, $pages); // clamp to valid range

// Log rows — LIMIT/OFFSET are integers, safe to interpolate
$logStmt = $db->prepare(
    "SELECT a.id, a.action, a.resource, a.resource_id, a.details,
            a.ip_address, a.created_at, u.full_name
     FROM audit_log a
     LEFT JOIN users u ON u.id = a.user_id
     WHERE $whereSQL
     ORDER BY a.created_at DESC
     LIMIT $limit OFFSET $offset"
);
$logStmt->execute($params);
$logs = $logStmt->fetchAll();

// Badge colour mapping — fixed map, no user data
$actionBadge = array(
    'login_success'             => 'approved',
    'login_failed'              => 'rejected',
    'logout'                    => 'missing',
    'csrf_failure'              => 'rejected',
    'rate_limit_login'          => 'rejected',
    'rate_limit_login_email'    => 'rejected',
    'unauthorized_access'       => 'rejected',
    'document_uploaded'         => 'info',
    'document_approve'          => 'approved',
    'document_reject'           => 'rejected',
    'document_more_info'        => 'info',
    'document_viewed'           => 'info',
    'timesheet_submit'          => 'info',
    'timesheet_approve'         => 'approved',
    'timesheet_reject'          => 'rejected',
    'timesheets_exported'       => 'info',
    'user_registered'           => 'approved',
    'email_verified'            => 'approved',
    'password_reset_requested'  => 'pending',
    'password_reset_completed'  => 'pending',
    'employee_deactivate'       => 'rejected',
    'employee_reactivate'       => 'approved',
    'hr_note_added'             => 'info',
    'onboarding_complete'       => 'approved',
);

pageHead('Audit Log');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'audit'); ?>
  <div class="main-content">
    <?php renderTopbar('Audit Log', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <h1>🔍 Audit Log</h1>
        <p>Complete tamper-evident record of all system actions — <?= number_format($total) ?> total entries.</p>
      </div>

      <!-- Filters -->
      <div class="card" style="margin-bottom:20px;">
        <div class="card-body" style="padding:16px 24px;">
          <form method="GET" style="display:flex;gap:12px;flex-wrap:wrap;align-items:center;">
            <input type="text" name="search" class="form-control" style="width:220px;"
                   placeholder="🔍 Name or IP..." value="<?= e($search) ?>" maxlength="80">
            <select name="action_filter" class="form-control" style="width:240px;" onchange="this.form.submit()">
              <option value="">All Actions</option>
              <?php foreach ($ALLOWED_ACTIONS as $a): ?>
                <option value="<?= e($a) ?>" <?= $actionFilter === $a ? 'selected' : '' ?>>
                  <?= e(str_replace('_', ' ', ucfirst($a))) ?>
                </option>
              <?php endforeach; ?>
            </select>
            <button type="submit" class="btn btn-primary btn-sm" onclick="this.classList.add('btn-loading')"><span class="btn-text">Filter</span></button>
            <?php if ($search || $actionFilter): ?>
              <a href="/admin/audit_log.php" class="btn btn-outline btn-sm" onclick="this.classList.add('btn-loading')"><span class="btn-text">Clear</span></a>
            <?php endif; ?>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-body" style="padding:0;">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>IP Address</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                <?php if (!$logs): ?>
                  <tr><td colspan="6" style="text-align:center;padding:40px;color:var(--gray-400);">No log entries found.</td></tr>
                <?php endif; ?>
                <?php foreach ($logs as $log): ?>
                  <tr>
                    <td style="white-space:nowrap;font-size:.78rem;color:var(--gray-400);">
                      <?= e(date('M j, Y H:i:s', strtotime($log['created_at']))) ?>
                    </td>
                    <td style="font-weight:600;font-size:.88rem;">
                      <?= e($log['full_name'] ?? 'System') ?>
                    </td>
                    <td>
                      <span class="badge badge-<?= e($actionBadge[$log['action']] ?? 'missing') ?>" style="font-size:.72rem;">
                        <?= e(str_replace('_', ' ', $log['action'])) ?>
                      </span>
                    </td>
                    <td style="font-size:.82rem;color:var(--gray-600);">
                      <?php if ($log['resource']): ?>
                        <?= e($log['resource']) ?><?= $log['resource_id'] ? ' #' . (int)$log['resource_id'] : '' ?>
                      <?php else: ?>—<?php endif; ?>
                    </td>
                    <td style="font-size:.78rem;font-family:monospace;color:var(--gray-400);">
                      <?= e($log['ip_address'] ?? '—') ?>
                    </td>
                    <td style="font-size:.75rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--gray-400);">
                      <?php
                      if ($log['details']) {
                          $d = json_decode($log['details'], true);
                          if (is_array($d)) {
                              $parts = [];
                              foreach ($d as $k => $v) {
                                  // Mask sensitive keys
                                  $display = in_array($k, ['password','hash','token'], true) ? '[redacted]' : (string)$v;
                                  $parts[] = e($k) . ': ' . e(mb_substr($display, 0, 40, 'UTF-8'));
                              }
                              echo implode(', ', $parts);
                          }
                      } else {
                          echo '—';
                      }
                      ?>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Pagination -->
        <?php if ($pages > 1): ?>
        <div style="padding:16px 24px;border-top:1px solid var(--gray-100);display:flex;align-items:center;justify-content:space-between;">
          <div style="font-size:.85rem;color:var(--gray-400);">
            Page <?= $page ?> of <?= $pages ?> &bull; <?= number_format($total) ?> entries
          </div>
          <div style="display:flex;gap:8px;">
            <?php if ($page > 1): ?>
              <a href="?page=<?= $page - 1 ?>&search=<?= urlencode($search) ?>&action_filter=<?= urlencode($actionFilter) ?>"
                 class="btn btn-outline btn-sm" onclick="this.classList.add('btn-loading')"><span class="btn-text">← Prev</span></a>
            <?php endif; ?>
            <?php if ($page < $pages): ?>
              <a href="?page=<?= $page + 1 ?>&search=<?= urlencode($search) ?>&action_filter=<?= urlencode($actionFilter) ?>"
                 class="btn btn-primary btn-sm" onclick="this.classList.add('btn-loading')"><span class="btn-text">Next →</span></a>
            <?php endif; ?>
          </div>
        </div>
        <?php endif; ?>
      </div>

    </div>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
