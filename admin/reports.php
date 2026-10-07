<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

// ── All queries use fixed SQL — zero user input involved ─────────────────────

// Onboarding matrix — fixed CASE expressions, no interpolation
$onboardingQ = $db->query(
    "SELECT u.id, u.full_name, u.email, u.employee_type, u.status AS acc_status,
       MAX(CASE WHEN d.doc_type = 'drivers_license'    THEN d.status END) AS drivers_license,
       MAX(CASE WHEN d.doc_type = 'i9'                 THEN d.status END) AS i9,
       MAX(CASE WHEN d.doc_type = 'direct_deposit'     THEN d.status END) AS direct_deposit,
       MAX(CASE WHEN d.doc_type = 'passport'           THEN d.status END) AS passport,
       MAX(CASE WHEN d.doc_type = 'work_authorization' THEN d.status END) AS work_authorization,
       MAX(CASE WHEN d.doc_type = 'h1b_i797'           THEN d.status END) AS h1b_i797
     FROM users u
     LEFT JOIN documents d ON d.user_id = u.id
     WHERE u.role = 'employee'
     GROUP BY u.id, u.full_name, u.email, u.employee_type, u.status
     ORDER BY u.full_name ASC"
);
$employees = $onboardingQ->fetchAll();

// Expiring documents — next 60 days
$expiringQ = $db->query(
    "SELECT d.id, d.doc_type, d.expiry_date, u.full_name, u.email,
            DATEDIFF(d.expiry_date, CURDATE()) AS days_left
     FROM documents d
     JOIN users u ON u.id = d.user_id
     WHERE d.expiry_date IS NOT NULL
       AND d.expiry_date >= CURDATE()
       AND d.expiry_date <= DATE_ADD(CURDATE(), INTERVAL 60 DAY)
       AND d.status = 'approved'
     ORDER BY d.expiry_date ASC"
);
$expiring = $expiringQ->fetchAll();

// Timesheet compliance — last 4 weeks
$compQ = $db->query(
    "SELECT u.id, u.full_name,
       COUNT(t.id) AS submitted,
       SUM(CASE WHEN t.status = 'approved' THEN 1 ELSE 0 END) AS approved
     FROM users u
     LEFT JOIN timesheets t
       ON t.user_id = u.id
       AND t.week_start >= DATE_SUB(CURDATE(), INTERVAL 28 DAY)
     WHERE u.role = 'employee' AND u.status = 'active'
     GROUP BY u.id, u.full_name
     ORDER BY u.full_name ASC"
);
$compliance = $compQ->fetchAll();

// Summary counts
$fullyOnboarded = 0;
foreach ($employees as $e) {
    if ($e['drivers_license'] === 'approved'
        && $e['i9']           === 'approved'
        && $e['direct_deposit']=== 'approved') {
        $fullyOnboarded++;
    }
}
$pct = count($employees) > 0
    ? round($fullyOnboarded / count($employees) * 100)
    : 0;

$docLabels = array(
    'drivers_license'    => "Driver's License",
    'i9'                 => 'Form I-9',
    'direct_deposit'     => 'Direct Deposit',
    'passport'           => 'Passport',
    'work_authorization' => 'Work Auth',
    'h1b_i797'           => 'H-1B',
    'social_security'    => 'SSN Card',
    'education'          => 'Education',
    'other'              => 'Other Document',
);

// Helper: status icon (no user data — fixed values)
function statusIcon($s) {
    switch ($s) {
        case 'approved':         return '<span style="color:var(--mint);font-weight:700;">✓</span>';
        case 'pending':          return '<span style="color:var(--amber);">⏳</span>';
        case 'rejected':         return '<span style="color:var(--rose);font-weight:700;">✗</span>';
        case 'more_info_needed': return '<span style="color:var(--sky);">ℹ</span>';
        default:                 return '<span style="color:var(--gray-400);">○</span>';
    }
}

pageHead('Reports');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'reports'); ?>
  <div class="main-content">
    <?php renderTopbar('Reports & Insights', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <h1>📈 Reports</h1>
        <p>Onboarding status, document expiry alerts, and timesheet compliance.</p>
      </div>

      <!-- Summary stats -->
      <div class="stats-grid" style="margin-bottom:28px;">
        <div class="stat-card">
          <div class="stat-icon blue">👥</div>
          <div><div class="stat-value"><?= count($employees) ?></div><div class="stat-label">Total Employees</div></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon mint">🎉</div>
          <div><div class="stat-value"><?= $fullyOnboarded ?></div><div class="stat-label">Fully Onboarded</div></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon <?= count($expiring) ? 'rose' : 'mint' ?>">⚠️</div>
          <div><div class="stat-value"><?= count($expiring) ?></div><div class="stat-label">Expiring Docs</div></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon blue">📊</div>
          <div><div class="stat-value"><?= $pct ?>%</div><div class="stat-label">Onboarding Rate</div></div>
        </div>
      </div>

      <!-- Onboarding status report -->
      <div class="card" style="margin-bottom:24px;">
        <div class="card-header">
          <h3>📋 Onboarding Status Report</h3>
          <span style="font-size:.78rem;color:var(--gray-400);">✓ Approved &nbsp; ⏳ Pending &nbsp; ✗ Rejected &nbsp; ○ Missing</span>
        </div>
        <div class="card-body" style="padding:0;">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Employee</th>
                  <th>Type</th>
                  <th>Driver's Lic</th>
                  <th>I-9</th>
                  <th>Direct Dep.</th>
                  <th>Passport</th>
                  <th>Work Auth</th>
                  <th>H-1B</th>
                  <th>Progress</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($employees as $emp): ?>
                  <?php
                  $mandApproved = 0;
                  if ($emp['drivers_license'] === 'approved') $mandApproved++;
                  if ($emp['i9']              === 'approved') $mandApproved++;
                  if ($emp['direct_deposit']  === 'approved') $mandApproved++;
                  $empPct = round($mandApproved / 3 * 100);
                  ?>
                  <tr>
                    <td>
                      <div style="font-weight:600;"><?= e($emp['full_name']) ?></div>
                      <div style="font-size:.75rem;color:var(--gray-400);"><?= e($emp['email']) ?></div>
                    </td>
                    <td><span class="badge badge-info" style="font-size:.72rem;"><?= e($emp['employee_type'] ?? '') ?></span></td>
                    <td style="text-align:center;"><?= statusIcon($emp['drivers_license']) ?></td>
                    <td style="text-align:center;"><?= statusIcon($emp['i9']) ?></td>
                    <td style="text-align:center;"><?= statusIcon($emp['direct_deposit']) ?></td>
                    <td style="text-align:center;"><?= statusIcon($emp['passport']) ?></td>
                    <td style="text-align:center;"><?= statusIcon($emp['work_authorization']) ?></td>
                    <td style="text-align:center;"><?= statusIcon($emp['h1b_i797']) ?></td>
                    <td>
                      <div style="display:flex;align-items:center;gap:8px;">
                        <div class="progress-bar" style="flex:1;height:6px;">
                          <div class="progress-bar-fill" style="width:<?= $empPct ?>%"></div>
                        </div>
                        <span style="font-size:.75rem;color:var(--gray-400);width:32px;"><?= $empPct ?>%</span>
                      </div>
                    </td>
                    <td><a href="/admin/employees.php?id=<?= (int)$emp['id'] ?>" class="btn btn-outline btn-sm">View</a></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Expiry alerts -->
      <?php if ($expiring): ?>
      <div class="card" style="margin-bottom:24px;">
        <div class="card-header"><h3>⚠️ Document Expiry Alerts (Next 60 Days)</h3></div>
        <div class="card-body" style="padding:0;">
          <div class="table-wrap">
            <table>
              <thead><tr><th>Employee</th><th>Document</th><th>Expiry Date</th><th>Days Left</th><th></th></tr></thead>
              <tbody>
                <?php foreach ($expiring as $d): ?>
                  <tr>
                    <td style="font-weight:600;"><?= e($d['full_name']) ?></td>
                    <td><?= e($docLabels[$d['doc_type']] ?? $d['doc_type']) ?></td>
                    <td><?= e(date('M j, Y', strtotime($d['expiry_date']))) ?></td>
                    <td>
                      <span class="badge badge-<?= (int)$d['days_left'] <= 30 ? 'rejected' : 'pending' ?>">
                        <?= (int)$d['days_left'] ?> days
                      </span>
                    </td>
                    <td><a href="/admin/documents.php?doc_id=<?= (int)$d['id'] ?>" class="btn btn-outline btn-sm">View</a></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <?php endif; ?>

      <!-- Timesheet compliance -->
      <div class="card">
        <div class="card-header"><h3>📅 Timesheet Compliance (Last 4 Weeks)</h3></div>
        <div class="card-body" style="padding:0;">
          <div class="table-wrap">
            <table>
              <thead><tr><th>Employee</th><th>Submitted</th><th>Approved</th><th>Rate</th></tr></thead>
              <tbody>
                <?php foreach ($compliance as $c): ?>
                  <?php $cp = (int)$c['submitted'] > 0 ? round((int)$c['approved'] / (int)$c['submitted'] * 100) : 0; ?>
                  <tr>
                    <td style="font-weight:600;"><?= e($c['full_name']) ?></td>
                    <td><?= (int)$c['submitted'] ?>/4 weeks</td>
                    <td><?= (int)$c['approved'] ?></td>
                    <td>
                      <div style="display:flex;align-items:center;gap:8px;">
                        <div class="progress-bar" style="flex:1;height:6px;min-width:80px;">
                          <div class="progress-bar-fill" style="width:<?= $cp ?>%"></div>
                        </div>
                        <span style="font-size:.75rem;color:var(--gray-400);"><?= $cp ?>%</span>
                      </div>
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
<?php pageFooter(); ?>
</body>
</html>
