<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
startSecureSession();
if (!empty($_SESSION['user_id']) && ($_SESSION['role'] ?? '') === 'super_admin') {
    header('Location: ' . APP_URL . '/admin/dashboard.php');
    exit;
}
$user = requireRole('hr_admin');
$db = getDB();

$stats = [
    'team' => (int)$db->query("SELECT COUNT(*) FROM users WHERE role='employee' AND status='active'")->fetchColumn(),
    'leave' => (int)$db->query("SELECT COUNT(*) FROM leave_requests WHERE status='pending'")->fetchColumn(),
    'documents' => (int)$db->query("SELECT COUNT(*) FROM documents WHERE status='pending'")->fetchColumn(),
    'timesheets' => (int)$db->query("SELECT COUNT(*) FROM timesheets WHERE status='pending'")->fetchColumn(),
    'jobs' => (int)$db->query("SELECT COUNT(*) FROM job_openings WHERE status='active'")->fetchColumn(),
];

$requests = $db->query(
    "SELECT lr.id, lr.leave_type, lr.start_date, lr.end_date, lr.created_at, u.full_name
     FROM leave_requests lr
     JOIN users u ON u.id = lr.user_id
     WHERE lr.status='pending' AND u.role='employee'
     ORDER BY lr.created_at ASC LIMIT 6"
)->fetchAll();

if (tableExists('workspace_people')) {
    $people = $db->query(
        "SELECT u.id,u.full_name,u.email,u.created_at,p.department,p.job_title,p.avatar_color
         FROM users u LEFT JOIN workspace_people p ON p.user_id=u.id
         WHERE u.role='employee' AND u.status='active'
         ORDER BY u.created_at DESC LIMIT 6"
    )->fetchAll();
} else {
    $people = $db->query(
        "SELECT id,full_name,email,created_at,'People' department,'Team member' job_title,'#94b8d8' avatar_color
         FROM users WHERE role='employee' AND status='active'
         ORDER BY created_at DESC LIMIT 6"
    )->fetchAll();
}

pageHead('HR Manager Portal');
?>
<body>
<div class="app-shell">
  <?php renderSidebar($user, 'dashboard'); ?>
  <main class="main-content">
    <?php renderTopbar('HR Manager / Overview', $user); ?>
    <div class="page-body">
      <?php if (defined('APP_DEMO_MODE') && APP_DEMO_MODE): ?>
        <div class="demo-banner"><span>HR MANAGER WORKSPACE</span> People operations, approvals, and recruitment.</div>
      <?php endif; ?>
      <div class="overview-heading">
        <div><div class="eyebrow">PEOPLE OPERATIONS</div><h1>Welcome back, <?= e(explode(' ', $user['name'])[0]) ?>.</h1><p>Your team, requests, and hiring activity in one place.</p></div>
        <a class="btn btn-primary" href="/admin/create_account.php">＋ Add team member</a>
      </div>

      <div class="stats-grid hr-manager-stats">
        <a class="stat-card lift" href="/admin/people.php"><div class="stat-icon blue">👥</div><div><div class="stat-value"><?= $stats['team'] ?></div><div class="stat-label">Active employees</div></div></a>
        <a class="stat-card lift" href="/employee/leave.php"><div class="stat-icon amber">🌿</div><div><div class="stat-value"><?= $stats['leave'] ?></div><div class="stat-label">Leave requests</div></div></a>
        <a class="stat-card lift" href="/admin/documents.php"><div class="stat-icon rose">📄</div><div><div class="stat-value"><?= $stats['documents'] ?></div><div class="stat-label">Documents to review</div></div></a>
        <a class="stat-card lift" href="/admin/submitted_timesheets.php"><div class="stat-icon mint">⏱</div><div><div class="stat-value"><?= $stats['timesheets'] ?></div><div class="stat-label">Timesheets to review</div></div></a>
        <a class="stat-card lift" href="/admin/manage_jobs.php"><div class="stat-icon blue">↗</div><div><div class="stat-value"><?= $stats['jobs'] ?></div><div class="stat-label">Open positions</div></div></a>
      </div>

      <section class="card hr-manager-welcome">
        <div><span class="eyebrow">YOUR HR WORKSPACE</span><h2>Help people do their best work.</h2><p>Manage employee records, review requests, and keep hiring moving. Your HR tools are ready below.</p></div>
        <div class="hr-manager-actions">
          <a class="btn btn-primary" href="/admin/people.php">Open people directory ↗</a>
          <a class="btn btn-outline" href="/admin/reports.php">View HR reports</a>
        </div>
      </section>

      <div class="grid-2 hr-manager-panels">
        <section class="card">
          <div class="card-header"><h3>Leave requests to review</h3><a href="/employee/leave.php">Open leave ↗</a></div>
          <div class="card-body" style="padding:0">
            <?php if (!$requests): ?><div class="empty-state">You’re all caught up. New requests will appear here.</div><?php endif; ?>
            <?php foreach ($requests as $request): ?>
              <a class="hr-request-row" href="/employee/leave.php">
                <span class="hr-request-avatar"><?= e(strtoupper(substr($request['full_name'], 0, 1))) ?></span>
                <span class="hr-request-copy"><strong><?= e($request['full_name']) ?></strong><small><?= e(ucfirst($request['leave_type'])) ?> · <?= e(date('M j', strtotime($request['start_date']))) ?>–<?= e(date('M j', strtotime($request['end_date']))) ?></small></span>
                <span class="pill">Review</span>
              </a>
            <?php endforeach; ?>
          </div>
        </section>

        <section class="card">
          <div class="card-header"><h3>Recently added teammates</h3><a href="/admin/people.php">View people ↗</a></div>
          <div class="card-body" style="padding:0">
            <?php if (!$people): ?><div class="empty-state">No active employees yet.</div><?php endif; ?>
            <?php foreach ($people as $person): ?>
              <?php $avatarColor = preg_match('/^#[a-fA-F0-9]{6}$/', (string)($person['avatar_color'] ?? '')) ? $person['avatar_color'] : '#94b8d8'; ?>
              <a class="hr-request-row" href="/admin/people.php?person=<?= (int)$person['id'] ?>">
                <span class="hr-request-avatar" style="background:<?= e($avatarColor) ?>"><?= e(strtoupper(substr($person['full_name'], 0, 1))) ?></span>
                <span class="hr-request-copy"><strong><?= e($person['full_name']) ?></strong><small><?= e($person['job_title'] ?: 'Team member') ?> · <?= e($person['department'] ?: 'People') ?></small></span>
                <span aria-hidden="true">↗</span>
              </a>
            <?php endforeach; ?>
          </div>
        </section>
      </div>

      <section class="module-grid hr-manager-modules" aria-label="HR management tools">
        <a class="card module-card" href="/admin/employees.php"><span>👥</span><h3>Employee records</h3><p>Review profiles and keep team information current.</p></a>
        <a class="card module-card" href="/admin/documents.php"><span>📁</span><h3>Document review</h3><p>Check employee documents and onboarding items.</p></a>
        <a class="card module-card" href="/admin/submitted_timesheets.php"><span>⏱️</span><h3>Timesheet approvals</h3><p>Review submitted hours and follow up on exceptions.</p></a>
        <a class="card module-card" href="/admin/manage_jobs.php"><span>✨</span><h3>Recruitment</h3><p>Publish roles and track hiring activity.</p></a>
        <a class="card module-card" href="/admin/reports.php"><span>📊</span><h3>People reports</h3><p>Explore workforce and attendance insights.</p></a>
        <a class="card module-card" href="/employee/profile.php"><span>⚙️</span><h3>My HR profile</h3><p>Update your own profile and personal documents.</p></a>
      </section>
    </div>
  </main>
</div>
<?php pageFooter(); ?>
</body>
</html>
