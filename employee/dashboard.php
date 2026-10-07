<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/workspace.php';
require_once __DIR__ . '/../includes/dashboard-operations.php';

sendSecurityHeaders();
startSecureSession();
if (!empty($_SESSION['user_id']) && ($_SESSION['role'] ?? '') !== 'employee') {
    header('Location: ' . APP_URL . roleDashboardPath((string)$_SESSION['role']));
    exit;
}
$user   = requireRole('employee');
$userId = $user['id'];
$db     = getDB();

// Stats
$docsQ = $db->prepare("SELECT status, COUNT(*) as cnt FROM documents WHERE user_id=? GROUP BY status");
$docsQ->execute([$userId]);
$docStats = array_column($docsQ->fetchAll(), 'cnt', 'status');

$tsQ = $db->prepare("SELECT status, COUNT(*) as cnt FROM timesheets WHERE user_id=? GROUP BY status");
$tsQ->execute([$userId]);
$tsStats = array_column($tsQ->fetchAll(), 'cnt', 'status');

$notifQ = $db->prepare("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0");
$notifQ->execute([$userId]);
$unreadNotifs = (int)$notifQ->fetchColumn();

// Current week timesheet
$thisWeek = date('Y-m-d', strtotime('monday this week'));
$tsNow = $db->prepare("SELECT * FROM timesheets WHERE user_id=? AND week_start=? LIMIT 1");
$tsNow->execute([$userId, $thisWeek]);
$currentTs = $tsNow->fetch();

// Recent notifications
$notifStmt = $db->prepare("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 5");
$notifStmt->execute([$userId]);
$notifications = $notifStmt->fetchAll();

pageHead('Dashboard');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id'=>$userId,'name'=>$user['name'],'role'=>$user['role']], 'dashboard'); ?>
  <div class="main-content">
    <?php renderTopbar('Dashboard', $user); ?>
    <div class="page-body"><?php renderWorkspaceHero($user); renderDashboardOperations($db,$user); ?>
      <div class="page-header">
        <h1>👋 Welcome back, <?= e(explode(' ', $user['name'])[0]) ?>!</h1>
        <p><?= date('l, F j, Y') ?></p>
      </div>

      <!-- Quick stats -->
      <div class="stats-grid">
        <div class="stat-card lift">
          <div class="stat-icon blue">📁</div>
          <div data-stat="docs_approved">
            <div class="stat-value"><?= (int)($docStats['approved'] ?? 0) ?></div>
            <div class="stat-label">Docs Approved</div>
          </div>
        </div>
        <div class="stat-card lift">
          <div class="stat-icon amber">⏳</div>
          <div data-stat="docs_pending">
            <div class="stat-value"><?= (int)($docStats['pending'] ?? 0) ?></div>
            <div class="stat-label">Docs Pending</div>
          </div>
        </div>
        <div class="stat-card lift">
          <div class="stat-icon mint">✅</div>
          <div data-stat="ts_approved">
            <div class="stat-value"><?= (int)($tsStats['approved'] ?? 0) ?></div>
            <div class="stat-label">TS Approved</div>
          </div>
        </div>
        <div class="stat-card lift">
          <div class="stat-icon rose">🔔</div>
          <div data-stat="unread_notifs">
            <div class="stat-value"><?= $unreadNotifs ?></div>
            <div class="stat-label">Unread Alerts</div>
          </div>
        </div>
      </div>

      <div class="grid-2" style="gap:22px;">
        <!-- This week's timesheet -->
        <div class="card">
          <div class="card-header" data-ts-header>
            <h3>⏱️ This Week</h3>
            <?php if ($currentTs): ?>
              <span class="badge badge-<?= e($currentTs['status']) ?>"><?= e(ucfirst($currentTs['status'])) ?></span>
            <?php else: ?>
              <span class="badge badge-missing">Not Started</span>
            <?php endif; ?>
          </div>
          <div class="card-body">
            <?php if ($currentTs): ?>
              <div class="ts-total" style="margin:0 0 16px;">
                <div class="ts-total-num <?= $currentTs['is_overtime'] ? 'ts-overtime' : '' ?>">
                  <?= e(number_format((float)$currentTs['total_hours'],1)) ?>
                </div>
                <div class="ts-total-label">Hours logged · Week of <?= date('M j', strtotime($thisWeek)) ?></div>
              </div>
              <?php if ($currentTs['status'] === 'rejected'): ?>
                <div class="rejection-notice" style="margin-bottom:12px;">
                  <strong style="font-size:.8rem;color:var(--rose);">Rejected:</strong>
                  <div class="reason"><?= e(substr($currentTs['rejection_reason'],0,100)) ?></div>
                </div>
              <?php endif; ?>
            <?php else: ?>
              <div style="text-align:center;padding:16px 0;color:var(--text-3);font-size:.88rem;">
                No timesheet for this week yet.
              </div>
            <?php endif; ?>
            <a href="/employee/timesheets.php" class="btn btn-primary btn-block">
              <?= $currentTs ? '✏️ View / Edit Timesheet' : '+ Log This Week\'s Hours' ?>
            </a>
          </div>
        </div>

        <!-- Notifications -->
        <div class="card">
          <div class="card-header">
            <h3>🔔 Recent Notifications</h3>
            <?php if ($unreadNotifs): ?>
              <span class="badge badge-pending"><?= $unreadNotifs ?> new</span>
            <?php endif; ?>
          </div>
          <div class="card-body" style="padding:0;" data-queue="notifications">
            <?php if (!$notifications): ?>
              <div style="padding:32px;text-align:center;color:var(--text-3);">No notifications yet.</div>
            <?php endif; ?>
            <?php foreach ($notifications as $n): ?>
              <div style="padding:12px 20px;border-bottom:1px solid var(--surface-3);display:flex;gap:12px;align-items:flex-start;<?= !$n['is_read'] ? 'background:rgba(31,160,192,.04);' : '' ?>">
                <div style="flex:1;min-width:0;">
                  <div style="font-weight:<?= !$n['is_read'] ? '700' : '500' ?>;font-size:.88rem;color:var(--text-1);"><?= e($n['title']) ?></div>
                  <div style="font-size:.78rem;color:var(--text-3);margin-top:2px;"><?= e($n['message']) ?></div>
                  <div style="font-size:.72rem;color:var(--text-3);margin-top:4px;"><?= e(date('M j, g:i a', strtotime($n['created_at']))) ?></div>
                </div>
                <?php if (!$n['is_read']): ?><div style="width:7px;height:7px;border-radius:50%;background:var(--cyan);flex-shrink:0;margin-top:5px;"></div><?php endif; ?>
              </div>
            <?php endforeach; ?>
          </div>
        </div>
      </div>

      <!-- Quick actions -->
      <div style="margin-top:22px;display:flex;gap:12px;flex-wrap:wrap;">
        <a href="/employee/documents.php" class="btn btn-navy">📁 My Documents</a>
        <a href="/employee/timesheets.php" class="btn btn-navy">⏱️ My Timesheets</a>
        <a href="/employee/profile.php" class="btn btn-navy">👤 My Profile</a>
      </div>
    </div>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
