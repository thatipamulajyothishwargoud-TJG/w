<?php
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/layout.php';

sendSecurityHeaders();
$user = requireLogin();
$db   = getDB();

// Mark all this user's notifications as read — parameterized
$db->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ?")->execute([$user['id']]);

// Load notifications — this user only, no user input in query
$notifQ = $db->prepare(
    "SELECT id, type, title, message, link, is_read, created_at
     FROM notifications WHERE user_id = ?
     ORDER BY created_at DESC LIMIT 100"
);
$notifQ->execute([$user['id']]);
$notifs = $notifQ->fetchAll();

pageHead('Notifications');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'notifs'); ?>
  <div class="main-content">
    <?php renderTopbar('Notifications', $user); ?>
    <div class="page-body">
      <div class="page-header">
        <h1>🔔 Notifications</h1>
        <p><?= count($notifs) ?> notification(s) — all marked as read.</p>
      </div>

      <div class="card">
        <div class="card-body" style="padding:0;">
          <?php if (!$notifs): ?>
            <div style="text-align:center;padding:80px 24px;color:var(--gray-400);">
              <div style="font-size:3rem;margin-bottom:16px;">🎉</div>
              <p>You're all caught up! No notifications.</p>
            </div>
          <?php endif; ?>
          <?php foreach ($notifs as $n): ?>
            <div style="display:flex;align-items:flex-start;gap:16px;padding:18px 24px;border-bottom:1px solid var(--gray-100);">
              <div style="font-size:1.5rem;flex-shrink:0;margin-top:2px;">
                <?php
                $ntype = $n['type'];
                if (strpos($ntype, 'approved') !== false)        echo '✅';
                elseif (strpos($ntype, 'rejected') !== false)    echo '❌';
                elseif (strpos($ntype, 'complete') !== false)    echo '🎉';
                elseif (strpos($ntype, 'lock') !== false)        echo '🔒';
                elseif (strpos($ntype, 'submitted') !== false)   echo '📤';
                elseif (strpos($ntype, 'uploaded') !== false)    echo '📁';
                elseif (strpos($ntype, 'registered') !== false)  echo '👤';
                elseif (strpos($ntype, 'reminder') !== false)    echo '⏰';
                elseif (strpos($ntype, 'expiry') !== false)      echo '⚠️';
                else                                              echo '🔔';
                ?>
              </div>
              <div style="flex:1;min-width:0;">
                <div style="font-weight:700;color:var(--navy);margin-bottom:3px;"><?= e($n['title']) ?></div>
                <div style="font-size:.88rem;color:var(--gray-600);line-height:1.5;"><?= e($n['message']) ?></div>
                <div style="font-size:.75rem;color:var(--gray-400);margin-top:6px;">
                  <?= e(date('M j, Y g:i a', strtotime($n['created_at']))) ?>
                </div>
              </div>
              <?php
              // Validate link — only allow safe internal relative paths
              $link = $n['link'] ?? '';
              if ($link && preg_match('#^/[a-zA-Z0-9/_\-\.]+\.php(\?[a-zA-Z0-9=&_\-]+)$#', $link)):
              ?>
                <a href="<?= e($link) ?>" class="btn btn-outline btn-sm" style="flex-shrink:0;">View →</a>
              <?php endif; ?>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
    </div>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
