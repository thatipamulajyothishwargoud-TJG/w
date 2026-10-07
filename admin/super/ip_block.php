<?php
/**
 * Super Admin — IP Blocking
 * Add / remove IPs from blocked_ips. Timed or permanent blocks with reason.
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
    $action = validateEnum($_POST['action'] ?? '', ['block_ip', 'unblock_ip']);

    if ($action === 'block_ip') {
        $ip     = trim($_POST['ip_address'] ?? '');
        $reason = sanitizeString($_POST['reason'] ?? '', 255);
        $hours  = sanitizeInt($_POST['expires_hours'] ?? 0, 0, 8760); // 0 = permanent, max 1yr

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $msg = 'Invalid IP address.'; $msgType = 'error';
        } elseif ($ip === getClientIpSecure()) {
            // checkIpBlock() runs before role/session checks on every admin page,
            // including this one — blocking your own current IP locks every admin
            // out with no in-app recovery on hosting with no SSH/DB console handy.
            $msg = 'You cannot block your own current IP address (' . e($ip) . ') — this would lock you out with no way to undo it from here.';
            $msgType = 'error';
        } else {
            $expires = $hours > 0 ? date('Y-m-d H:i:s', time() + ($hours * 3600)) : null;
            try {
                $db->prepare(
                    "INSERT INTO blocked_ips (ip_address, reason, expires_at)
                     VALUES (?, ?, ?)
                     ON DUPLICATE KEY UPDATE reason = VALUES(reason), expires_at = VALUES(expires_at), blocked_at = NOW()"
                )->execute([$ip, $reason ?: null, $expires]);
                auditLog('ip_blocked', 'blocked_ips', null, ['ip' => $ip, 'reason' => $reason, 'expires' => $expires]);
                $msg = 'IP ' . e($ip) . ' blocked' . ($expires ? ' until ' . date('M j Y g:i a', strtotime($expires)) : ' permanently') . '.';
                $msgType = 'success';
            } catch (Exception $e) {
                $msg = 'Database error.'; $msgType = 'error';
            }
        }
    }

    if ($action === 'unblock_ip') {
        $blockId = sanitizeInt($_POST['block_id'] ?? 0, 1);
        if ($blockId) {
            // Get IP for audit log
            $ipRow = $db->prepare("SELECT ip_address FROM blocked_ips WHERE id = ? LIMIT 1");
            $ipRow->execute([$blockId]);
            $ipData = $ipRow->fetch();
            $db->prepare("DELETE FROM blocked_ips WHERE id = ?")->execute([$blockId]);
            auditLog('ip_unblocked', 'blocked_ips', $blockId, ['ip' => $ipData['ip_address'] ?? '']);
            $msg = 'IP unblocked successfully.'; $msgType = 'success';
        }
    }
}

// Fetch blocked IPs
$blockedIPs = $db->query(
    "SELECT id, ip_address, reason, blocked_at, expires_at,
            (expires_at IS NOT NULL AND expires_at < NOW()) AS is_expired
     FROM blocked_ips ORDER BY blocked_at DESC LIMIT 200"
)->fetchAll();

pageHead('IP Blocking');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'sa_ip'); ?>
  <div class="main-content">
    <?php renderTopbar('IP Blocking', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <div>
          <h1>🚫 IP Blocking</h1>
          <p>Manually block IP addresses from accessing the portal. Supports timed or permanent bans.</p>
        </div>
        <span style="padding:5px 14px;border-radius:20px;font-size:.82rem;font-weight:700;background:rgba(168,85,247,.12);color:#7c3aed;">⬡ Super Admin Panel</span>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <div class="grid-2" style="gap:24px;align-items:start;">

        <!-- Block form -->
        <div class="card">
          <div class="card-header"><h3>➕ Add IP Block</h3></div>
          <div class="card-body">
            <form method="POST">
              <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
              <input type="hidden" name="action"     value="block_ip">
              <div class="form-group">
                <label>IP Address <span style="color:var(--rose);">*</span></label>
                <input type="text" name="ip_address" class="form-control" required
                       placeholder="e.g. 203.0.113.45 or 2001:db8::1" maxlength="45">
              </div>
              <div class="form-group">
                <label>Reason</label>
                <input type="text" name="reason" class="form-control"
                       placeholder="e.g. Repeated brute-force attempts" maxlength="255">
              </div>
              <div class="form-group">
                <label>Duration (hours) — 0 = permanent</label>
                <input type="number" name="expires_hours" class="form-control" value="0" min="0" max="8760">
                <div style="font-size:.78rem;color:var(--gray-400);margin-top:4px;">Examples: 24 = 1 day, 168 = 1 week, 0 = never expires</div>
              </div>
              <button type="submit" class="btn btn-danger">Block IP</button>
            </form>
          </div>
        </div>

        <!-- Blocked IPs list -->
        <div class="card">
          <div class="card-header">
            <h3>🛡️ Blocked IPs <span style="font-size:.82rem;font-weight:400;color:var(--gray-400);">(<?= count($blockedIPs) ?>)</span></h3>
          </div>
          <div class="card-body" style="padding:0;max-height:480px;overflow-y:auto;">
            <?php if (!$blockedIPs): ?>
              <div style="padding:32px;text-align:center;color:var(--gray-400);">No IPs are currently blocked.</div>
            <?php endif; ?>
            <?php foreach ($blockedIPs as $b): ?>
              <?php $expired = (bool)$b['is_expired']; ?>
              <div style="padding:14px 20px;border-bottom:1px solid var(--gray-100);<?= $expired ? 'opacity:.5;' : '' ?>">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;">
                  <div style="flex:1;min-width:0;">
                    <div style="font-family:monospace;font-size:.9rem;font-weight:700;color:var(--navy);"><?= e($b['ip_address']) ?></div>
                    <?php if ($b['reason']): ?>
                      <div style="font-size:.8rem;color:var(--gray-600);margin-top:2px;"><?= e($b['reason']) ?></div>
                    <?php endif; ?>
                    <div style="font-size:.75rem;color:var(--gray-400);margin-top:4px;">
                      Blocked <?= e(date('M j Y g:i a', strtotime($b['blocked_at']))) ?>
                      <?php if ($b['expires_at']): ?>
                        · <?= $expired ? '<span style="color:var(--rose);">Expired</span>' : 'Expires ' . e(date('M j Y g:i a', strtotime($b['expires_at']))) ?>
                      <?php else: ?>
                        · <span style="color:var(--rose);font-weight:600;">Permanent</span>
                      <?php endif; ?>
                    </div>
                  </div>
                  <form method="POST" style="flex-shrink:0;"
                        onsubmit="return confirm('Unblock <?= e(addslashes($b['ip_address'])) ?>?')">
                    <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                    <input type="hidden" name="action"   value="unblock_ip">
                    <input type="hidden" name="block_id" value="<?= (int)$b['id'] ?>">
                    <button type="submit" class="btn btn-outline btn-sm">Unblock</button>
                  </form>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        </div>

      </div>
    </div>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
