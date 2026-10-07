<?php
/**
 * Super Admin — User Role Management
 * Promote / demote users between employee, hr_admin, super_admin.
 * Super Admin only.
 */
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/helpers.php';
require_once __DIR__ . '/../../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('super_admin');
$db   = getDB();

$ALLOWED_ROLES = ['employee', 'hr_admin', 'super_admin'];
$msg = ''; $msgType = '';

// ── POST: change role ─────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true); // rotate token after use

    $targetId  = sanitizeInt($_POST['target_id'] ?? 0, 1);
    $newRole   = validateEnum($_POST['new_role'] ?? '', $ALLOWED_ROLES);

    if (!$targetId || !$newRole) {
        $msg = 'Invalid request.'; $msgType = 'error';
    } elseif ((int)$targetId === (int)$user['id']) {
        $msg = 'You cannot change your own role.'; $msgType = 'error';
    } else {
        // Fetch current role
        $chk = $db->prepare("SELECT id, full_name, role FROM users WHERE id = ? LIMIT 1");
        $chk->execute([$targetId]);
        $target = $chk->fetch();

        if (!$target) {
            $msg = 'User not found.'; $msgType = 'error';
        } else {
            $oldRole = $target['role'];
            $db->prepare("UPDATE users SET role = ? WHERE id = ?")->execute([$newRole, $targetId]);
            auditLog('role_changed', 'users', $targetId, [
                'old_role' => $oldRole,
                'new_role' => $newRole,
                'target'   => $target['full_name'],
            ]);
            $msg = 'Role updated: ' . e($target['full_name']) . ' → ' . e($newRole) . '.';
            $msgType = 'success';
        }
    }
}

// ── User list ─────────────────────────────────────────────────────────────────
$search   = sanitizeString($_GET['search'] ?? '', 100);
$roleF    = validateEnum($_GET['role_filter'] ?? '', array_merge($ALLOWED_ROLES, [''])) ?? '';
$where    = ['1=1']; $params = [];

if ($search) {
    $where[]  = '(full_name LIKE ? OR email LIKE ?)';
    $params[] = '%' . $search . '%';
    $params[] = '%' . $search . '%';
}
if ($roleF) {
    $where[]  = 'role = ?';
    $params[] = $roleF;
}

$listQ = $db->prepare(
    "SELECT id, full_name, email, role, status, created_at
     FROM users WHERE " . implode(' AND ', $where) . "
     ORDER BY FIELD(role,'super_admin','hr_admin','employee'), full_name ASC
     LIMIT 300"
);
$listQ->execute($params);
$users = $listQ->fetchAll();

$roleColors = [
    'employee'    => ['bg' => 'rgba(43,143,212,.1)',  'color' => '#2b8fd4'],
    'hr_admin'    => ['bg' => 'rgba(26,184,154,.12)', 'color' => '#0d9c80'],
    'super_admin' => ['bg' => 'rgba(168,85,247,.15)', 'color' => '#7c3aed'],
];

pageHead('User Role Management');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'sa_users'); ?>
  <div class="main-content">
    <?php renderTopbar('User Role Management', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <div>
          <h1>🔑 User Roles</h1>
          <p>Promote or demote users between Employee, HR Admin, and Super Admin. <strong>Super Admin only.</strong></p>
        </div>
        <span style="padding:5px 14px;border-radius:20px;font-size:.82rem;font-weight:700;background:rgba(168,85,247,.12);color:#7c3aed;">⬡ Super Admin Panel</span>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <!-- Search / filter -->
      <div class="card" style="margin-bottom:24px;">
        <div class="card-body" style="padding:16px 20px;">
          <form method="GET" style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;">
            <div class="form-group" style="margin:0;flex:1;min-width:180px;">
              <label style="margin-bottom:5px;">Search</label>
              <input type="text" name="search" class="form-control" placeholder="Name or email…" value="<?= e($search) ?>" maxlength="100">
            </div>
            <div class="form-group" style="margin:0;">
              <label style="margin-bottom:5px;">Role Filter</label>
              <select name="role_filter" class="form-control">
                <option value="">All Roles</option>
                <option value="employee"    <?= $roleF === 'employee'    ? 'selected' : '' ?>>Employee</option>
                <option value="hr_admin"    <?= $roleF === 'hr_admin'    ? 'selected' : '' ?>>HR Admin</option>
                <option value="super_admin" <?= $roleF === 'super_admin' ? 'selected' : '' ?>>Super Admin</option>
              </select>
            </div>
            <button type="submit" class="btn btn-primary" style="margin-bottom:0;">Search</button>
          </form>
        </div>
      </div>

      <!-- User table -->
      <div class="card">
        <div class="card-header">
          <h3>👥 All Users <span style="font-size:.82rem;font-weight:400;color:var(--gray-400);">(<?= count($users) ?> found)</span></h3>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Current Role</th>
                <th>Status</th>
                <th>Joined</th>
                <th style="width:240px;">Change Role</th>
              </tr>
            </thead>
            <tbody>
              <?php if (!$users): ?>
                <tr><td colspan="6" style="text-align:center;color:var(--gray-400);padding:32px;">No users found.</td></tr>
              <?php endif; ?>
              <?php foreach ($users as $u): ?>
                <?php
                $chip = $roleColors[$u['role']] ?? ['bg'=>'var(--gray-100)','color'=>'var(--gray-600)'];
                $isSelf = ((int)$u['id'] === (int)$user['id']);
                ?>
                <tr>
                  <td>
                    <div style="display:flex;align-items:center;gap:10px;">
                      <div style="width:32px;height:32px;border-radius:50%;background:var(--navy);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.8rem;flex-shrink:0;">
                        <?= e(strtoupper(substr($u['full_name'],0,1))) ?>
                      </div>
                      <span style="font-weight:600;font-size:.88rem;"><?= e($u['full_name']) ?></span>
                      <?php if ($isSelf): ?>
                        <span style="font-size:.7rem;background:var(--gray-100);color:var(--gray-400);padding:1px 6px;border-radius:8px;">you</span>
                      <?php endif; ?>
                    </div>
                  </td>
                  <td style="font-size:.85rem;color:var(--gray-600);"><?= e($u['email']) ?></td>
                  <td>
                    <span style="padding:3px 10px;border-radius:20px;font-size:.75rem;font-weight:700;background:<?= $chip['bg'] ?>;color:<?= $chip['color'] ?>;">
                      <?= e(str_replace('_',' ', ucwords($u['role'],'_'))) ?>
                    </span>
                  </td>
                  <td>
                    <span class="badge badge-<?= $u['status'] === 'active' ? 'approved' : ($u['status'] === 'deactivated' ? 'rejected' : 'pending') ?>">
                      <?= e(ucfirst(str_replace('_',' ',$u['status']))) ?>
                    </span>
                  </td>
                  <td style="font-size:.82rem;color:var(--gray-400);"><?= e(date('M j, Y', strtotime($u['created_at']))) ?></td>
                  <td>
                    <?php if ($isSelf): ?>
                      <span style="font-size:.8rem;color:var(--gray-400);">Cannot edit own role</span>
                    <?php else: ?>
                      <form method="POST" style="display:flex;gap:6px;align-items:center;"
                            onsubmit="return confirm('Change role of <?= e(addslashes($u['full_name'])) ?> to ' + this.new_role.value + '?')">
                        <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                        <input type="hidden" name="target_id"  value="<?= (int)$u['id'] ?>">
                        <select name="new_role" class="form-control" style="font-size:.82rem;padding:6px 10px;">
                          <option value="employee"    <?= $u['role'] === 'employee'    ? 'selected' : '' ?>>Employee</option>
                          <option value="hr_admin"    <?= $u['role'] === 'hr_admin'    ? 'selected' : '' ?>>HR Admin</option>
                          <option value="super_admin" <?= $u['role'] === 'super_admin' ? 'selected' : '' ?>>Super Admin</option>
                        </select>
                        <button type="submit" class="btn btn-sm" style="background:rgba(168,85,247,.12);color:#7c3aed;border:1px solid rgba(168,85,247,.3);white-space:nowrap;">Set Role</button>
                      </form>
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
<?php pageFooter(); ?>
</body>
</html>
