<?php
/**
 * Super Admin — Employee Offboarding
 * Sets employment_status = 'offboarded' — a permanent closure distinct from
 * simple deactivation. Only Super Admin can do this.
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
    $action  = validateEnum($_POST['action'] ?? '', ['offboard', 'reinstate']);
    $empId   = sanitizeInt($_POST['emp_id'] ?? 0, 1);
    $reason  = sanitizeString($_POST['reason'] ?? '', 1000);

    if (!$action || !$empId) {
        $msg = 'Invalid request.'; $msgType = 'error';
    } else {
        $chk = $db->prepare("SELECT id, full_name, employment_status FROM users WHERE id = ? AND role = 'employee' LIMIT 1");
        $chk->execute([$empId]);
        $emp = $chk->fetch();

        if (!$emp) {
            $msg = 'Employee not found.'; $msgType = 'error';
        } elseif ($action === 'offboard') {
            $db->prepare(
                "UPDATE users SET employment_status = 'offboarded', status = 'deactivated' WHERE id = ?"
            )->execute([$empId]);
            if ($reason) {
                $db->prepare(
                    "INSERT INTO hr_notes (employee_id, hr_user_id, note) VALUES (?, ?, ?)"
                )->execute([$empId, $user['id'], '[OFFBOARD] ' . $reason]);
            }
            auditLog('employee_offboarded', 'users', $empId, ['reason' => $reason]);
            $msg = e($emp['full_name']) . ' has been permanently offboarded.'; $msgType = 'success';
        } elseif ($action === 'reinstate') {
            $db->prepare(
                "UPDATE users SET employment_status = 'active', status = 'active' WHERE id = ?"
            )->execute([$empId]);
            auditLog('employee_reinstated', 'users', $empId);
            $msg = e($emp['full_name']) . ' has been reinstated.'; $msgType = 'success';
        }
    }
}

// Active employees
$active = $db->query(
    "SELECT id, full_name, email, employee_type, employment_status, status, start_date
     FROM users WHERE role = 'employee' AND employment_status != 'offboarded'
     ORDER BY full_name ASC LIMIT 300"
)->fetchAll();

// Offboarded
$offboarded = $db->query(
    "SELECT id, full_name, email, employee_type, status
     FROM users WHERE role = 'employee' AND employment_status = 'offboarded'
     ORDER BY full_name ASC LIMIT 300"
)->fetchAll();

pageHead('Employee Offboarding');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'sa_offboard'); ?>
  <div class="main-content">
    <?php renderTopbar('Employee Offboarding', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <div>
          <h1>👋 Employee Offboarding</h1>
          <p>Permanently offboard a worker. This is irreversible without Super Admin reinstating them.</p>
        </div>
        <span style="padding:5px 14px;border-radius:20px;font-size:.82rem;font-weight:700;background:rgba(168,85,247,.12);color:#7c3aed;">⬡ Super Admin Panel</span>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <div class="grid-2" style="gap:24px;">

        <!-- Active employees -->
        <div class="card">
          <div class="card-header">
            <h3>✅ Active Employees <span style="font-size:.82rem;font-weight:400;color:var(--gray-400);">(<?= count($active) ?>)</span></h3>
          </div>
          <div style="max-height:520px;overflow-y:auto;">
            <?php if (!$active): ?>
              <div style="padding:32px;text-align:center;color:var(--gray-400);">No active employees.</div>
            <?php endif; ?>
            <?php foreach ($active as $e): ?>
              <div style="padding:14px 20px;border-bottom:1px solid var(--gray-100);">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
                  <div style="flex:1;min-width:0;">
                    <div style="font-weight:600;font-size:.88rem;color:var(--navy);"><?= e($e['full_name']) ?></div>
                    <div style="font-size:.78rem;color:var(--gray-400);"><?= e($e['email']) ?> · <?= e($e['employee_type'] ?? '—') ?></div>
                  </div>
                  <form method="POST" style="display:flex;flex-direction:column;gap:4px;"
                        onsubmit="return confirm('Permanently offboard <?= e(addslashes($e['full_name'])) ?>? This will deactivate their account.')">
                    <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                    <input type="hidden" name="action"  value="offboard">
                    <input type="hidden" name="emp_id"  value="<?= (int)$e['id'] ?>">
                    <input type="text"   name="reason"  class="form-control"
                           placeholder="Reason (optional)" maxlength="1000"
                           style="font-size:.78rem;padding:5px 8px;width:160px;"
                           onclick="event.stopPropagation()">
                    <button type="submit" class="btn btn-danger btn-sm" style="width:100%;">Offboard</button>
                  </form>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        </div>

        <!-- Offboarded employees -->
        <div class="card">
          <div class="card-header">
            <h3>📦 Offboarded <span style="font-size:.82rem;font-weight:400;color:var(--gray-400);">(<?= count($offboarded) ?>)</span></h3>
          </div>
          <div style="max-height:520px;overflow-y:auto;">
            <?php if (!$offboarded): ?>
              <div style="padding:32px;text-align:center;color:var(--gray-400);">No offboarded employees.</div>
            <?php endif; ?>
            <?php foreach ($offboarded as $e): ?>
              <div style="padding:14px 20px;border-bottom:1px solid var(--gray-100);opacity:.8;">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
                  <div style="flex:1;min-width:0;">
                    <div style="font-weight:600;font-size:.88rem;color:var(--gray-600);"><?= e($e['full_name']) ?></div>
                    <div style="font-size:.78rem;color:var(--gray-400);"><?= e($e['email']) ?> · <?= e($e['employee_type'] ?? '—') ?></div>
                    <span class="badge badge-rejected" style="margin-top:4px;font-size:.7rem;">Offboarded</span>
                  </div>
                  <form method="POST"
                        onsubmit="return confirm('Reinstate <?= e(addslashes($e['full_name'])) ?> as active employee?')">
                    <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                    <input type="hidden" name="action" value="reinstate">
                    <input type="hidden" name="emp_id" value="<?= (int)$e['id'] ?>">
                    <button type="submit" class="btn btn-success btn-sm">Reinstate</button>
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
