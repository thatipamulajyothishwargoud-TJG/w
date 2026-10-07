<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

$ALLOWED_ACTIONS  = array('deactivate', 'reactivate', 'add_note', 'update_start_date', 'update_date_of_birth', 'update_employment_type', 'verify_email', 'resend_verify');
$ALLOWED_STATUSES = array('active', 'pending_verification', 'deactivated', 'locked', '');

$msg = ''; $msgType = '';

// ── POST actions ──────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true); // rotate token after use

    $action = validateEnum($_POST['action'] ?? '', $ALLOWED_ACTIONS);
    $empId  = sanitizeInt($_POST['emp_id'] ?? 0, 1);

    if (!$action || !$empId) {
        $msg = 'Invalid request.'; $msgType = 'error';
    } else {
        // Confirm target is actually an employee (not HR/admin) — IDOR prevention
        $checkEmp = $db->prepare(
            "SELECT id FROM users WHERE id = ? AND role = 'employee' LIMIT 1"
        );
        $checkEmp->execute([$empId]);
        if (!$checkEmp->fetch()) {
            $msg = 'Employee not found.'; $msgType = 'error';
        } else {

            if ($action === 'deactivate') {
                $endDate = sanitizeDate($_POST['end_date'] ?? '');
                if (!$endDate) {
                    $msg = 'An end date is required to deactivate an employee.'; $msgType = 'error';
                } else {
                    $db->prepare(
                        "UPDATE users SET status = 'deactivated', end_date = ? WHERE id = ? AND role = 'employee'"
                    )->execute([$endDate, $empId]);
                    auditLog('employee_deactivate', 'users', $empId, ['end_date' => $endDate]);
                    $msg = 'Employee account deactivated (end date: ' . e(date('M j, Y', strtotime($endDate))) . ').'; $msgType = 'success';
                }
            }

            if ($action === 'reactivate') {
                $db->prepare(
                    "UPDATE users SET status = 'active', end_date = NULL WHERE id = ? AND role = 'employee'"
                )->execute([$empId]);
                auditLog('employee_reactivate', 'users', $empId);
                $msg = 'Employee account reactivated.'; $msgType = 'success';
            }

            if ($action === 'add_note') {
                $note = sanitizeString($_POST['note'] ?? '', 2000);
                if ($note) {
                    $db->prepare(
                        "INSERT INTO hr_notes (employee_id, hr_user_id, note) VALUES (?, ?, ?)"
                    )->execute([$empId, $user['id'], $note]);
                    auditLog('hr_note_added', 'users', $empId);
                    $msg = 'Note added.'; $msgType = 'success';
                } else {
                    $msg = 'Note cannot be empty.'; $msgType = 'error';
                }
            }

            if ($action === 'update_start_date') {
                $startDate = sanitizeDate($_POST['start_date'] ?? '');
                if ($startDate) {
                    $db->prepare(
                        "UPDATE users SET start_date = ? WHERE id = ? AND role = 'employee'"
                    )->execute([$startDate, $empId]);
                    auditLog('start_date_updated', 'users', $empId, array('date' => $startDate));
                    $msg = 'Start date updated.'; $msgType = 'success';
                } else {
                    $msg = 'Invalid date format.'; $msgType = 'error';
                }
            }

            if ($action === 'update_date_of_birth') {
                $dateOfBirth = sanitizeDate($_POST['date_of_birth'] ?? '');
                if ($dateOfBirth) {
                    $db->prepare(
                        "UPDATE users SET date_of_birth = ? WHERE id = ? AND role = 'employee'"
                    )->execute([$dateOfBirth, $empId]);
                    auditLog('date_of_birth_updated', 'users', $empId, array('date_of_birth' => $dateOfBirth));
                    $msg = 'Date of birth updated.'; $msgType = 'success';
                } else {
                    $msg = 'Invalid date of birth.'; $msgType = 'error';
                }
            }

            if ($action === 'update_employment_type') {
                $empType = validateEnum($_POST['employment_type'] ?? '', ['W2', 'C2C', '1099']);
                if ($empType) {
                    $db->prepare(
                        "UPDATE users SET employee_type = ? WHERE id = ? AND role = 'employee'"
                    )->execute([$empType, $empId]);
                    auditLog('employment_type_updated', 'users', $empId, array('type' => $empType));
                    $msg = 'Employment type updated to ' . e($empType) . '.'; $msgType = 'success';
                } else {
                    $msg = 'Invalid employment type.'; $msgType = 'error';
                }
            }

            // ── Manual email verify (admin override) ─────────────────────────
            if ($action === 'verify_email') {
                $db->prepare(
                    "UPDATE users SET email_verified = 1, status = 'active',
                     verify_token = NULL, verify_token_expiry = NULL
                     WHERE id = ? AND role = 'employee'"
                )->execute([$empId]);
                auditLog('email_manually_verified', 'users', $empId, ['by' => $user['name']]);
                $msg = 'Email marked as verified. Employee can now sign in.'; $msgType = 'success';
            }

            // ── Resend verification email ─────────────────────────────────────
            if ($action === 'resend_verify') {
                $empRow = $db->prepare("SELECT full_name, email, email_verified FROM users WHERE id = ? LIMIT 1");
                $empRow->execute([$empId]);
                $empData = $empRow->fetch();
                if ($empData && !$empData['email_verified']) {
                    $token  = bin2hex(random_bytes(32));
                    $expiry = date('Y-m-d H:i:s', strtotime('+72 hours'));
                    $db->prepare(
                        "UPDATE users SET verify_token = ?, verify_token_expiry = ? WHERE id = ?"
                    )->execute([$token, $expiry, $empId]);
                    $appUrl   = rtrim(defined('APP_URL') ? APP_URL : '', '/');
                    $link     = $appUrl . '/auth/verify.php?token=' . urlencode($token);
                    $btnStyle = "background:#1fa0c0;color:#000;padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;";
                    $body = emailTemplate('Verify Your Email', "
                        <p>Hi <strong>" . htmlspecialchars($empData['full_name'], ENT_QUOTES, 'UTF-8') . "</strong>,</p>
                        <p>Your HR administrator has resent your email verification link for the CloudFen HR Portal.</p>
                        <p><a href='" . htmlspecialchars($link, ENT_QUOTES, 'UTF-8') . "' style='{$btnStyle}'>✅ Verify My Email →</a></p>
                        <p style='margin-top:12px;font-size:12px;color:#666;word-break:break-all;'>Or copy: " . htmlspecialchars($link, ENT_QUOTES, 'UTF-8') . "</p>
                        <p style='color:#888;font-size:13px;margin-top:16px;'>This link expires in <strong>72 hours</strong>.</p>
                    ");
                    $sent = sendMail($empData['email'], 'Verify Your Email - CloudFen HR Portal', $body);
                    auditLog('verification_resent_by_admin', 'users', $empId, ['by' => $user['name'], 'sent' => $sent]);
                    $msg = $sent
                        ? 'Verification email resent to ' . e($empData['email']) . '.'
                        : 'Failed to send email. Check server mail config. You can also use "Mark as Verified" to bypass email.';
                    $msgType = $sent ? 'success' : 'error';
                } else {
                    $msg = 'Account is already verified or not found.'; $msgType = 'error';
                }
            }
        }
    }
}

// ── Focus employee ────────────────────────────────────────────────────────────
$focusId   = sanitizeInt($_GET['id'] ?? 0, 1) ?? 0;
$focusEmp  = null;
$focusDocs = $focusNotes = $focusTS = [];

if ($focusId) {
    $s = $db->prepare(
        "SELECT id, full_name, email, phone, role, status, employee_type,
                employment_status, start_date, end_date, date_of_birth, address, emergency_contact,
                ssn_last4, email_verified, created_at
         FROM users WHERE id = ? AND role = 'employee' LIMIT 1"
    );
    $s->execute([$focusId]);
    $focusEmp = $s->fetch();

    if ($focusEmp) {
        $focusEmergencyContact = decodeEmergencyContact((string)($focusEmp['emergency_contact'] ?? ''));
        // Documents — only this employee's, latest per type
        $ds = $db->prepare(
            "SELECT doc_type, document_name, status, rejection_reason, uploaded_at, file_size, id
             FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC"
        );
        $ds->execute([$focusId]);
        $focusDocs = $ds->fetchAll();

        // HR notes — latest first
        $ns = $db->prepare(
            "SELECT n.note, n.created_at, u.full_name AS hr_name
             FROM hr_notes n
             JOIN users u ON u.id = n.hr_user_id
             WHERE n.employee_id = ?
             ORDER BY n.created_at DESC LIMIT 30"
        );
        $ns->execute([$focusId]);
        $focusNotes = $ns->fetchAll();

        // Recent timesheets
        $ts = $db->prepare(
            "SELECT week_start, total_hours, status, submitted_at, is_overtime
             FROM timesheets WHERE user_id = ?
             ORDER BY week_start DESC LIMIT 12"
        );
        $ts->execute([$focusId]);
        $focusTS = $ts->fetchAll();
    }
}

// ── Employee list ─────────────────────────────────────────────────────────────
$search  = sanitizeString($_GET['search']        ?? '', 100);
// Default to "Active" on first load (no status_filter in the URL at all);
// an explicit status_filter=(empty) means the admin chose "All Statuses".
$statusF = isset($_GET['status_filter'])
    ? (validateEnum($_GET['status_filter'], $ALLOWED_STATUSES) ?? '')
    : 'active';

$where  = ["u.role = 'employee'"];
$params = [];

if ($search) {
    $where[]  = '(u.full_name LIKE ? OR u.email LIKE ?)';
    $params[] = '%' . $search . '%';
    $params[] = '%' . $search . '%';
}
if ($statusF) {
    $where[]  = 'u.status = ?';
    $params[] = $statusF;
}

$listQ = $db->prepare(
    "SELECT id, full_name, email, status, employee_type, created_at
     FROM users u
     WHERE " . implode(' AND ', $where) . "
     ORDER BY created_at DESC LIMIT 200"
);
$listQ->execute($params);
$employees = $listQ->fetchAll();

$docLabels = array(
    'drivers_license'    => "Driver's License",
    'i9'                 => 'Form I-9',
    'passport'           => 'Passport',
    'work_authorization' => 'Work Auth',
    'h1b_i797'           => 'H-1B',
    'social_security'    => 'SSN Card',
    'education'          => 'Education',
    'direct_deposit'     => 'Direct Deposit',
    'other'              => 'Other Document',
);

pageHead('Employees');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'employees'); ?>
  <div class="main-content">
    <?php renderTopbar('Employee Management', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <div>
          <h1>👥 Employees</h1>
          <p>Manage accounts, view profiles, and track onboarding status.</p>
        </div>
        <a href="/admin/create_account.php" class="btn btn-primary">➕ Create Account</a>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <div style="display:grid;grid-template-columns:300px 1fr;gap:24px;align-items:start;">

        <!-- ── Employee List ─────────────────────────────────────────────── -->
        <div class="card">
          <div class="card-header"><h3>Directory</h3></div>
          <div class="card-body" style="padding:12px;">
            <form method="GET" style="display:flex;flex-direction:column;gap:8px;margin-bottom:12px;">
              <input type="text" name="search" class="form-control"
                     placeholder="🔍 Name or email..."
                     value="<?= e($search) ?>" maxlength="100">
              <select name="status_filter" class="form-control" onchange="this.form.submit()">
                <option value="">All Statuses</option>
                <option value="active"               <?= $statusF === 'active'               ? 'selected' : '' ?>>Active</option>
                <option value="pending_verification" <?= $statusF === 'pending_verification' ? 'selected' : '' ?>>Pending Verification</option>
                <option value="deactivated"          <?= $statusF === 'deactivated'          ? 'selected' : '' ?>>Deactivated</option>
                <option value="locked"               <?= $statusF === 'locked'               ? 'selected' : '' ?>>Locked</option>
              </select>
              <button type="submit" class="btn btn-primary btn-sm">Search</button>
            </form>
            <div style="font-size:.78rem;color:var(--gray-400);margin-bottom:8px;"><?= count($employees) ?> employee(s)</div>
          </div>
          <div style="max-height:560px;overflow-y:auto;">
            <?php if (!$employees): ?>
              <div style="padding:24px;text-align:center;color:var(--gray-400);font-size:.88rem;">No employees found.</div>
            <?php endif; ?>
            <?php foreach ($employees as $emp): ?>
              <?php
              if ($emp['status'] === 'active')           $statusColor = 'var(--mint)';
              elseif ($emp['status'] === 'deactivated')   $statusColor = 'var(--rose)';
              else                                        $statusColor = 'var(--amber)';
              ?>
              <a href="?id=<?= (int)$emp['id'] ?>&search=<?= urlencode($search) ?>&status_filter=<?= urlencode($statusF) ?>"
                 style="display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--gray-100);text-decoration:none;background:<?= $focusId === (int)$emp['id'] ? 'var(--cloud)' : 'transparent' ?>;">
                <div style="width:36px;height:36px;border-radius:50%;background:var(--navy);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem;flex-shrink:0;">
                  <?= e(strtoupper(substr($emp['full_name'], 0, 1))) ?>
                </div>
                <div style="flex:1;min-width:0;">
                  <div style="font-weight:600;font-size:.88rem;color:var(--navy);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><?= e($emp['full_name']) ?></div>
                  <div style="font-size:.75rem;color:var(--gray-400);">
                    <?= e($emp['employee_type'] ?? '') ?> &bull;
                    <span style="color:<?= $statusColor ?>;"><?= e(ucfirst(str_replace('_', ' ', $emp['status']))) ?></span>
                  </div>
                </div>
              </a>
            <?php endforeach; ?>
          </div>
        </div>

        <!-- ── Employee Detail ───────────────────────────────────────────── -->
        <?php if ($focusEmp): ?>
        <div style="display:flex;flex-direction:column;gap:20px;">

          <!-- Profile card -->
          <div class="card">
            <div class="card-header flex-between">
              <div style="display:flex;align-items:center;gap:14px;">
                <div style="width:52px;height:52px;border-radius:50%;background:var(--navy);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.2rem;">
                  <?= e(strtoupper(substr($focusEmp['full_name'], 0, 1))) ?>
                </div>
                <div>
                  <h3 style="margin:0;"><?= e($focusEmp['full_name']) ?></h3>
                  <div style="font-size:.82rem;color:var(--gray-400);"><?= e($focusEmp['email']) ?> &bull; <?= e($focusEmp['employee_type'] ?? '') ?></div>
                </div>
              </div>
              <!-- Deactivate / Reactivate -->
              <?php if ($focusEmp['status'] === 'deactivated'): ?>
                <form method="POST">
                  <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                  <input type="hidden" name="emp_id"    value="<?= (int)$focusEmp['id'] ?>">
                  <input type="hidden" name="action" value="reactivate">
                  <button type="submit" class="btn btn-success btn-sm">Reactivate Account</button>
                </form>
              <?php else: ?>
                <form method="POST" style="display:flex;gap:8px;align-items:center;"
                      onsubmit="return confirm('Deactivate this employee? They will no longer be able to log in.')">
                  <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                  <input type="hidden" name="emp_id"    value="<?= (int)$focusEmp['id'] ?>">
                  <input type="hidden" name="action" value="deactivate">
                  <input type="date" name="end_date" class="form-control" style="width:150px;"
                         required title="Last day of employment">
                  <button type="submit" class="btn btn-danger btn-sm">Deactivate</button>
                </form>
              <?php endif; ?>
            </div>
            <div class="card-body">
              <div class="grid-2">
                <table style="font-size:.88rem;">
                  <tr>
                    <td style="color:var(--gray-400);padding:5px 12px 5px 0;width:130px;">Status</td>
                    <td>
                      <span class="badge badge-<?= in_array($focusEmp['status'], ['active']) ? 'approved' : ($focusEmp['status'] === 'deactivated' ? 'rejected' : 'pending') ?>">
                        <?= e(ucfirst(str_replace('_', ' ', $focusEmp['status']))) ?>
                      </span>
                    </td>
                  </tr>
                  <tr><td style="color:var(--gray-400);padding:5px 12px 5px 0;">Employment</td><td><?= e($focusEmp['employment_status'] ?? '—') ?></td></tr>
                  <tr><td style="color:var(--gray-400);padding:5px 12px 5px 0;">Phone</td><td><?= e($focusEmp['phone'] ?? '—') ?></td></tr>
                  <tr><td style="color:var(--gray-400);padding:5px 12px 5px 0;">Start Date</td>
                      <td><?= $focusEmp['start_date'] ? e(date('M j, Y', strtotime($focusEmp['start_date']))) : '—' ?></td>
                  </tr>
                  <?php if ($focusEmp['status'] === 'deactivated'): ?>
                  <tr><td style="color:var(--gray-400);padding:5px 12px 5px 0;">End Date</td>
                      <td><?= $focusEmp['end_date'] ? e(date('M j, Y', strtotime($focusEmp['end_date']))) : '—' ?></td>
                  </tr>
                  <?php endif; ?>
                  <tr><td style="color:var(--gray-400);padding:5px 12px 5px 0;">Date of Birth</td>
                      <td><?= $focusEmp['date_of_birth'] ? e(date('M j, Y', strtotime($focusEmp['date_of_birth']))) : '—' ?></td>
                  </tr>
                  <tr><td style="color:var(--gray-400);padding:5px 12px 5px 0;">SSN Last 4</td><td>****<?= e($focusEmp['ssn_last4'] ?? '—') ?></td></tr>
                  <tr><td style="color:var(--gray-400);padding:5px 12px 5px 0;">Email Verified</td><td>
                    <?php if ($focusEmp['email_verified']): ?>
                      ✅ Yes
                    <?php else: ?>
                      ⚠️ No &nbsp;
                      <form method="POST" style="display:inline;">
                        <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                        <input type="hidden" name="action"     value="resend_verify">
                        <input type="hidden" name="emp_id"     value="<?= (int)$focusEmp['id'] ?>">
                        <button type="submit" style="font-size:.75rem;padding:3px 10px;border-radius:5px;background:var(--cyan);color:#000;border:none;cursor:pointer;font-weight:700;">📧 Resend Email</button>
                      </form>
                      <form method="POST" style="display:inline;margin-left:4px;">
                        <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                        <input type="hidden" name="action"     value="verify_email">
                        <input type="hidden" name="emp_id"     value="<?= (int)$focusEmp['id'] ?>">
                        <button type="submit" style="font-size:.75rem;padding:3px 10px;border-radius:5px;background:#22c55e;color:#000;border:none;cursor:pointer;font-weight:700;" onclick="return confirm('Mark this account as verified without email confirmation?')">✅ Mark Verified</button>
                      </form>
                    <?php endif; ?>
                  </td></tr>
                  <tr><td style="color:var(--gray-400);padding:5px 12px 5px 0;">Joined</td><td><?= e(date('M j, Y', strtotime($focusEmp['created_at']))) ?></td></tr>
                </table>
                <div>
                  <div style="font-weight:600;font-size:.82rem;color:var(--gray-600);margin-bottom:6px;">Address</div>
                  <div style="font-size:.88rem;"><?= nl2br(e($focusEmp['address'] ?? 'Not provided')) ?></div>
                  <?php if (($focusEmergencyContact['name'] ?? '') !== '' || ($focusEmergencyContact['phone'] ?? '') !== ''): ?>
                    <div style="font-weight:600;font-size:.82rem;color:var(--gray-600);margin:12px 0 4px;">Emergency Contact</div>
                    <div style="font-size:.88rem;"><?= e($focusEmergencyContact['name'] ?? '') ?></div>
                    <div style="font-size:.84rem;color:var(--gray-400);margin-top:2px;"><?= e($focusEmergencyContact['phone'] ?? '') ?></div>
                  <?php endif; ?>
                  <!-- Set start date -->
                  <form method="POST" style="margin-top:16px;">
                    <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                    <input type="hidden" name="action"     value="update_start_date">
                    <input type="hidden" name="emp_id"     value="<?= (int)$focusEmp['id'] ?>">
                    <div style="display:flex;gap:8px;align-items:center;">
                      <input type="date" name="start_date" class="form-control" style="flex:1;"
                             value="<?= e($focusEmp['start_date'] ?? '') ?>">
                      <button type="submit" class="btn btn-outline btn-sm">Set Start</button>
                    </div>
                  </form>
                  <form method="POST" style="margin-top:12px;">
                    <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                    <input type="hidden" name="action"     value="update_date_of_birth">
                    <input type="hidden" name="emp_id"     value="<?= (int)$focusEmp['id'] ?>">
                    <div style="display:flex;gap:8px;align-items:center;">
                      <input type="date" name="date_of_birth" class="form-control" style="flex:1;"
                             value="<?= e($focusEmp['date_of_birth'] ?? '') ?>">
                      <button type="submit" class="btn btn-outline btn-sm">Set DOB</button>
                    </div>
                  </form>
                  <!-- Edit Employment Type (HR Admin + Super Admin) -->
                  <form method="POST" style="margin-top:12px;">
                    <input type="hidden" name="csrf_token"       value="<?= generateCsrfToken() ?>">
                    <input type="hidden" name="action"           value="update_employment_type">
                    <input type="hidden" name="emp_id"           value="<?= (int)$focusEmp['id'] ?>">
                    <label style="font-size:.8rem;font-weight:700;color:var(--gray-600);display:block;margin-bottom:5px;text-transform:uppercase;letter-spacing:.04em;">Employment Type</label>
                    <div style="display:flex;gap:8px;align-items:center;">
                      <select name="employment_type" class="form-control" style="flex:1;">
                        <option value="W2"  <?= ($focusEmp['employee_type'] ?? '') === 'W2'  ? 'selected' : '' ?>>W2</option>
                        <option value="C2C" <?= ($focusEmp['employee_type'] ?? '') === 'C2C' ? 'selected' : '' ?>>C2C</option>
                        <option value="1099"<?= ($focusEmp['employee_type'] ?? '') === '1099' ? 'selected' : '' ?>>1099</option>
                      </select>
                      <button type="submit" class="btn btn-primary btn-sm">Update</button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          </div>

          <!-- Documents -->
          <div class="card">
            <div class="card-header">
              <h3>Documents</h3>
              <a href="/admin/documents.php?status=all&emp_id=<?= (int)$focusEmp['id'] ?>" class="btn btn-outline btn-sm">Review →</a>
            </div>
            <div class="card-body" style="padding:0 24px;">
              <?php if (!$focusDocs): ?>
                <div style="padding:20px 0;color:var(--gray-400);font-size:.88rem;">No documents uploaded yet.</div>
              <?php endif; ?>
              <?php foreach ($focusDocs as $d): ?>
                <div class="doc-item">
                  <div class="doc-item-info">
                    <div class="doc-item-name"><?= e($d['doc_type'] === 'other' && !empty($d['document_name']) ? $d['document_name'] : ($docLabels[$d['doc_type']] ?? $d['doc_type'])) ?></div>
                    <div class="doc-item-meta"><?= e(date('M j, Y', strtotime($d['uploaded_at']))) ?> &bull; <?= e((string)round($d['file_size'] / 1024)) ?>KB</div>
                  </div>
                  <span class="badge badge-<?= $d['status'] === 'more_info_needed' ? 'info' : e($d['status']) ?>">
                    <?= e(ucfirst(str_replace('_', ' ', $d['status']))) ?>
                  </span>
                  <a href="/admin/documents.php?doc_id=<?= (int)$d['id'] ?>" class="btn btn-outline btn-sm">View</a>
                </div>
              <?php endforeach; ?>
            </div>
          </div>

          <!-- Timesheets -->
          <div class="card">
            <div class="card-header"><h3>Recent Timesheets</h3></div>
            <div class="card-body" style="padding:0;">
              <div class="table-wrap">
                <table>
                  <thead><tr><th>Week</th><th>Hours</th><th>Status</th><th>Submitted</th></tr></thead>
                  <tbody>
                    <?php if (!$focusTS): ?>
                      <tr><td colspan="4" style="text-align:center;color:var(--gray-400);padding:24px;">No timesheets.</td></tr>
                    <?php endif; ?>
                    <?php foreach ($focusTS as $t): ?>
                      <tr>
                        <td><?= e(date('M j, Y', strtotime($t['week_start']))) ?></td>
                        <td>
                          <?= e(number_format((float)$t['total_hours'], 1)) ?>
                          <?php if ($t['is_overtime']): ?>
                            <span class="badge badge-pending" style="font-size:.68rem;">OT</span>
                          <?php endif; ?>
                        </td>
                        <td><span class="badge badge-<?= e($t['status']) ?>"><?= e(ucfirst($t['status'])) ?></span></td>
                        <td><?= $t['submitted_at'] ? e(date('M j', strtotime($t['submitted_at']))) : '—' ?></td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <!-- HR Notes -->
          <div class="card">
            <div class="card-header">
              <h3>🔒 Internal HR Notes</h3>
              <span style="font-size:.75rem;font-weight:400;color:var(--gray-400);">Not visible to employee</span>
            </div>
            <div class="card-body">
              <?php foreach ($focusNotes as $n): ?>
                <div style="background:var(--gray-50);border-radius:8px;padding:12px 16px;margin-bottom:10px;">
                  <div style="font-size:.8rem;color:var(--sky);font-weight:600;margin-bottom:4px;">
                    <?= e($n['hr_name']) ?> &bull; <?= e(date('M j, Y g:i a', strtotime($n['created_at']))) ?>
                  </div>
                  <div style="font-size:.88rem;"><?= nl2br(e($n['note'])) ?></div>
                </div>
              <?php endforeach; ?>
              <form method="POST" style="margin-top:12px;">
                <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                <input type="hidden" name="action"     value="add_note">
                <input type="hidden" name="emp_id"     value="<?= (int)$focusEmp['id'] ?>">
                <div class="form-group" style="margin-bottom:8px;">
                  <textarea name="note" class="form-control" rows="2"
                            placeholder="Add an internal note..." maxlength="2000"></textarea>
                </div>
                <button type="submit" class="btn btn-navy btn-sm">Add Note</button>
              </form>
            </div>
          </div>

        </div>
        <?php else: ?>
          <div class="card">
            <div class="card-body" style="text-align:center;padding:80px 24px;color:var(--gray-400);">
              <div style="font-size:3rem;margin-bottom:12px;">👈</div>
              <p>Select an employee from the list to view their full profile.</p>
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
