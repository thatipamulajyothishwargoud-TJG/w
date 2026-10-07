<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

function normalizeProfile(array $profile, array $sessionUser): array {
    $defaults = [
        'id' => (int)($sessionUser['id'] ?? 0),
        'full_name' => $sessionUser['name'] ?? 'User',
        'email' => '',
        'phone' => '',
        'role' => $sessionUser['role'] ?? 'employee',
        'employee_type' => '',
        'status' => 'active',
        'employment_status' => '',
        'start_date' => null,
        'address' => '',
        'emergency_contact' => '',
        'ssn_last4' => '',
        'date_of_birth' => null,
        'created_at' => date('Y-m-d H:i:s'),
        'password_hash' => '',
    ];

    $profile = array_merge($defaults, $profile);
    foreach (['full_name', 'email', 'phone', 'role', 'employee_type', 'status', 'employment_status', 'address', 'emergency_contact', 'ssn_last4', 'password_hash'] as $field) {
        $profile[$field] = (string)($profile[$field] ?? $defaults[$field]);
    }

    return $profile;
}

sendSecurityHeaders();
$user = requireAnyRole();
$db   = getDB();
$userId = (int)$user['id'];

$profileStmt = $db->prepare(
    "SELECT id, full_name, email, phone, role, employee_type, status,
            employment_status, start_date, address, emergency_contact,
            ssn_last4, date_of_birth, created_at, password_hash
     FROM users WHERE id = ? LIMIT 1"
);
$profileStmt->execute([$userId]);
$profile = $profileStmt->fetch();
if (!$profile) {
    error_log('Profile load failed: no user row for session user_id=' . $userId);
    startSecureSession();
    session_unset();
    session_destroy();
    header('Location: ' . APP_URL . '/auth/login.php');
    exit;
}

$profile = normalizeProfile($profile, $user);
$emergencyContact = decodeEmergencyContact((string)($profile['emergency_contact'] ?? ''));

$msg = ''; $msgType = '';
$mustCompleteProfile = isset($_GET['complete']) && $_GET['complete'] === '1';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true);
    $action = validateEnum($_POST['action'] ?? '', ['update_profile', 'change_password']);

    if ($action === 'update_profile') {
        $phone          = sanitizeString($_POST['phone'] ?? '', 25);
        $address        = sanitizeString($_POST['address'] ?? '', 500);
        $emergencyName  = sanitizeString($_POST['emergency_contact_name'] ?? '', 120);
        $emergencyPhone = sanitizePhoneNumber($_POST['emergency_contact_phone'] ?? '', 25);
        $dateOfBirth    = sanitizeDate($_POST['date_of_birth'] ?? '');

        $dobTs = $dateOfBirth ? strtotime($dateOfBirth) : false;
        $dobInRange = $dobTs !== false && $dobTs <= time() && $dobTs >= strtotime('-100 years');

        if (!$dateOfBirth || $address === '' || $emergencyName === '' || $emergencyPhone === '') {
            $msg = 'Date of birth, address, and emergency contact are required.'; $msgType = 'error';
        } elseif (!$dobInRange) {
            $msg = 'Please enter a valid date of birth (not in the future, within the last 100 years).'; $msgType = 'error';
        } else {
            $emergency = encodeEmergencyContact($emergencyName, $emergencyPhone);
            $db->prepare(
                "UPDATE users SET phone = ?, address = ?, emergency_contact = ?, date_of_birth = ? WHERE id = ?"
            )->execute([$phone, $address, $emergency, $dateOfBirth, $userId]);

            auditLog('profile_updated', 'users', $userId);
            $msg = 'Profile updated successfully.'; $msgType = 'success';

            $profileStmt->execute([$userId]);
            $profile = $profileStmt->fetch();
            if (!$profile) {
                error_log('Profile reload failed after update for user_id=' . $userId);
                header('Location: ' . APP_URL . '/auth/login.php');
                exit;
            }
            $profile = normalizeProfile($profile, $user);
            $emergencyContact = decodeEmergencyContact((string)($profile['emergency_contact'] ?? ''));

            if ($mustCompleteProfile && !userProfileRequiresCompletion($userId)) {
                $dest = in_array($user['role'], ['hr_admin', 'super_admin'], true)
                    ? '/admin/dashboard.php'
                    : '/employee/dashboard.php';
                header('Location: ' . APP_URL . $dest . '?profile_completed=1');
                exit;
            }
        }
    }

    if ($action === 'change_password') {
        $curr  = $_POST['current_password'] ?? '';
        $new   = $_POST['new_password'] ?? '';
        $new2  = $_POST['confirm_password'] ?? '';

        if (!password_verify($curr, $profile['password_hash'])) {
            $msg = 'Current password is incorrect.'; $msgType = 'error';
        } elseif ($new !== $new2) {
            $msg = 'New passwords do not match.'; $msgType = 'error';
        } else {
            $pwErrors = validatePassword($new);
            if ($pwErrors) {
                $msg = implode(' ', $pwErrors); $msgType = 'error';
            } else {
                $hash = hashPassword($new);
                $db->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$hash, $userId]);
                auditLog('password_changed', 'users', $userId);
                $msg = 'Password updated successfully.'; $msgType = 'success';
            }
        }
    }
}

// ── Load user's documents ─────────────────────────────────────────────────────
$docStmt = $db->prepare(
    "SELECT id, doc_type, status, rejection_reason, uploaded_at, expiry_date, file_name
     FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC"
);
$docStmt->execute([$userId]);
$allDocs = $docStmt->fetchAll();

$DOC_LABELS = [
    'drivers_license'    => ["Driver's License / State ID", '🪪'],
    'i9'                 => ['Form I-9',                    '📋'],
    'passport'           => ['Passport',                    '📘'],
    'work_authorization' => ['Work Authorization / EAD',    '✅'],
    'h1b_i797'           => ['H-1B Approval (I-797)',       '📄'],
    'social_security'    => ['Social Security Card',        '🔐'],
    'education'          => ['Educational Certificates',    '🎓'],
    'direct_deposit'     => ['Direct Deposit / Voided Check','🏦'],
];

// Build stats
$docTotal    = count($allDocs);
$docApproved = count(array_filter($allDocs, fn($d) => $d['status'] === 'approved'));
$docPending  = count(array_filter($allDocs, fn($d) => $d['status'] === 'pending'));
$docRejected = count(array_filter($allDocs, fn($d) => in_array($d['status'], ['rejected','more_info_needed'])));

// Expiry warnings
$today    = time();
$expiring = []; // docs expiring within 60 days
foreach ($allDocs as $d) {
    if ($d['expiry_date'] && $d['status'] === 'approved') {
        $daysLeft = (int)(( strtotime($d['expiry_date']) - $today ) / 86400);
        if ($daysLeft <= 60) {
            $expiring[] = ['doc' => $d, 'days' => $daysLeft];
        }
    }
}

$roleLabels = ['employee' => 'Employee', 'hr_admin' => 'HR Admin', 'super_admin' => 'Super Admin'];
$roleLabel  = $roleLabels[$profile['role'] ?? 'employee'] ?? 'User';
$isEmployee = ($profile['role'] ?? '') === 'employee';

// Avatar initials (up to 2 chars)
$nameParts = explode(' ', trim($profile['full_name']));
$initials  = strtoupper(substr($nameParts[0], 0, 1) . (isset($nameParts[1]) ? substr($nameParts[1], 0, 1) : ''));

pageHead('My Profile');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'profile'); ?>
  <div class="main-content">
    <?php renderTopbar('My Profile', $user); ?>
    <div class="page-body">

      <?php if ($mustCompleteProfile): ?>
        <div class="alert alert-warn" style="margin-bottom:20px;">⚠️ Please complete your date of birth, address, and emergency contact before continuing.</div>
      <?php endif; ?>
      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <!-- ── Profile Hero ──────────────────────────────────────────────── -->
      <div class="profile-hero">
        <div class="profile-avatar"><?= e($initials) ?></div>
        <div class="profile-hero-info">
          <h1><?= e($profile['full_name']) ?></h1>
          <div class="profile-hero-meta">
            <span><?= e($profile['email']) ?></span>
            <?php if ($profile['phone']): ?>
              <span class="meta-sep">·</span>
              <span><?= e($profile['phone']) ?></span>
            <?php endif; ?>
          </div>
          <div class="profile-badges">
            <span class="badge badge-info"><?= e($roleLabel) ?></span>
            <?php if ($isEmployee && $profile['employee_type']): ?>
              <span class="badge badge-approved"><?= e($profile['employee_type']) ?></span>
            <?php endif; ?>
            <span class="badge badge-<?= $profile['status'] === 'active' ? 'approved' : 'rejected' ?>">
              <?= e(ucfirst(str_replace('_', ' ', $profile['status'] ?? 'active'))) ?>
            </span>
          </div>
        </div>
        <div class="profile-hero-stats">
          <?php if ($profile['start_date']): ?>
          <div class="hero-stat">
            <div class="hero-stat-val"><?= e(date('M Y', strtotime($profile['start_date']))) ?></div>
            <div class="hero-stat-label">Start Date</div>
          </div>
          <?php endif; ?>
          <div class="hero-stat">
            <div class="hero-stat-val"><?= $docApproved ?>/<?= $docTotal ?></div>
            <div class="hero-stat-label">Docs Approved</div>
          </div>
          <?php if ($docPending): ?>
          <div class="hero-stat hero-stat-warn">
            <div class="hero-stat-val"><?= $docPending ?></div>
            <div class="hero-stat-label">Pending Review</div>
          </div>
          <?php endif; ?>
          <?php if ($expiring): ?>
          <div class="hero-stat hero-stat-danger">
            <div class="hero-stat-val"><?= count($expiring) ?></div>
            <div class="hero-stat-label">Expiring Soon</div>
          </div>
          <?php endif; ?>
        </div>
      </div>

      <!-- ── Expiry Alerts ─────────────────────────────────────────────── -->
      <?php foreach ($expiring as $ex):
        $dLabel = $DOC_LABELS[$ex['doc']['doc_type']][0] ?? ucfirst(str_replace('_',' ',$ex['doc']['doc_type']));
        $dIcon  = $DOC_LABELS[$ex['doc']['doc_type']][1] ?? '📄';
        $isExpired = $ex['days'] < 0;
      ?>
      <div class="alert alert-<?= $isExpired ? 'error' : ($ex['days'] <= 14 ? 'error' : 'warn') ?>" style="margin-bottom:10px;">
        <?= $dIcon ?> <strong><?= $isExpired ? 'Expired' : 'Expiring in ' . $ex['days'] . ' day' . ($ex['days'] === 1 ? '' : 's') ?>:</strong>
        <?= e($dLabel) ?> — <?= e(date('M j, Y', strtotime($ex['doc']['expiry_date']))) ?>.
        <a href="/employee/documents.php" style="margin-left:6px;font-weight:700;color:inherit;text-decoration:underline;">Upload renewal →</a>
      </div>
      <?php endforeach; ?>

      <!-- ── Main 3-column grid ────────────────────────────────────────── -->
      <div class="profile-layout">

        <!-- Left col: personal info form -->
        <div class="profile-col-main">
          <div class="card">
            <div class="card-header">
              <h3>✏️ Personal Information</h3>
            </div>
            <div class="card-body">
              <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                <input type="hidden" name="action" value="update_profile">

                <div class="pf-readonly-row">
                  <span class="pf-readonly-label">Full Name</span>
                  <span class="pf-readonly-val"><?= e($profile['full_name']) ?> <span class="pf-hint">(contact HR to change)</span></span>
                </div>
                <div class="pf-readonly-row">
                  <span class="pf-readonly-label">Email</span>
                  <span class="pf-readonly-val"><?= e($profile['email']) ?></span>
                </div>

                <div class="form-group" style="margin-top:16px;">
                  <label>Phone Number</label>
                  <input type="tel" name="phone" class="form-control" maxlength="25"
                         value="<?= e($profile['phone'] ?? '') ?>" placeholder="+1 (555) 000-0000">
                </div>
                <div class="form-group">
                  <label>Date of Birth <span class="req">*</span></label>
                  <input type="date" name="date_of_birth" class="form-control" required
                         min="<?= e(date('Y-m-d', strtotime('-100 years'))) ?>" max="<?= e(date('Y-m-d')) ?>"
                         value="<?= e($profile['date_of_birth'] ?? '') ?>">
                </div>
                <div class="form-group">
                  <label>Home Address <span class="req">*</span></label>
                  <textarea name="address" class="form-control" rows="3" maxlength="500" required
                            placeholder="Street, City, State ZIP"><?= e($profile['address'] ?? '') ?></textarea>
                </div>
                <div class="grid-2" style="gap:14px;">
                  <div class="form-group">
                    <label>Emergency Contact Name <span class="req">*</span></label>
                    <input type="text" name="emergency_contact_name" class="form-control" maxlength="120" required
                           value="<?= e($emergencyContact['name'] ?? '') ?>" placeholder="Jane Doe">
                  </div>
                  <div class="form-group">
                    <label>Emergency Contact Phone <span class="req">*</span></label>
                    <input type="tel" name="emergency_contact_phone" class="form-control" maxlength="25" required
                           value="<?= e($emergencyContact['phone'] ?? '') ?>" placeholder="+1 (555) 123-4567">
                  </div>
                </div>
                <button type="submit" class="btn btn-primary" style="margin-top:4px;">Save Changes</button>
              </form>
            </div>
          </div>
        </div>

        <!-- Right col: account details + password -->
        <div class="profile-col-side">

          <!-- Account details -->
          <div class="card">
            <div class="card-header"><h3>🗂️ Account Details</h3></div>
            <div class="card-body" style="padding:0;">
              <table class="pf-detail-table">
                <tr>
                  <td>Status</td>
                  <td><span class="badge badge-<?= $profile['status'] === 'active' ? 'approved' : 'rejected' ?>"><?= e(ucfirst(str_replace('_',' ',$profile['status'] ?? 'active'))) ?></span></td>
                </tr>
                <tr><td>Role</td><td><?= e($roleLabel) ?></td></tr>
                <?php if ($isEmployee): ?>
                  <tr><td>Employment Type</td><td><?= e($profile['employee_type'] ?? '—') ?></td></tr>
                <?php endif; ?>
                <tr><td>Member Since</td><td><?= e(date('M j, Y', strtotime($profile['created_at']))) ?></td></tr>
                <?php if ($profile['date_of_birth']): ?>
                  <tr><td>Date of Birth</td><td><?= e(date('M j, Y', strtotime($profile['date_of_birth']))) ?></td></tr>
                <?php endif; ?>
                <?php if ($profile['start_date']): ?>
                  <tr><td>Start Date</td><td><?= e(date('M j, Y', strtotime($profile['start_date']))) ?></td></tr>
                <?php endif; ?>
                <?php if ($isEmployee): ?>
                  <tr><td>SSN (last 4)</td><td>••••<?= e($profile['ssn_last4'] ?? '—') ?></td></tr>
                <?php endif; ?>
              </table>
            </div>
          </div>

          <!-- Change password -->
          <div class="card" style="margin-top:20px;">
            <div class="card-header"><h3>🔒 Change Password</h3></div>
            <div class="card-body">
              <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                <input type="hidden" name="action" value="change_password">
                <div class="form-group">
                  <label>Current Password</label>
                  <input type="password" name="current_password" class="form-control" required maxlength="128" autocomplete="current-password">
                </div>
                <div class="form-group">
                  <label>New Password</label>
                  <input type="password" name="new_password" class="form-control" required maxlength="128" autocomplete="new-password">
                </div>
                <div class="form-group">
                  <label>Confirm New Password</label>
                  <input type="password" name="confirm_password" class="form-control" required maxlength="128" autocomplete="new-password">
                </div>
                <div class="pf-hint" style="margin-bottom:14px;">8+ characters, one uppercase, one number.</div>
                <button type="submit" class="btn btn-navy" style="width:100%;">Update Password</button>
              </form>
            </div>
          </div>

        </div><!-- /right col -->
      </div><!-- /profile-layout -->

      <!-- ── Documents Section ─────────────────────────────────────────── -->
      <div class="card" style="margin-top:24px;">
        <div class="card-header" style="justify-content:space-between;">
          <h3>📂 My Submitted Documents</h3>
          <a href="/employee/documents.php" class="btn btn-outline btn-sm">Manage Documents →</a>
        </div>

        <?php if (!$allDocs): ?>
          <div class="card-body" style="text-align:center;padding:40px 20px;color:var(--text-3);">
            <div style="font-size:2.2rem;margin-bottom:10px;">📭</div>
            <div>No documents submitted yet.</div>
            <a href="/employee/documents.php" class="btn btn-primary" style="margin-top:16px;display:inline-block;">Upload Documents</a>
          </div>
        <?php else: ?>

          <!-- Doc summary pills -->
          <div class="doc-summary-bar">
            <div class="doc-summary-pill">
              <span class="doc-pill-num"><?= $docTotal ?></span>
              <span class="doc-pill-label">Total</span>
            </div>
            <div class="doc-summary-pill doc-pill-green">
              <span class="doc-pill-num"><?= $docApproved ?></span>
              <span class="doc-pill-label">Approved</span>
            </div>
            <?php if ($docPending): ?>
            <div class="doc-summary-pill doc-pill-amber">
              <span class="doc-pill-num"><?= $docPending ?></span>
              <span class="doc-pill-label">Pending</span>
            </div>
            <?php endif; ?>
            <?php if ($docRejected): ?>
            <div class="doc-summary-pill doc-pill-red">
              <span class="doc-pill-num"><?= $docRejected ?></span>
              <span class="doc-pill-label">Needs Action</span>
            </div>
            <?php endif; ?>
          </div>

          <div class="table-wrap">
            <table class="pf-doc-table">
              <thead>
                <tr>
                  <th>Document</th>
                  <th>Status</th>
                  <th>Submitted</th>
                  <th>Expiry Date</th>
                  <th>Days Left</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($allDocs as $doc):
                  $dtype   = $doc['doc_type'];
                  $dLabel  = $DOC_LABELS[$dtype][0] ?? ucfirst(str_replace('_', ' ', $dtype));
                  $dIcon   = $DOC_LABELS[$dtype][1] ?? '📄';
                  $dStatus = $doc['status'];

                  $expiryTs   = $doc['expiry_date'] ? strtotime($doc['expiry_date']) : null;
                  $daysLeft   = $expiryTs ? (int)(($expiryTs - $today) / 86400) : null;
                  $isExpired  = $daysLeft !== null && $daysLeft < 0;
                  $isWarning  = $daysLeft !== null && $daysLeft >= 0 && $daysLeft <= 30;
                  $isCaution  = $daysLeft !== null && $daysLeft > 30 && $daysLeft <= 60;

                  $expiryClass = '';
                  if ($isExpired)      $expiryClass = 'expiry-danger';
                  elseif ($isWarning)  $expiryClass = 'expiry-warn';
                  elseif ($isCaution)  $expiryClass = 'expiry-caution';

                  $badgeMap = [
                    'approved'         => 'badge-approved',
                    'pending'          => 'badge-pending',
                    'rejected'         => 'badge-rejected',
                    'more_info_needed' => 'badge-pending',
                  ];
                  $badgeClass = $badgeMap[$dStatus] ?? 'badge-draft';
                  $statusLabel = match($dStatus) {
                    'more_info_needed' => 'More Info Needed',
                    default            => ucfirst($dStatus),
                  };
                ?>
                <tr class="<?= $expiryClass ?>-row">
                  <td>
                    <span class="doc-icon"><?= $dIcon ?></span>
                    <div class="doc-name-wrap">
                      <strong><?= e($dLabel) ?></strong>
                      <?php if ($doc['file_name']): ?>
                        <span class="pf-hint doc-filename"><?= e($doc['file_name']) ?></span>
                      <?php endif; ?>
                      <?php if ($dStatus === 'rejected' && $doc['rejection_reason']): ?>
                        <span class="doc-rejection-note">↳ <?= e($doc['rejection_reason']) ?></span>
                      <?php elseif ($dStatus === 'more_info_needed' && $doc['rejection_reason']): ?>
                        <span class="doc-rejection-note doc-info-note">↳ <?= e($doc['rejection_reason']) ?></span>
                      <?php endif; ?>
                    </div>
                  </td>
                  <td><span class="badge <?= $badgeClass ?>"><?= e($statusLabel) ?></span></td>
                  <td class="pf-hint"><?= e(date('M j, Y', strtotime($doc['uploaded_at']))) ?></td>
                  <td class="<?= $expiryClass ?>">
                    <?php if ($doc['expiry_date']): ?>
                      <?= e(date('M j, Y', strtotime($doc['expiry_date']))) ?>
                    <?php else: ?>
                      <span class="pf-hint">—</span>
                    <?php endif; ?>
                  </td>
                  <td>
                    <?php if ($daysLeft === null): ?>
                      <span class="pf-hint">—</span>
                    <?php elseif ($isExpired): ?>
                      <span class="expiry-chip expiry-chip-danger">Expired <?= abs($daysLeft) ?>d ago</span>
                    <?php elseif ($isWarning): ?>
                      <span class="expiry-chip expiry-chip-warn"><?= $daysLeft ?>d left</span>
                    <?php elseif ($isCaution): ?>
                      <span class="expiry-chip expiry-chip-caution"><?= $daysLeft ?>d left</span>
                    <?php else: ?>
                      <span class="expiry-chip expiry-chip-ok"><?= $daysLeft ?>d</span>
                    <?php endif; ?>
                  </td>
                </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php endif; ?>
      </div><!-- /documents card -->

      <!-- ── RECENT ACCOUNT ACTIVITY (Security) ─────────────────── -->
      <?php
        $secActivity = getUserSecuritySummary($userId, 8);
        $actIcons = [
            'login_success'       => ['🟢', 'Signed in'],
            'login_failed'        => ['🔴', 'Failed sign-in attempt'],
            'logout'              => ['⬛', 'Signed out'],
            'password_changed'    => ['🔑', 'Password changed'],
            'document_uploaded'   => ['📄', 'Document uploaded'],
            'document_downloaded' => ['⬇️', 'Document downloaded'],
            'timesheet_submitted' => ['⏱️', 'Timesheet submitted'],
            'rate_limit_login'    => ['⚠️', 'Rate limit hit on sign-in'],
        ];
      ?>
      <div class="card" style="margin-top:24px;">
        <div class="card-header" style="padding:14px 20px;border-bottom:1px solid var(--surface-3);display:flex;align-items:center;justify-content:space-between;">
          <span style="font-weight:700;font-size:.92rem;">🔒 Recent Account Activity</span>
          <span style="font-size:.75rem;color:var(--text-3);">Last 8 events · <a href="/employee/profile.php" style="color:var(--cyan);">Refresh</a></span>
        </div>
        <?php if (empty($secActivity)): ?>
          <div class="card-body" style="padding:20px;color:var(--text-3);font-size:.86rem;">No recent activity recorded.</div>
        <?php else: ?>
          <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:.83rem;">
              <thead>
                <tr style="background:var(--surface-2);">
                  <th style="padding:9px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.05em;"></th>
                  <th style="padding:9px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.05em;">Event</th>
                  <th style="padding:9px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.05em;">IP Address</th>
                  <th style="padding:9px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.05em;">When</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($secActivity as $evt): ?>
                  <?php
                    [$icon, $label] = $actIcons[$evt['action']] ?? ['•', ucfirst(str_replace('_', ' ', $evt['action']))];
                    $isAlert = in_array($evt['action'], ['login_failed','rate_limit_login'], true);
                    $diff = time() - strtotime($evt['created_at']);
                    if ($diff < 60)         $when = 'Just now';
                    elseif ($diff < 3600)   $when = round($diff/60) . ' min ago';
                    elseif ($diff < 86400)  $when = round($diff/3600) . ' hr ago';
                    else                    $when = date('M j', strtotime($evt['created_at']));
                  ?>
                  <tr style="border-bottom:1px solid var(--surface-3);<?= $isAlert ? 'background:rgba(239,68,68,.04);' : '' ?>">
                    <td style="padding:10px 8px 10px 16px;font-size:1rem;"><?= $icon ?></td>
                    <td style="padding:10px 16px;color:<?= $isAlert ? 'var(--rose)' : 'var(--text-1)' ?>;font-weight:<?= $isAlert ? '600' : '400' ?>;">
                      <?= e($label) ?>
                      <?php if ($isAlert): ?><span style="font-size:.72rem;font-weight:700;background:rgba(239,68,68,.12);color:#dc2626;border-radius:20px;padding:1px 8px;margin-left:6px;">Alert</span><?php endif; ?>
                    </td>
                    <td style="padding:10px 16px;color:var(--text-3);font-family:monospace;font-size:.8rem;"><?= e($evt['ip_address'] ?? '—') ?></td>
                    <td style="padding:10px 16px;color:var(--text-3);white-space:nowrap;"><?= e($when) ?></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
          <div style="padding:10px 16px;font-size:.75rem;color:var(--text-3);border-top:1px solid var(--surface-3);">
            🔒 If you see unfamiliar sign-ins, <a href="/auth/change_password.php" style="color:var(--cyan);font-weight:600;">change your password</a> and contact HR immediately.
          </div>
        <?php endif; ?>
      </div><!-- /security activity card -->

    </div><!-- /page-body -->
  </div>
</div>

<style>
/* ── Profile Hero ───────────────────────────────────────────────────────── */
.profile-hero {
  display: flex;
  align-items: center;
  gap: 24px;
  background: var(--surface-1);
  border: 1px solid var(--surface-3);
  border-radius: var(--radius-lg);
  padding: 28px 30px;
  margin-bottom: 20px;
  animation: fadeIn .4s ease both;
}
.profile-avatar {
  width: 76px;
  height: 76px;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--cyan-dim), #0e3a4a);
  color: var(--cyan-bright);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  font-size: 1.7rem;
  letter-spacing: -.5px;
  border: 2px solid var(--cyan-dim);
  flex-shrink: 0;
}
.profile-hero-info { flex: 1; min-width: 0; }
.profile-hero-info h1 {
  font-size: 1.35rem;
  font-weight: 800;
  color: var(--text-1);
  margin: 0 0 4px;
  font-family: var(--font-display);
}
.profile-hero-meta {
  font-size: .84rem;
  color: var(--text-3);
  margin-bottom: 10px;
}
.meta-sep { margin: 0 8px; opacity: .4; }
.profile-badges { display: flex; gap: 7px; flex-wrap: wrap; }
.profile-hero-stats {
  display: flex;
  gap: 28px;
  flex-shrink: 0;
}
.hero-stat { text-align: center; }
.hero-stat-val {
  font-size: 1.4rem;
  font-weight: 800;
  color: var(--text-1);
  line-height: 1;
  font-family: var(--font-display);
}
.hero-stat-label {
  font-size: .72rem;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: .05em;
  margin-top: 4px;
}
.hero-stat-warn .hero-stat-val { color: var(--amber); }
.hero-stat-danger .hero-stat-val { color: var(--rose); }

/* ── Layout ─────────────────────────────────────────────────────────────── */
.profile-layout {
  display: grid;
  grid-template-columns: 1fr 380px;
  gap: 24px;
  align-items: start;
}
.profile-col-main, .profile-col-side { display: flex; flex-direction: column; gap: 0; }

/* ── Readonly rows ──────────────────────────────────────────────────────── */
.pf-readonly-row {
  display: flex;
  align-items: baseline;
  gap: 12px;
  padding: 9px 0;
  border-bottom: 1px solid var(--surface-3);
  font-size: .87rem;
}
.pf-readonly-label {
  color: var(--text-3);
  min-width: 80px;
  flex-shrink: 0;
  font-size: .8rem;
  text-transform: uppercase;
  letter-spacing: .04em;
}
.pf-readonly-val { color: var(--text-1); }
.pf-hint { color: var(--text-3); font-size: .78rem; }
.req { color: var(--rose); }

/* ── Detail table ────────────────────────────────────────────────────────── */
.pf-detail-table { width: 100%; border-collapse: collapse; font-size: .87rem; }
.pf-detail-table td {
  padding: 11px 20px;
  border-bottom: 1px solid var(--surface-3);
  vertical-align: middle;
}
.pf-detail-table td:first-child { color: var(--text-3); width: 140px; }
.pf-detail-table tr:last-child td { border-bottom: none; }

/* ── Document summary bar ────────────────────────────────────────────────── */
.doc-summary-bar {
  display: flex;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--surface-3);
  flex-wrap: wrap;
}
.doc-summary-pill {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--surface-2);
  border: 1px solid var(--surface-3);
  border-radius: 10px;
  padding: 8px 16px;
}
.doc-pill-num {
  font-size: 1.15rem;
  font-weight: 800;
  color: var(--text-1);
  font-family: var(--font-display);
  line-height: 1;
}
.doc-pill-label { font-size: .74rem; color: var(--text-3); text-transform: uppercase; letter-spacing: .04em; }
.doc-pill-green .doc-pill-num { color: var(--green); }
.doc-pill-amber .doc-pill-num { color: var(--amber); }
.doc-pill-red   .doc-pill-num { color: var(--rose); }

/* ── Document table ──────────────────────────────────────────────────────── */
.pf-doc-table { width: 100%; border-collapse: collapse; font-size: .87rem; }
.pf-doc-table th {
  padding: 10px 16px;
  text-align: left;
  font-size: .74rem;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: var(--text-3);
  background: var(--surface-2);
  border-bottom: 1px solid var(--surface-3);
  font-weight: 700;
}
.pf-doc-table td {
  padding: 13px 16px;
  border-bottom: 1px solid var(--surface-3);
  vertical-align: middle;
}
.pf-doc-table tr:last-child td { border-bottom: none; }
.pf-doc-table tr:hover td { background: var(--surface-2); }
.pf-doc-table tr.expiry-danger-row td { background: rgba(239,68,68,.04); }
.pf-doc-table tr.expiry-warn-row td   { background: rgba(245,158,11,.04); }

.doc-icon { font-size: 1.3rem; margin-right: 10px; flex-shrink: 0; vertical-align: middle; }
.doc-name-wrap { display: inline-flex; flex-direction: column; gap: 2px; vertical-align: middle; }
.doc-filename { font-size: .74rem; color: var(--text-3); max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.doc-rejection-note { font-size: .74rem; color: var(--rose); }
.doc-info-note { color: var(--amber); }

/* ── Expiry colours ──────────────────────────────────────────────────────── */
.expiry-danger { color: var(--rose) !important; font-weight: 700; }
.expiry-warn   { color: var(--amber) !important; font-weight: 700; }
.expiry-caution{ color: #f0a040 !important; }

.expiry-chip {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 20px;
  font-size: .73rem;
  font-weight: 700;
  white-space: nowrap;
}
.expiry-chip-ok      { background: var(--green-dim); color: var(--green); border: 1px solid rgba(16,185,129,.2); }
.expiry-chip-caution { background: rgba(240,160,64,.12); color: #f0a040; border: 1px solid rgba(240,160,64,.25); }
.expiry-chip-warn    { background: var(--amber-dim); color: var(--amber); border: 1px solid rgba(245,158,11,.22); }
.expiry-chip-danger  { background: var(--rose-dim); color: var(--rose); border: 1px solid rgba(239,68,68,.22); }

/* ── Responsive ──────────────────────────────────────────────────────────── */
@media (max-width: 900px) {
  .profile-layout { grid-template-columns: 1fr; }
  .profile-hero { flex-wrap: wrap; }
  .profile-hero-stats { width: 100%; justify-content: space-around; padding-top: 16px; border-top: 1px solid var(--surface-3); }
}
@media (max-width: 600px) {
  .profile-hero { padding: 20px 16px; gap: 16px; }
  .profile-avatar { width: 58px; height: 58px; font-size: 1.3rem; }
  .doc-summary-bar { gap: 8px; }
  .pf-doc-table th:nth-child(3),
  .pf-doc-table td:nth-child(3) { display: none; }
}
</style>
</body>
</html>
