<?php
/**
 * CloudFen HR Portal — Create Employee Account
 * Only HR Admin and Super Admin can access this page.
 * Creates a new user account and sends a welcome/invite email.
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

$msg = ''; $msgType = ''; $created = null;

// ── POST: Create account ───────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true); // rotate token after use

    $fullName   = sanitizeString($_POST['full_name']   ?? '', 120);
    $email      = sanitizeEmail($_POST['email']        ?? '');
    $countryCode = sanitizeString($_POST['country_code'] ?? '+1', 6);
    $phoneRaw   = sanitizeString($_POST['phone']       ?? '', 20);
    $phone      = $phoneRaw ? $countryCode . ' ' . $phoneRaw : '';
    $role       = validateEnum($_POST['role']          ?? '', ['employee', 'hr_admin', 'super_admin']);
    $empType    = validateEnum($_POST['employee_type'] ?? '', ['W2', 'C2C', '1099', '']);
    $startDate  = sanitizeDate($_POST['start_date']   ?? '');
    $dateOfBirth = sanitizeDate($_POST['date_of_birth'] ?? '');
    $address    = sanitizeString($_POST['address'] ?? '', 500);
    $emergencyContactName = sanitizeString($_POST['emergency_contact_name'] ?? '', 120);
    $emergencyContactPhone = sanitizePhoneNumber($_POST['emergency_contact_phone'] ?? '', 25);
    $sendWelcome = !empty($_POST['send_welcome']);

    // Super admin only can create other admins
    if (in_array($role, ['hr_admin', 'super_admin'], true) && $user['role'] !== 'super_admin') {
        $msg = 'Only an Administrator can create HR Manager or Administrator accounts.';
        $msgType = 'error';
    } elseif (!$fullName || !$email || !$role || !$dateOfBirth || !$address || !$emergencyContactName || !$emergencyContactPhone) {
        $msg = 'Full name, email, role, date of birth, address, and emergency contact are required.';
        $msgType = 'error';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $msg = 'Invalid email address.';
        $msgType = 'error';
    } else {
        // Check email uniqueness
        $chk = $db->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
        $chk->execute([$email]);
        if ($chk->fetch()) {
            $msg = 'An account with that email already exists.';
            $msgType = 'error';
        } else {
            // Check full name uniqueness (case-insensitive)
            $chkName = $db->prepare("SELECT id FROM users WHERE LOWER(full_name) = LOWER(?) LIMIT 1");
            $chkName->execute([$fullName]);
            if ($chkName->fetch()) {
                $msg = 'An account with that full name already exists. Please verify this is not a duplicate.';
                $msgType = 'error';
            } else {
            $emergencyContact = encodeEmergencyContact($emergencyContactName, $emergencyContactPhone);
            // Generate a secure temporary password
            $tempPassword = bin2hex(random_bytes(8)); // 16-char hex
            $hash = password_hash($tempPassword, PASSWORD_BCRYPT, ['cost' => 12]);

            // Generate email verification token
            $verifyToken  = bin2hex(random_bytes(32));
            $tokenExpiry  = date('Y-m-d H:i:s', strtotime('+72 hours'));

            $db->prepare(
                "INSERT INTO users (full_name, email, phone, password_hash, role, employee_type,
                                    status, email_verified, verify_token, verify_token_expiry, start_date, date_of_birth, address, emergency_contact,
                                    force_password_change)
                 VALUES (?, ?, ?, ?, ?, ?, 'pending_verification', 0, ?, ?, ?, ?, ?, ?, 1)"
            )->execute([
                $fullName, $email, $phone ?: null, $hash, $role,
                $empType ?: null, $verifyToken, $tokenExpiry, $startDate ?: null, $dateOfBirth, $address, $emergencyContact,
            ]);

            $newId = (int)$db->lastInsertId();
            auditLog('account_created', 'users', $newId, [
                'created_by' => $user['name'],
                'role'       => $role,
                'email'      => $email,
            ]);

            // Send welcome email with verification link + temp password
            if ($sendWelcome) {
                $appUrl  = rtrim(defined('APP_URL') ? APP_URL : '', '/');
                $appName = defined('APP_NAME') ? APP_NAME : 'CloudFen HR Portal';
                $roleLabelMap = ['super_admin' => 'Administrator', 'hr_admin' => 'HR Manager'];
                $roleLabel    = $roleLabelMap[$role] ?? 'Employee';
                $verifyLink   = $appUrl . '/auth/verify.php?token=' . urlencode($verifyToken);
                $btnStyle     = "background:#1fa0c0;color:#000;padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:8px;";
                $loginRoute = match ($role) {
                    'hr_admin' => '/auth/hr-login.php',
                    'super_admin' => '/auth/administrator-login.php',
                    default => '/auth/employee-login.php',
                };
                $loginUrl = $appUrl . $loginRoute;
                $body = emailTemplate('Welcome to ' . $appName, "
                    <p>Hi <strong>" . htmlspecialchars($fullName, ENT_QUOTES, 'UTF-8') . "</strong>,</p>
                    <p>Your <strong>" . htmlspecialchars($roleLabel, ENT_QUOTES, 'UTF-8') . "</strong> account on the <strong>" . htmlspecialchars($appName, ENT_QUOTES, 'UTF-8') . "</strong> has been created and is ready to use.</p>

                    <p><strong>Your login credentials:</strong></p>
                    <table style=\"background:#1a1a1a;border-radius:10px;padding:18px 24px;width:100%;margin:16px 0;\">
                      <tr><td style=\"color:#888;font-size:.82rem;padding-bottom:4px;\">Login URL</td></tr>
                      <tr><td style=\"padding-bottom:14px;\"><a href='" . htmlspecialchars($loginUrl, ENT_QUOTES, 'UTF-8') . "' style=\"color:#20a0c0;font-weight:700;\">" . htmlspecialchars($loginUrl, ENT_QUOTES, 'UTF-8') . "</a></td></tr>
                      <tr><td style=\"color:#888;font-size:.82rem;padding-bottom:4px;\">Email</td></tr>
                      <tr><td style=\"color:#f0f0f0;font-size:1rem;font-weight:700;padding-bottom:14px;\">" . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . "</td></tr>
                      <tr><td style=\"color:#888;font-size:.82rem;padding-bottom:4px;\">Temporary Password</td></tr>
                      <tr><td style=\"color:#20a0c0;font-size:1.15rem;font-weight:700;letter-spacing:2px;\">" . htmlspecialchars($tempPassword, ENT_QUOTES, 'UTF-8') . "</td></tr>
                    </table>

                    <p><a href='" . htmlspecialchars($loginUrl, ENT_QUOTES, 'UTF-8') . "' style='{$btnStyle}'>🔑 Sign In Now →</a></p>

                    <p style=\"color:#e09020;margin-top:20px;\">⚠️ <strong>You will be asked to set a new password immediately after signing in.</strong><br>Your email will be verified automatically on first login — no separate step required.</p>
                    <p style=\"color:#888;font-size:13px;margin-top:16px;\">If you did not expect this account, please contact <a href='mailto:hr@cloudfen.com' style=\"color:#20a0c0;\">hr@cloudfen.com</a>.</p>
                ");
                $mailSent = sendMail($email, "Your CloudFen HR Portal Account & Temporary Password", $body);
                if (!$mailSent) {
                    error_log("CloudFen: welcome email failed to send to: {$email}");
                }
            }

            $created = [
                'name'     => $fullName,
                'email'    => $email,
                'password' => $tempPassword,
                'role'     => $role,
                'id'       => $newId,
            ];
            $emailNote = $sendWelcome
                ? (isset($mailSent) && $mailSent ? ' and welcome email sent.' : ' — welcome email FAILED (check server mail config). Share credentials below manually.')
                : '.';
            $msg = 'Account created successfully' . $emailNote . ' Save the temporary password below — it will not be shown again.';
            $msgType = 'success';
        }
        } // end name uniqueness check
    }
}

pageHead('Create Account');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'create_account'); ?>
  <div class="main-content">
    <?php renderTopbar('Create Account', $user); ?>
    <div class="page-body">

      <div class="page-header">
        <div>
          <h1>➕ Create Account</h1>
          <p>Create a new portal account and optionally send a welcome email with login credentials.</p>
        </div>
        <a href="/admin/employees.php" class="btn btn-outline">← Back to Employees</a>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <?php if ($created): ?>
        <!-- Credential reveal card -->
        <div class="card" style="border:2px solid rgba(32,160,192,.4);margin-bottom:24px;">
          <div class="card-header" style="background:rgba(32,160,192,.08);">
            <h3 style="color:var(--cyan);">🔑 Account Credentials — Save Now</h3>
          </div>
          <div class="card-body" style="padding:24px;">
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;">
              <div>
                <div style="font-size:.75rem;color:var(--gray-400);margin-bottom:4px;">Name</div>
                <div style="font-weight:700;"><?= e($created['name']) ?></div>
              </div>
              <div>
                <div style="font-size:.75rem;color:var(--gray-400);margin-bottom:4px;">Email</div>
                <div style="font-weight:700;"><?= e($created['email']) ?></div>
              </div>
              <div>
                <div style="font-size:.75rem;color:var(--gray-400);margin-bottom:4px;">Role</div>
                <div style="font-weight:700;"><?= e(str_replace('_',' ', ucwords($created['role'], '_'))) ?></div>
              </div>
              <div>
                <div style="font-size:.75rem;color:var(--gray-400);margin-bottom:4px;">Temporary Password</div>
                <div style="font-family:monospace;font-size:1.1rem;font-weight:700;color:var(--cyan);letter-spacing:1px;display:flex;align-items:center;gap:10px;">
                  <?= e($created['password']) ?>
                  <button onclick="navigator.clipboard.writeText('<?= e($created['password']) ?>');this.textContent='✓ Copied!';setTimeout(()=>this.textContent='Copy',2000);"
                          class="btn btn-sm" style="font-size:.75rem;padding:3px 10px;">Copy</button>
                </div>
              </div>
            </div>
            <div style="margin-top:20px;display:flex;gap:10px;flex-wrap:wrap;">
              <a href="/admin/employees.php?id=<?= $created['id'] ?>" class="btn btn-primary">View Employee Profile</a>
              <a href="/admin/create_account.php" class="btn btn-outline">Create Another Account</a>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <!-- Create Account Form -->
      <div class="card">
        <div class="card-header"><h3>New Account Details</h3></div>
        <div class="card-body" style="padding:28px;">
          <form method="POST" style="max-width:620px;">
            <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;">

              <div class="form-group" style="grid-column:1/-1;">
                <label>Full Name <span style="color:#e05c5c;">*</span></label>
                <input type="text" name="full_name" class="form-control" required maxlength="120"
                       placeholder="Jane Smith"
                       value="<?= e($_POST['full_name'] ?? '') ?>">
              </div>

              <div class="form-group">
                <label>Email Address <span style="color:#e05c5c;">*</span></label>
                <input type="email" name="email" class="form-control" required maxlength="180"
                       placeholder="jane@example.com"
                       value="<?= e($_POST['email'] ?? '') ?>">
              </div>

              <div class="form-group">
                <label>Phone Number</label>
                <div style="display:flex;gap:8px;align-items:stretch;">
                  <select name="country_code" class="form-control" style="width:130px;flex-shrink:0;font-size:.85rem;padding-left:6px;">
                    <option value="+1"    <?= (($_POST['country_code'] ?? '+1') === '+1')    ? 'selected' : '' ?>>🇺🇸 +1</option>
                    <option value="+1-CA" <?= (($_POST['country_code'] ?? '') === '+1-CA')  ? 'selected' : '' ?>>🇨🇦 +1 CA</option>
                    <option value="+44"   <?= (($_POST['country_code'] ?? '') === '+44')    ? 'selected' : '' ?>>🇬🇧 +44</option>
                    <option value="+91"   <?= (($_POST['country_code'] ?? '') === '+91')    ? 'selected' : '' ?>>🇮🇳 +91</option>
                    <option value="+61"   <?= (($_POST['country_code'] ?? '') === '+61')    ? 'selected' : '' ?>>🇦🇺 +61</option>
                    <option value="+64"   <?= (($_POST['country_code'] ?? '') === '+64')    ? 'selected' : '' ?>>🇳🇿 +64</option>
                    <option value="+49"   <?= (($_POST['country_code'] ?? '') === '+49')    ? 'selected' : '' ?>>🇩🇪 +49</option>
                    <option value="+33"   <?= (($_POST['country_code'] ?? '') === '+33')    ? 'selected' : '' ?>>🇫🇷 +33</option>
                    <option value="+34"   <?= (($_POST['country_code'] ?? '') === '+34')    ? 'selected' : '' ?>>🇪🇸 +34</option>
                    <option value="+39"   <?= (($_POST['country_code'] ?? '') === '+39')    ? 'selected' : '' ?>>🇮🇹 +39</option>
                    <option value="+31"   <?= (($_POST['country_code'] ?? '') === '+31')    ? 'selected' : '' ?>>🇳🇱 +31</option>
                    <option value="+46"   <?= (($_POST['country_code'] ?? '') === '+46')    ? 'selected' : '' ?>>🇸🇪 +46</option>
                    <option value="+47"   <?= (($_POST['country_code'] ?? '') === '+47')    ? 'selected' : '' ?>>🇳🇴 +47</option>
                    <option value="+45"   <?= (($_POST['country_code'] ?? '') === '+45')    ? 'selected' : '' ?>>🇩🇰 +45</option>
                    <option value="+41"   <?= (($_POST['country_code'] ?? '') === '+41')    ? 'selected' : '' ?>>🇨🇭 +41</option>
                    <option value="+32"   <?= (($_POST['country_code'] ?? '') === '+32')    ? 'selected' : '' ?>>🇧🇪 +32</option>
                    <option value="+351"  <?= (($_POST['country_code'] ?? '') === '+351')   ? 'selected' : '' ?>>🇵🇹 +351</option>
                    <option value="+353"  <?= (($_POST['country_code'] ?? '') === '+353')   ? 'selected' : '' ?>>🇮🇪 +353</option>
                    <option value="+48"   <?= (($_POST['country_code'] ?? '') === '+48')    ? 'selected' : '' ?>>🇵🇱 +48</option>
                    <option value="+420"  <?= (($_POST['country_code'] ?? '') === '+420')   ? 'selected' : '' ?>>🇨🇿 +420</option>
                    <option value="+36"   <?= (($_POST['country_code'] ?? '') === '+36')    ? 'selected' : '' ?>>🇭🇺 +36</option>
                    <option value="+40"   <?= (($_POST['country_code'] ?? '') === '+40')    ? 'selected' : '' ?>>🇷🇴 +40</option>
                    <option value="+380"  <?= (($_POST['country_code'] ?? '') === '+380')   ? 'selected' : '' ?>>🇺🇦 +380</option>
                    <option value="+7"    <?= (($_POST['country_code'] ?? '') === '+7')     ? 'selected' : '' ?>>🇷🇺 +7</option>
                    <option value="+90"   <?= (($_POST['country_code'] ?? '') === '+90')    ? 'selected' : '' ?>>🇹🇷 +90</option>
                    <option value="+966"  <?= (($_POST['country_code'] ?? '') === '+966')   ? 'selected' : '' ?>>🇸🇦 +966</option>
                    <option value="+971"  <?= (($_POST['country_code'] ?? '') === '+971')   ? 'selected' : '' ?>>🇦🇪 +971</option>
                    <option value="+972"  <?= (($_POST['country_code'] ?? '') === '+972')   ? 'selected' : '' ?>>🇮🇱 +972</option>
                    <option value="+92"   <?= (($_POST['country_code'] ?? '') === '+92')    ? 'selected' : '' ?>>🇵🇰 +92</option>
                    <option value="+880"  <?= (($_POST['country_code'] ?? '') === '+880')   ? 'selected' : '' ?>>🇧🇩 +880</option>
                    <option value="+94"   <?= (($_POST['country_code'] ?? '') === '+94')    ? 'selected' : '' ?>>🇱🇰 +94</option>
                    <option value="+977"  <?= (($_POST['country_code'] ?? '') === '+977')   ? 'selected' : '' ?>>🇳🇵 +977</option>
                    <option value="+86"   <?= (($_POST['country_code'] ?? '') === '+86')    ? 'selected' : '' ?>>🇨🇳 +86</option>
                    <option value="+81"   <?= (($_POST['country_code'] ?? '') === '+81')    ? 'selected' : '' ?>>🇯🇵 +81</option>
                    <option value="+82"   <?= (($_POST['country_code'] ?? '') === '+82')    ? 'selected' : '' ?>>🇰🇷 +82</option>
                    <option value="+65"   <?= (($_POST['country_code'] ?? '') === '+65')    ? 'selected' : '' ?>>🇸🇬 +65</option>
                    <option value="+60"   <?= (($_POST['country_code'] ?? '') === '+60')    ? 'selected' : '' ?>>🇲🇾 +60</option>
                    <option value="+66"   <?= (($_POST['country_code'] ?? '') === '+66')    ? 'selected' : '' ?>>🇹🇭 +66</option>
                    <option value="+84"   <?= (($_POST['country_code'] ?? '') === '+84')    ? 'selected' : '' ?>>🇻🇳 +84</option>
                    <option value="+63"   <?= (($_POST['country_code'] ?? '') === '+63')    ? 'selected' : '' ?>>🇵🇭 +63</option>
                    <option value="+62"   <?= (($_POST['country_code'] ?? '') === '+62')    ? 'selected' : '' ?>>🇮🇩 +62</option>
                    <option value="+27"   <?= (($_POST['country_code'] ?? '') === '+27')    ? 'selected' : '' ?>>🇿🇦 +27</option>
                    <option value="+234"  <?= (($_POST['country_code'] ?? '') === '+234')   ? 'selected' : '' ?>>🇳🇬 +234</option>
                    <option value="+20"   <?= (($_POST['country_code'] ?? '') === '+20')    ? 'selected' : '' ?>>🇪🇬 +20</option>
                    <option value="+254"  <?= (($_POST['country_code'] ?? '') === '+254')   ? 'selected' : '' ?>>🇰🇪 +254</option>
                    <option value="+55"   <?= (($_POST['country_code'] ?? '') === '+55')    ? 'selected' : '' ?>>🇧🇷 +55</option>
                    <option value="+52"   <?= (($_POST['country_code'] ?? '') === '+52')    ? 'selected' : '' ?>>🇲🇽 +52</option>
                    <option value="+54"   <?= (($_POST['country_code'] ?? '') === '+54')    ? 'selected' : '' ?>>🇦🇷 +54</option>
                    <option value="+56"   <?= (($_POST['country_code'] ?? '') === '+56')    ? 'selected' : '' ?>>🇨🇱 +56</option>
                    <option value="+57"   <?= (($_POST['country_code'] ?? '') === '+57')    ? 'selected' : '' ?>>🇨🇴 +57</option>
                    <option value="+51"   <?= (($_POST['country_code'] ?? '') === '+51')    ? 'selected' : '' ?>>🇵🇪 +51</option>
                  </select>
                  <input type="tel" name="phone" class="form-control" maxlength="15"
                         placeholder="555 000-0000" style="flex:1;"
                         value="<?= e($_POST['phone'] ?? '') ?>"
                         pattern="[\d\s\-\(\)]{7,15}"
                         title="Enter digits only, 7–15 characters">
                </div>
                <small style="color:var(--gray-400);font-size:.78rem;margin-top:4px;display:block;">Select country code, then enter local number (digits only, max 15)</small>
              </div>

              <div class="form-group">
                <label>Role <span style="color:#e05c5c;">*</span></label>
                <select name="role" class="form-control" required>
                  <option value="">— Select Role —</option>
                  <option value="employee" <?= (($_POST['role'] ?? '') === 'employee')    ? 'selected' : '' ?>>Employee</option>
                  <?php if ($user['role'] === 'super_admin'): ?>
                  <option value="hr_admin" <?= (($_POST['role'] ?? '') === 'hr_admin')    ? 'selected' : '' ?>>HR Manager</option>
                  <option value="super_admin" <?= (($_POST['role'] ?? '') === 'super_admin') ? 'selected' : '' ?>>Administrator</option>
                  <?php endif; ?>
                </select>
                <?php if ($user['role'] !== 'super_admin'): ?>
                  <small style="color:var(--gray-400);">HR Managers can only create Employee accounts. Contact an Administrator to create admin roles.</small>
                <?php endif; ?>
              </div>

              <div class="form-group">
                <label>Employment Type</label>
                <select name="employee_type" class="form-control">
                  <option value="">— Optional —</option>
                  <option value="W2"   <?= (($_POST['employee_type'] ?? '') === 'W2')   ? 'selected' : '' ?>>W2</option>
                  <option value="C2C"  <?= (($_POST['employee_type'] ?? '') === 'C2C')  ? 'selected' : '' ?>>C2C</option>
                  <option value="1099" <?= (($_POST['employee_type'] ?? '') === '1099') ? 'selected' : '' ?>>1099</option>
                </select>
              </div>

              <div class="form-group">
                <label>Start Date</label>
                <input type="date" name="start_date" class="form-control"
                       value="<?= e($_POST['start_date'] ?? '') ?>">
              </div>

              <div class="form-group">
                <label>Date of Birth <span style="color:#e05c5c;">*</span></label>
                <input type="date" name="date_of_birth" class="form-control" required
                       value="<?= e($_POST['date_of_birth'] ?? '') ?>">
              </div>

              <div class="form-group" style="grid-column:1/-1;">
                <label>Home Address <span style="color:#e05c5c;">*</span></label>
                <textarea name="address" class="form-control" rows="3" maxlength="500" required
                          placeholder="Street, City, State ZIP"><?= e($_POST['address'] ?? '') ?></textarea>
              </div>

              <div class="form-group">
                <label>Emergency Contact Name <span style="color:#e05c5c;">*</span></label>
                <input type="text" name="emergency_contact_name" class="form-control" maxlength="120" required
                       placeholder="Jane Doe"
                       value="<?= e($_POST['emergency_contact_name'] ?? '') ?>">
              </div>
              <div class="form-group">
                <label>Emergency Contact Phone <span style="color:#e05c5c;">*</span></label>
                <input type="tel" name="emergency_contact_phone" class="form-control" maxlength="25" required
                       placeholder="+1 (555) 123-4567"
                       value="<?= e($_POST['emergency_contact_phone'] ?? '') ?>">
              </div>

            </div>

            <div style="margin-top:6px;padding:16px;background:rgba(255,255,255,.03);border-radius:10px;border:1px solid var(--border);">
              <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-weight:500;">
                <input type="checkbox" name="send_welcome" value="1" <?= !empty($_POST['send_welcome']) ? 'checked' : 'checked' ?>
                       style="width:16px;height:16px;accent-color:var(--cyan);">
                Send welcome email with login credentials
              </label>
              <p style="margin:6px 0 0 26px;font-size:.81rem;color:var(--gray-400);">
                The employee will receive their temporary password by email. A secure password is auto-generated — the employee must change it on first login.
              </p>
            </div>

            <div style="margin-top:24px;display:flex;gap:12px;">
              <button type="submit" class="btn btn-primary">Create Account</button>
              <a href="/admin/employees.php" class="btn btn-outline">Cancel</a>
            </div>
          </form>
        </div>
      </div>

    </div>
  </div>
</div>
<?php pageFooter(); ?>
</body>
</html>
