<?php
/**
 * CloudFen HR Portal — Forced First-Login Password Change
 *
 * Shown automatically when a user logs in with a temporary password
 * (force_password_change = 1 in DB).  After a successful change the flag
 * is cleared and the user is redirected to their dashboard.
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
sendNoCacheHeaders();
checkIpBlock();
startSecureSession();
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
checkHoneypot();

// Must be logged in — if not, redirect to login
if (empty($_SESSION['user_id'])) {
    header('Location: ' . APP_URL . '/auth/login.php');
    exit;
}

// If the flag is not set (they ended up here directly without a temp password),
// just send them to their normal dashboard.
if (empty($_SESSION['force_password_change'])) {
    $dest = in_array($_SESSION['role'] ?? '', ['hr_admin', 'super_admin'])
        ? '/admin/dashboard.php'
        : '/employee/dashboard.php';
    header('Location: ' . APP_URL . $dest);
    exit;
}

$db  = getDB();
$msg = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true); // rotate token after use

    $newPass  = $_POST['new_password']     ?? '';
    $confirm  = $_POST['confirm_password'] ?? '';

    if ($newPass !== $confirm) {
        $msg = 'Passwords do not match.';
        $msgType = 'error';
    } else {
        $errors = validatePassword($newPass);
        if ($errors) {
            $msg = implode(' ', $errors);
            $msgType = 'error';
        } else {
            $hash = hashPassword($newPass);
            try {
                $db->prepare(
                    "UPDATE users
                     SET password_hash = ?, force_password_change = 0,
                         failed_logins = 0
                     WHERE id = ?"
                )->execute([$hash, (int)$_SESSION['user_id']]);

                auditLog('password_changed_forced', 'users', (int)$_SESSION['user_id'], [
                    'ip' => getClientIpSecure(),
                ]);

                session_regenerate_id(true);
                $_SESSION['_regenerated_at'] = time();

                // Clear the session flag
                unset($_SESSION['force_password_change']);

                // Redirect to the correct dashboard
                $dest = in_array($_SESSION['role'] ?? '', ['hr_admin', 'super_admin'])
                    ? '/admin/dashboard.php'
                    : '/employee/dashboard.php';

                header('Location: ' . APP_URL . $dest . '?pw_changed=1');
                exit;

            } catch (\Throwable $e) {
                error_log('CloudFen: forced password change error — ' . $e->getMessage());
                $msg = 'A server error occurred. Please try again.';
                $msgType = 'error';
            }
        }
    }
}

pageHead('Set Your Password');
?>
<body>
<div class="auth-shell">
  <!-- Left panel -->
  <div class="auth-panel">
    <div class="auth-panel-logo"><img src="/assets/img/logo.png" alt="CloudFen"></div>
    <h2>Secure Your<br><span>Account</span></h2>
    <p>You signed in with a temporary password. Please choose a strong permanent password before continuing.</p>
    <div class="auth-features" style="margin-top:32px;">
      <div class="auth-feature-item"><span class="feat-dot">🔠</span> At least 12 characters</div>
      <div class="auth-feature-item"><span class="feat-dot">🔡</span> Uppercase &amp; lowercase letters</div>
      <div class="auth-feature-item"><span class="feat-dot">🔢</span> At least one number</div>
      <div class="auth-feature-item"><span class="feat-dot">🔣</span> At least one special character</div>
    </div>
  </div>

  <!-- Right form -->
  <div class="auth-form-wrap">
    <h1>Set Your Password</h1>
    <p class="sub" style="color:#e09020;font-weight:600;">⚠️ Your account uses a temporary password — please change it now.</p>

    <?php if ($msg && $msgType === 'error'): ?>
      <div class="alert alert-error">⚠️ <?= e($msg) ?></div>
    <?php endif; ?>

    <form method="POST" data-loading autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">

      <div class="form-group">
        <label>New Password</label>
        <input type="password"
               name="new_password"
               id="new_password"
               class="form-control"
               placeholder="Choose a strong password"
               required
               minlength="12"
               maxlength="128"
               autocomplete="new-password"
               oninput="checkStrength(this.value)">

        <!-- Strength bar -->
        <div id="strength-bar-wrap" style="margin-top:8px;height:4px;background:var(--border);border-radius:4px;overflow:hidden;display:none;">
          <div id="strength-bar" style="height:100%;width:0%;border-radius:4px;transition:width .3s,background .3s;"></div>
        </div>
        <div id="strength-label" style="font-size:.75rem;margin-top:4px;min-height:16px;"></div>

        <!-- Live requirement checklist -->
        <ul id="pw-reqs" style="list-style:none;padding:10px 0 0;margin:0;font-size:.8rem;color:var(--gray-400);">
          <li id="req-len"  style="margin-bottom:4px;">✗ &nbsp;12 or more characters</li>
          <li id="req-up"   style="margin-bottom:4px;">✗ &nbsp;At least one uppercase letter</li>
          <li id="req-low"  style="margin-bottom:4px;">✗ &nbsp;At least one lowercase letter</li>
          <li id="req-num"  style="margin-bottom:4px;">✗ &nbsp;At least one number</li>
          <li id="req-spc"  style="margin-bottom:4px;">✗ &nbsp;At least one special character (!@#$%…)</li>
        </ul>
      </div>

      <div class="form-group">
        <label>Confirm New Password</label>
        <input type="password"
               name="confirm_password"
               id="confirm_password"
               class="form-control"
               placeholder="Repeat your new password"
               required
               minlength="12"
               maxlength="128"
               autocomplete="new-password"
               oninput="checkMatch()">
        <div id="match-label" style="font-size:.75rem;margin-top:4px;min-height:16px;"></div>
      </div>

      <button type="submit" id="submit-btn" class="btn btn-primary btn-block" disabled>
        <span class="btn-text">Save Password & Continue →</span>
      </button>
    </form>

    <p style="font-size:.8rem;color:var(--gray-400);margin-top:20px;text-align:center;">
      Need help? <a href="<?= e(getHrContactUrl()) ?>" style="color:var(--cyan);">Contact HR</a>
    </p>
  </div>
</div>

<script>
function checkStrength(val) {
  var bar  = document.getElementById('strength-bar');
  var wrap = document.getElementById('strength-bar-wrap');
  var lbl  = document.getElementById('strength-label');

  wrap.style.display = val.length ? 'block' : 'none';

  var score = 0;
  var reqLen  = val.length >= 12;
  var reqUp   = /[A-Z]/.test(val);
  var reqLow  = /[a-z]/.test(val);
  var reqNum  = /[0-9]/.test(val);
  var reqSpc  = /[^A-Za-z0-9]/.test(val);

  // Update checklist
  setReq('req-len',  reqLen,  '12 or more characters');
  setReq('req-up',   reqUp,   'At least one uppercase letter');
  setReq('req-low',  reqLow,  'At least one lowercase letter');
  setReq('req-num',  reqNum,  'At least one number');
  setReq('req-spc',  reqSpc,  'At least one special character (!@#$%…)');

  if (reqLen)  score++;
  if (reqUp)   score++;
  if (reqLow)  score++;
  if (reqNum)  score++;
  if (reqSpc)  score++;
  if (val.length >= 16) score++;

  var colors = ['#e05c5c','#e08020','#e0c020','#20c08a','#20a0c0','#1fa0c0'];
  var labels = ['Very weak','Weak','Fair','Good','Strong','Very strong'];
  var pct    = [17, 34, 50, 67, 83, 100];

  var idx = Math.max(0, Math.min(score - 1, 5));
  if (val.length === 0) { bar.style.width='0%'; lbl.textContent=''; return; }

  bar.style.width      = pct[idx] + '%';
  bar.style.background = colors[idx];
  lbl.style.color      = colors[idx];
  lbl.textContent      = labels[idx];

  updateSubmit();
}

function setReq(id, ok, text) {
  var el = document.getElementById(id);
  if (!el) return;
  el.textContent = (ok ? '✓' : '✗') + ' \u00a0' + text;
  el.style.color = ok ? '#20c08a' : 'var(--gray-400)';
}

function checkMatch() {
  var p1  = document.getElementById('new_password').value;
  var p2  = document.getElementById('confirm_password').value;
  var lbl = document.getElementById('match-label');
  if (!p2.length) { lbl.textContent=''; return; }
  if (p1 === p2) {
    lbl.textContent = '✓ Passwords match';
    lbl.style.color = '#20c08a';
  } else {
    lbl.textContent = '✗ Passwords do not match';
    lbl.style.color = '#e05c5c';
  }
  updateSubmit();
}

function updateSubmit() {
  var p1  = document.getElementById('new_password').value;
  var p2  = document.getElementById('confirm_password').value;
  var ok  = p1.length >= 12
         && /[A-Z]/.test(p1)
         && /[a-z]/.test(p1)
         && /[0-9]/.test(p1)
         && /[^A-Za-z0-9]/.test(p1)
         && p1 === p2;
  document.getElementById('submit-btn').disabled = !ok;
}
</script>

<?php pageFooter(); ?>
</body>
</html>
