<?php

/**

 * CloudFen HR Portal — Security Layer v2 (PHP 8.2)

 *

 * FIX (v14.2): Always add an output buffer layer here regardless of whether

 * one is already active.  On shared hosts (e.g. Turbify/Yahoo) the server

 * may inject content (visitor stats, charset headers, etc.) before PHP

 * executes, which sends HTTP headers and causes every subsequent ini_set(),

 * session_set_cookie_params(), and session_start() call to fail with

 * "headers already sent".  Calling ob_start() unconditionally is safe —

 * PHP simply stacks a new buffer on top of any existing one, and

 * ob_get_clean() / ob_end_flush() unwind them in order.

 *

 * The previous guard `if (ob_get_level() === 0)` was incorrect: it skipped

 * buffering whenever index.php had already called ob_start(), which is the

 * normal code path for every direct page request.

 */

ob_start();



/**

 *

 * LAYER 2 ADDITIONS (v14):

 *  - Input fingerprint binding (session hijack detection)

 *  - Request size guard (anti-DoS)

 *  - Clickjacking / MIME-sniff / HSTS / COOP headers

 *  - CSRF token rotation after use

 *  - IP-based block list check

 *  - PHP error suppression in output

 *  - Honeypot field helper

 *  - Trusted-proxy IP resolution

 */



/* ── SERVER VARIABLE HELPER ───────────────────────────────── */

function getServerVar(string $key, string $default = ''): string {

    if (!isset($_SERVER[$key])) return $default;

    $value = $_SERVER[$key];

    if (is_array($value)) return (string)($value[0] ?? $default);

    return (string)$value;

}



function isSecureRequest(): bool {

    $httpsValue = strtolower(getServerVar('HTTPS'));

    if ($httpsValue !== '' && $httpsValue !== 'off') {

        return true;

    }

    // APP_URL is deployment-controlled configuration. When it declares the
    // public origin as HTTPS, the browser-facing connection is secure even if
    // a hosting proxy terminates TLS before the PHP container receives it.
    $publicAppUrl = strtolower(trim(defined('APP_URL') ? APP_URL : ''));
    if (str_starts_with($publicAppUrl, 'https://')) {
        return true;
    }

    // Forwarding headers are controlled by the connecting client unless the
    // request came from a proxy explicitly trusted by the deployment.
    $remoteAddr = trim(getServerVar('REMOTE_ADDR', ''));
    $trustedProxies = defined('TRUSTED_PROXIES')
        ? (array)TRUSTED_PROXIES
        : ['127.0.0.1', '::1'];
    if (!in_array($remoteAddr, $trustedProxies, true)) {
        return false;
    }



    $forwardedProto = strtolower(getServerVar('HTTP_X_FORWARDED_PROTO'));

    if ($forwardedProto === 'https') {

        return true;

    }



    $forwardedSsl = strtolower(getServerVar('HTTP_X_FORWARDED_SSL'));

    if ($forwardedSsl === 'on') {

        return true;

    }



    $cfVisitor = getServerVar('HTTP_CF_VISITOR');

    if ($cfVisitor !== '' && stripos($cfVisitor, '"scheme":"https"') !== false) {

        return true;

    }



    return false;

}



/* ── SECURITY HEADERS ─────────────────────────────────────── */

function sendSecurityHeaders(bool $allowSameOriginFrame = false): void {

    if (headers_sent()) return;



    // Prevent MIME type sniffing

    header('X-Content-Type-Options: nosniff');

    // Deny framing entirely by default; allow same-origin framing only for secure document previews.

    header('X-Frame-Options: ' . ($allowSameOriginFrame ? 'SAMEORIGIN' : 'DENY'));

    // Limit referrer leakage

    header('Referrer-Policy: strict-origin-when-cross-origin');

    // Disable browser features not needed by this app

    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');

    // Legacy XSS filter

    header('X-XSS-Protection: 1; mode=block');

    // Force HTTPS for 1 year

    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

    // Prevent opening popups from this origin in other contexts

    header('Cross-Origin-Opener-Policy: same-origin');

    // Prevent other origins from reading our responses

    header('Cross-Origin-Resource-Policy: same-origin');

    // Remove PHP fingerprint

    header_remove('X-Powered-By');



    // Full CSP

    header(

        "Content-Security-Policy: " .

        "default-src 'self'; " .

        "base-uri 'self'; " .

        "form-action 'self'; " .

        "frame-ancestors " . ($allowSameOriginFrame ? "'self'; " : "'none'; ") .

        "object-src 'none'; " .

        "script-src 'self' 'unsafe-inline'; " .

        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; " .

        "font-src 'self' https://fonts.gstatic.com data:; " .

        "img-src 'self' data: blob:; " .

        "connect-src 'self'; " .

        "worker-src 'none'; " .

        "manifest-src 'none';"

    );

}



/* ── SEND NO-CACHE HEADERS (for auth / sensitive pages) ───── */

function sendNoCacheHeaders(): void {

    if (headers_sent()) return;

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

    header('Pragma: no-cache');

    header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');

}



/* ── REQUEST SIZE GUARD (anti-DoS) ───────────────────────── */

/**

 * Abort if POST body exceeds $maxBytes.

 * Should be called before reading $_POST on any page that

 * receives form submissions.

 */

function guardRequestSize(int $maxBytes = 5_242_880): void { // 5 MB default

    $contentLength = (int)getServerVar('CONTENT_LENGTH', '0');

    if ($contentLength > $maxBytes) {

        http_response_code(413);

        die(json_encode(['success' => false, 'message' => 'Request too large.']));

    }

}



/* ── IP BLOCK CHECK ───────────────────────────────────────── */

/**

 * Check the blocked_ips table and abort if the client IP is blocked.

 * Call this near the top of every page load (after session start).

 */

function checkIpBlock(): void {

    if (!function_exists('getDB')) return; // helpers not loaded yet — skip

    try {

        $ip = getClientIpSecure();

        $db = getDB();

        $stmt = $db->prepare(

            "SELECT id FROM blocked_ips

             WHERE ip_address = ?

               AND (expires_at IS NULL OR expires_at > NOW())

             LIMIT 1"

        );

        $stmt->execute([$ip]);

        if ($stmt->fetch()) {

            http_response_code(403);

            die('Access denied.');

        }

    } catch (\Throwable) {

        // Never break page load for a failed IP check

    }

}



/* ── TRUSTED-PROXY IP RESOLUTION ──────────────────────────── */

/**

 * Like getClientIp() in helpers.php but also validates the proxy

 * header against an optional allow-list of trusted proxy IPs.

 * Falls back to REMOTE_ADDR when the proxy is untrusted.

 */

function getClientIpSecure(): string {

    $remoteAddr = trim(getServerVar('REMOTE_ADDR', '0.0.0.0'));



    // Trusted proxy CIDR list — extend in configT.php as needed

    $trustedProxies = defined('TRUSTED_PROXIES')

        ? (array)TRUSTED_PROXIES

        : ['127.0.0.1', '::1'];



    $isTrustedProxy = in_array($remoteAddr, $trustedProxies, true);



    if ($isTrustedProxy) {

        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $header) {

            $v = getServerVar($header, '');

            if ($v !== '') {

                $ip = trim(explode(',', $v)[0]);

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {

                    return $ip;

                }

            }

        }

    }



    return filter_var($remoteAddr, FILTER_VALIDATE_IP) ? $remoteAddr : '0.0.0.0';

}



/* ── SESSION ──────────────────────────────────────────────── */

function startSecureSession(): void {

    if (session_status() === PHP_SESSION_NONE) {

        // On shared hosts (e.g. Turbify/Yahoo) the server may inject headers
        // before PHP runs, so headers_sent() is already true.  Guard every
        // ini_set / session_set_cookie_params call so we degrade silently
        // instead of flooding the error log with warnings.
        $isSecure      = isSecureRequest();
        $headersFrozen = headers_sent();

        if (!$headersFrozen) {
            ini_set('session.use_only_cookies',       '1');
            ini_set('session.use_strict_mode',        '1');
            ini_set('session.cookie_httponly',        '1');
            ini_set('session.cookie_samesite',        'Lax');
            ini_set('session.use_trans_sid',          '0');
            ini_set('session.sid_length',             '64');
            ini_set('session.sid_bits_per_character', '6');
            if ($isSecure) {
                ini_set('session.cookie_secure', '1');
            }
            session_set_cookie_params([
                'lifetime' => 0,
                'path'     => '/',
                'secure'   => $isSecure,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        }

        if (!headers_sent()) {
            session_start();
        } else {
            // Headers already sent — start session without cookie negotiation.
            // This is safe: the browser already has the session cookie from
            // the previous response; we just need PHP to load the data.
            @session_start();
        }

    }

    // Distinctive marker so admin/super/clear_sessions.php (which globs the
    // shared session-file directory on disk) can tell this app's session files
    // apart from another PHP app's on the same shared-hosting account, instead
    // of deleting every sess_* file it finds regardless of owner.
    $_SESSION['_app'] = $_SESSION['_app'] ?? 'cloudfen_hr_v1';




    // ── Session timeout ──────────────────────────────────────

    $lifetime = defined('SESSION_LIFETIME') ? SESSION_LIFETIME : 1800;

    if (!empty($_SESSION['last_active']) && (time() - $_SESSION['last_active']) > $lifetime) {

        session_unset();

        session_destroy();

        @session_start();  // safe even if headers sent — just resets session data

        if (!headers_sent()) {

            header('Location: ' . (defined('APP_URL') ? APP_URL : '') . '/auth/login.php?timeout=1');

            exit;

        }

        return;

    }



    if (isset($_SESSION['user_id'])) {

        // ── Session ID rotation every 15 minutes ─────────────

        if (empty($_SESSION['_regenerated_at']) || (time() - (int)$_SESSION['_regenerated_at']) > 900) {

            session_regenerate_id(true);

            $_SESSION['_regenerated_at'] = time();

        }



        // ── Session fingerprint binding (Layer 2) ─────────────

        // Bind session to UA + partial IP so a stolen cookie from

        // a different browser/network is rejected.

        $fingerprint = _buildSessionFingerprint();

        if (empty($_SESSION['_fingerprint'])) {

            $_SESSION['_fingerprint'] = $fingerprint;

        } elseif (!hash_equals($_SESSION['_fingerprint'], $fingerprint)) {

            // Fingerprint mismatch — possible session hijack

            session_unset();

            session_destroy();

            session_start();

            if (!headers_sent()) {

                header('Location: ' . (defined('APP_URL') ? APP_URL : '') . '/auth/login.php?security=1');

                exit;

            }

            return;

        }



        $_SESSION['last_active'] = time();

    }

}



/**

 * Build a session fingerprint from stable client attributes.

 * We use UA + first two octets of IP to balance security vs

 * mobile IP churn (LTE users often change last two octets).

 */

function _buildSessionFingerprint(): string {

    $ua      = substr(getServerVar('HTTP_USER_AGENT', 'unknown'), 0, 200);

    $ip      = getClientIpSecure();

    $ipParts = explode('.', $ip);

    // For IPv4 use /16 prefix; for IPv6 keep first 4 groups

    $ipPrefix = count($ipParts) >= 2

        ? $ipParts[0] . '.' . $ipParts[1]

        : $ip;

    $secret = resolveAppSecret();

    return hash_hmac('sha256', $ua . '|' . $ipPrefix, $secret);

}



/* ── CSRF ─────────────────────────────────────────────────── */

function generateCsrfToken(): string {

    if (empty($_SESSION['csrf_token'])) {

        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    }

    return $_SESSION['csrf_token'];

}



/**

 * Verify CSRF and optionally rotate the token afterwards so

 * every form submission uses a fresh token (double-submit prevention).

 */

function verifyCsrfToken(bool $rotate = false): void {

    $token = $_POST['csrf_token'] ?? getServerVar('HTTP_X_CSRF_TOKEN');

    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], (string)$token)) {

        http_response_code(403);

        if (!headers_sent()) {

            die(json_encode(['success' => false, 'message' => 'CSRF token mismatch. Please refresh and try again.']));

        }

        exit;

    }

    if ($rotate) {

        // Regenerate token so it can't be replayed

        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    }

}



function verifyCsrf(): void { verifyCsrfToken(); }



/* ── HONEYPOT FIELD ───────────────────────────────────────── */

/**

 * Output a hidden honeypot input in a form.

 * Call checkHoneypot() at the top of the POST handler.

 *

 * Usage in template:

 *   <?= honeypotField() ?>

 */

function honeypotField(): string {

    return '<input type="text" name="cf_url" style="display:none!important;position:absolute;left:-9999px" tabindex="-1" autocomplete="off" aria-hidden="true">';

}



/**

 * If the honeypot field was filled in, the submitter is a bot.

 * Silently return a fake success and exit.

 */

function checkHoneypot(): void {

    if (!empty($_POST['cf_url'])) {

        // Return a plausible 200 so bots don't retry

        http_response_code(200);

        echo json_encode(['success' => true, 'message' => 'Submitted.']);

        exit;

    }

}



/* ── FORCE PASSWORD CHANGE GUARD ──────────────────────────── */

// Deactivating/offboarding a user (admin/employees.php, admin/super/offboard.php)
// only blocks *new* logins — without this, an already-logged-in session keeps
// full access until its idle timeout. Runs the same lightweight per-request
// pattern as checkProfileCompletion()/checkDocumentCompletion() below.
function checkAccountStillActive(): void {

    if (empty($_SESSION['user_id'])) {

        return;

    }

    $currentPage = basename(getServerVar('SCRIPT_FILENAME'));

    if ($currentPage === 'logout.php') {

        return;

    }

    if (!function_exists('getDB')) {

        return;

    }

    try {

        $db = getDB();

        $stmt = $db->prepare('SELECT status FROM users WHERE id = ? LIMIT 1');

        $stmt->execute([(int)$_SESSION['user_id']]);

        $status = $stmt->fetchColumn();

    } catch (\Throwable) {

        return;

    }

    if ($status === 'deactivated') {

        $_SESSION = [];

        if (ini_get('session.use_cookies')) {

            $p = session_get_cookie_params();

            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);

        }

        session_destroy();

        header('Location: ' . (defined('APP_URL') ? APP_URL : '') . '/auth/login.php?deactivated=1');

        exit;

    }

}



function checkForcePasswordChange(): void {

    if (!empty($_SESSION['force_password_change'])) {

        $currentPage = basename(getServerVar('SCRIPT_FILENAME'));

        if ($currentPage !== 'change_password.php') {

            header('Location: ' . (defined('APP_URL') ? APP_URL : '') . '/auth/change_password.php');

            exit;

        }

    }

}



function userProfileRequiresCompletion(int $userId): bool {

    if (!function_exists('getDB')) {

        return false;

    }



    try {

        $db = getDB();

        $stmt = $db->prepare(

            "SELECT date_of_birth, address, emergency_contact

             FROM users

             WHERE id = ?

             LIMIT 1"

        );

        $stmt->execute([$userId]);

        $row = $stmt->fetch();

        if (!$row) {

            return false;

        }



        $emergencyContact = function_exists('decodeEmergencyContact')

            ? decodeEmergencyContact((string)($row['emergency_contact'] ?? ''))

            : ['name' => trim((string)($row['emergency_contact'] ?? '')), 'phone' => ''];



        return empty($row['date_of_birth'])

            || trim((string)($row['address'] ?? '')) === ''

            || trim((string)($emergencyContact['name'] ?? '')) === ''

            || trim((string)($emergencyContact['phone'] ?? '')) === '';

    } catch (\Throwable) {

        return false;

    }

}



function checkProfileCompletion(): void {

    if (empty($_SESSION['user_id'])) {

        return;

    }



    $currentPage = basename(getServerVar('SCRIPT_FILENAME'));

    if (in_array($currentPage, ['profile.php', 'change_password.php', 'logout.php', 'h1b_documents.php'], true)) {

        return;

    }



    if (userProfileRequiresCompletion((int)$_SESSION['user_id'])) {

        header('Location: ' . (defined('APP_URL') ? APP_URL : '') . '/employee/profile.php?complete=1');

        exit;

    }

}



// Mandatory onboarding documents — required for every role except
// super_admin and hr_admin. A document counts as satisfied only while its latest upload
// is 'pending' or 'approved'; missing, rejected, or more-info-needed rows
// still block access, same as the profile-completion gate above.
function userDocumentsRequireCompletion(int $userId): bool {

    // Explicitly enabled demo environments need no fabricated identity files.
    // Only server-marked fictional accounts are exempt; all auth/RBAC stays active.
    if (defined('APP_DEMO_MODE') && APP_DEMO_MODE && function_exists('tableExists') && tableExists('workspace_people')) {
        $demo = getDB()->prepare('SELECT is_demo FROM workspace_people WHERE user_id=?');
        $demo->execute([$userId]);
        if ((int)$demo->fetchColumn() === 1) return false;
    }

    if (!function_exists('getDB') || !function_exists('mandatoryOnboardingDocTypes')) {

        return false;

    }



    try {

        $required = mandatoryOnboardingDocTypes();

        $db = getDB();

        $placeholders = implode(',', array_fill(0, count($required), '?'));

        $stmt = $db->prepare(

            "SELECT doc_type, status, uploaded_at
             FROM documents
             WHERE user_id = ? AND doc_type IN ({$placeholders})
             ORDER BY uploaded_at DESC"

        );

        $stmt->execute(array_merge([$userId], $required));



        $latestByType = [];

        foreach ($stmt->fetchAll() as $row) {

            if (!isset($latestByType[$row['doc_type']])) {

                $latestByType[$row['doc_type']] = $row['status'];

            }

        }



        foreach ($required as $type) {

            $status = $latestByType[$type] ?? 'missing';

            if (in_array($status, ['missing', 'rejected', 'more_info_needed'], true)) {

                return true;

            }

        }



        return false;

    } catch (\Throwable) {

        return false;

    }

}



function checkDocumentCompletion(): void {

    if (empty($_SESSION['user_id'])) {

        return;

    }



    if (in_array($_SESSION['role'] ?? '', ['super_admin', 'hr_admin'], true)) {

        return;

    }



    $currentPage = basename(getServerVar('SCRIPT_FILENAME'));

    if (in_array($currentPage, ['documents.php', 'profile.php', 'change_password.php', 'logout.php', 'h1b_documents.php'], true)) {

        return;

    }



    if (userDocumentsRequireCompletion((int)$_SESSION['user_id'])) {

        header('Location: ' . (defined('APP_URL') ? APP_URL : '') . '/employee/documents.php?required=1');

        exit;

    }

}



/* ── AUTH GUARDS ──────────────────────────────────────────── */

function requireRole(string ...$roles): array {

    startSecureSession();

    checkIpBlock();

    if (empty($_SESSION['user_id'])) {

        $next = urlencode(getServerVar('REQUEST_URI'));

        header('Location: ' . (defined('APP_URL') ? APP_URL : '') . '/auth/login.php?next=' . $next);

        exit;

    }

    if (!in_array($_SESSION['role'] ?? '', $roles, true)) {

        http_response_code(403);

        die('Access denied.');

    }

    checkAccountStillActive();

    checkForcePasswordChange();

    checkProfileCompletion();

    checkDocumentCompletion();

    return [

        'id'   => (int)$_SESSION['user_id'],

        'name' => $_SESSION['name'] ?? 'User',

        'role' => $_SESSION['role'] ?? '',

    ];

}



function requireAnyRole(): array {

    startSecureSession();

    checkIpBlock();

    if (empty($_SESSION['user_id'])) {

        header('Location: ' . (defined('APP_URL') ? APP_URL : '') . '/auth/login.php');

        exit;

    }

    checkAccountStillActive();

    checkForcePasswordChange();

    checkProfileCompletion();

    checkDocumentCompletion();

    return [

        'id'   => (int)$_SESSION['user_id'],

        'name' => $_SESSION['name'] ?? 'User',

        'role' => $_SESSION['role'] ?? '',

    ];

}



function requireLogin(): array {

    return requireAnyRole();

}



/* ── OUTPUT SANITISER ALIAS ───────────────────────────────── */

/**

 * Short alias for htmlspecialchars() — identical to e() in helpers.php.

 * Defined here so security.php is self-contained even when loaded alone.

 */

if (!function_exists('esc')) {

    function esc(string $s): string {

        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    }

}



/* ── CSP NONCE ────────────────────────────────────────────── */

/**

 * Generate (or retrieve) a per-request CSP nonce.

 *

 * Add <?= cspNonce() ?> to every inline <script> and <style> tag, then

 * replace 'unsafe-inline' in the CSP header with 'nonce-{value}'.

 *

 * The nonce is stored in $_SERVER so it survives across multiple calls

 * within the same request without touching the session.

 */

function cspNonce(): string {

    if (empty($_SERVER['_CSP_NONCE'])) {

        $_SERVER['_CSP_NONCE'] = base64_encode(random_bytes(18));

    }

    return (string)$_SERVER['_CSP_NONCE'];

}



/* ── PASSWORD STRENGTH VALIDATOR ──────────────────────────── */

/**

 * Enforce the CloudFen password policy:

 *   • Minimum 12 characters

 *   • At least one uppercase letter

 *   • At least one lowercase letter

 *   • At least one digit

 *   • At least one special character

 *   • Not in the common-password block-list

 *

 * Returns an array of human-readable error strings (empty = passes).

 *

 * @param  string   $password  The candidate password (plain-text)

 * @return string[]            Validation failure messages

 */

function validatePasswordStrength(string $password): array {

    $errors = [];



    if (strlen($password) < 12) {

        $errors[] = 'Password must be at least 12 characters long.';

    }

    if (!preg_match('/[A-Z]/', $password)) {

        $errors[] = 'Password must contain at least one uppercase letter.';

    }

    if (!preg_match('/[a-z]/', $password)) {

        $errors[] = 'Password must contain at least one lowercase letter.';

    }

    if (!preg_match('/[0-9]/', $password)) {

        $errors[] = 'Password must contain at least one number.';

    }

    if (!preg_match('/[^A-Za-z0-9]/', $password)) {

        $errors[] = 'Password must contain at least one special character (e.g. !@#$%).';

    }



    // Common / breached password block-list (extend as needed)

    $blocked = [

        'password', 'password1', 'password12', 'password123', 'password1234',

        '123456789012', 'qwertyuiop[]', 'iloveyou!!!!!', 'letmein!!!!!!',

        'welcome12345', 'admin123admin', 'cloudfen12345',

    ];

    if (in_array(strtolower($password), $blocked, true)) {

        $errors[] = 'That password is too common. Please choose a more unique password.';

    }



    return $errors;

}



/* ── UPLOAD FILENAME SANITIZER ────────────────────────────── */

/**

 * Strip everything that is not an alphanumeric character, dot, dash or

 * underscore from an uploaded file's original name.  Also prevents

 * double-extension tricks (e.g. evil.php.jpg) by keeping only the last

 * extension and forcing it to match an allow-list.

 *

 * @param  string   $originalName  Raw filename from $_FILES[…]['name']

 * @param  string[] $allowedExts   Lower-cased extension allow-list

 * @param  string   $fallback      Used when no valid extension is found

 * @return string                  Safe filename (no path component)

 */

function sanitizeUploadFilename(string $originalName, array $allowedExts = ['pdf','jpg','jpeg','png'], string $fallback = 'file'): string {

    // Strip any directory component first

    $base = basename($originalName);



    // Extract the last extension only (prevents double-ext attacks)

    $dotPos  = strrpos($base, '.');

    $ext     = $dotPos !== false ? strtolower(substr($base, $dotPos + 1)) : '';

    $nameRaw = $dotPos !== false ? substr($base, 0, $dotPos) : $base;



    // Sanitize the stem: keep only safe characters

    $nameSafe = preg_replace('/[^A-Za-z0-9_\-]/', '_', $nameRaw) ?: $fallback;

    $nameSafe = substr($nameSafe, 0, 80); // cap length



    if (!in_array($ext, $allowedExts, true)) {

        $ext = $allowedExts[0] ?? 'bin';

    }



    return $nameSafe . '.' . $ext;

}



/* ── SECURITY EVENT LOGGER ────────────────────────────────── */

/**

 * Write a structured security event to the PHP error log.

 * Keeps a consistent format so log aggregators (fail2ban, SIEM) can

 * parse it reliably.

 *

 * @param string $event   Short event key  (e.g. 'csrf_fail', 'brute_force')

 * @param array  $context Additional key→value pairs to include

 */

function logSecurityEvent(string $event, array $context = []): void {

    $ip     = function_exists('getClientIpSecure') ? getClientIpSecure() : ($_SERVER['REMOTE_ADDR'] ?? 'unknown');

    $userId = $_SESSION['user_id'] ?? 'guest';

    $uri    = $_SERVER['REQUEST_URI'] ?? '';

    $ctx    = $context ? ' | ' . json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : '';

    error_log(sprintf('[CLOUDFEN_SECURITY] event=%s user=%s ip=%s uri=%s%s', $event, $userId, $ip, $uri, $ctx));

}



/* ── UPLOAD EXTENSION DOUBLE-CHECK ───────────────────────────────────────── */

/**

 * After MIME detection, verify the uploaded file's extension also matches

 * the detected MIME.  Rejects files where the extension contradicts the

 * content (e.g. a PHP file renamed to .jpg).

 *

 * @param  string   $tmpPath    Path to the uploaded tmp file

 * @param  string   $origName   Original filename from $_FILES[…]['name']

 * @param  string[] $mimeToExts Map of allowed MIME types → valid extensions

 * @return bool     true = extension is consistent with MIME

 */

function uploadExtensionMatchesMime(string $tmpPath, string $origName, array $mimeToExts): bool {

    $finfo      = new \finfo(FILEINFO_MIME_TYPE);

    $detectedMime = (string)$finfo->file($tmpPath);

    $allowed    = $mimeToExts[$detectedMime] ?? null;



    if ($allowed === null) {

        return false; // MIME not in allow-list at all

    }



    $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));

    $allowedExts = is_array($allowed) ? $allowed : [$allowed];

    return in_array($ext, $allowedExts, true);

}



/* ═══════════════════════════════════════════════════════════════════
 *  SECURITY ADDITIONS — new features
 * ═══════════════════════════════════════════════════════════════════ */

/* ── 1. LOGIN NOTIFICATION EMAIL ───────────────────────────────────
 * Send an alert email when a user logs in from a new IP address.
 * Compares against their last known login IP stored in the users table.
 */
function sendNewLoginAlert(int $userId, string $currentIp, string $userEmail, string $userName, string $lastKnownIp = ''): void {
    // Only alert if the IP has changed (skip first-ever login)
    if ($lastKnownIp === '' || $lastKnownIp === $currentIp) return;

    $ua      = substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown browser', 0, 120);
    $time    = date('F j, Y \a\t g:i A T');
    $appUrl  = defined('APP_URL') ? APP_URL : '';

    $body = emailTemplate('New Login Detected', "
        <p>Hi {$userName},</p>
        <p>We noticed a new sign-in to your HR Portal account from an IP address we haven\'t seen before.</p>
        <table style=\"width:100%;border-collapse:collapse;margin:16px 0;font-size:.9rem;\">
          <tr><td style=\"padding:8px 12px;background:#f4f4f5;border-radius:4px 4px 0 0;font-weight:700;\">When</td>
              <td style=\"padding:8px 12px;background:#fafafa;\">{$time}</td></tr>
          <tr><td style=\"padding:8px 12px;background:#f4f4f5;font-weight:700;\">IP Address</td>
              <td style=\"padding:8px 12px;background:#fafafa;\">{$currentIp}</td></tr>
          <tr><td style=\"padding:8px 12px;background:#f4f4f5;border-radius:0 0 4px 4px;font-weight:700;\">Browser</td>
              <td style=\"padding:8px 12px;background:#fafafa;\">{$ua}</td></tr>
        </table>
        <p>If this was you, no action is needed. If you do not recognise this login, please
           <a href=\"{$appUrl}/auth/change_password.php\">change your password immediately</a>
           and contact HR.</p>
    ");

    try {
        sendMail($userEmail, '⚠️ New Login to Your HR Portal Account', $body);
    } catch (\Throwable $e) {
        error_log('sendNewLoginAlert mail error: ' . $e->getMessage());
    }
}

/* ── 2. SESSION TRACKING — write/update the sessions table ────────
 * Records an active session row so admins can see who is logged in
 * and so concurrent-session limits can be enforced.
 */
function trackSession(int $userId, string $ip): void {
    try {
        $db        = getDB();
        $sessionId = session_id();
        if (!$sessionId) return;
        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 300);
        $db->prepare(
            "INSERT INTO sessions (session_id, user_id, ip_address, user_agent, last_active, created_at)
             VALUES (?, ?, ?, ?, NOW(), NOW())
             ON DUPLICATE KEY UPDATE ip_address = VALUES(ip_address), last_active = NOW()"
        )->execute([$sessionId, $userId, $ip, $ua]);
    } catch (\Throwable $e) {
        error_log('trackSession error: ' . $e->getMessage());
    }
}

/* ── 3. CONCURRENT SESSION LIMIT ──────────────────────────────────
 * Allow at most $maxSessions active sessions per user.
 * Kills the oldest sessions when the limit is exceeded.
 * Call right after login, before redirecting.
 */
function enforceConcurrentSessionLimit(int $userId, int $maxSessions = 3): void {
    try {
        $db = getDB();
        // Clean stale sessions first (inactive > 2 hours)
        $db->prepare(
            "DELETE FROM sessions WHERE user_id = ? AND last_active < DATE_SUB(NOW(), INTERVAL 2 HOUR)"
        )->execute([$userId]);

        // Count remaining active sessions (excluding the current one)
        $currentSid = session_id();
        $stmt = $db->prepare(
            "SELECT session_id FROM sessions
             WHERE user_id = ? AND session_id != ?
             ORDER BY last_active ASC"
        );
        $stmt->execute([$userId, $currentSid]);
        $sessions = $stmt->fetchAll();

        $excess = count($sessions) - ($maxSessions - 1);
        if ($excess > 0) {
            // Terminate oldest sessions beyond the limit
            $toKill = array_slice($sessions, 0, $excess);
            $ids    = array_column($toKill, 'session_id');
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $db->prepare("DELETE FROM sessions WHERE session_id IN ($placeholders)")->execute($ids);
            logSecurityEvent('concurrent_session_limit', [
                'user_id'        => $userId,
                'sessions_killed' => count($toKill),
            ]);
        }
    } catch (\Throwable $e) {
        error_log('enforceConcurrentSessionLimit error: ' . $e->getMessage());
    }
}

/* ── 4. AUTO-BLOCK IP AFTER REPEATED DOWNLOAD FAILURES ────────────
 * If a single IP racks up $threshold download failures within the
 * last $windowMinutes minutes, add it to blocked_ips automatically.
 */
function autoBlockIpOnDownloadAbuse(string $ip, int $threshold = 10, int $windowMinutes = 15): void {
    try {
        $db = getDB();
        $stmt = $db->prepare(
            "SELECT COUNT(*) FROM download_failures
             WHERE ip_address = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)"
        );
        $stmt->execute([$ip, $windowMinutes]);
        $count = (int)$stmt->fetchColumn();

        if ($count >= $threshold) {
            // Check not already blocked
            $already = $db->prepare(
                "SELECT id FROM blocked_ips WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1"
            );
            $already->execute([$ip]);
            if (!$already->fetch()) {
                $db->prepare(
                    "INSERT INTO blocked_ips (ip_address, reason, expires_at)
                     VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))"
                )->execute([$ip, "Auto-blocked: {$count} download failures in {$windowMinutes} min"]);
                logSecurityEvent('ip_auto_blocked_download_abuse', [
                    'ip'      => $ip,
                    'count'   => $count,
                    'window'  => $windowMinutes,
                ]);
            }
        }
    } catch (\Throwable $e) {
        error_log('autoBlockIpOnDownloadAbuse error: ' . $e->getMessage());
    }
}

/* ── 5. SINGLE-USE PASSWORD RESET TOKEN (race-condition safe) ──────
 * Atomically claims a reset token by clearing it in the same query
 * that verifies it, so two simultaneous requests cannot both succeed.
 * Returns the user row on success, null on failure.
 */
function claimPasswordResetToken(string $token): ?array {
    if (strlen($token) < 32) return null;
    try {
        $db = getDB();
        // Fetch and immediately null the token in one round-trip
        $stmt = $db->prepare(
            "SELECT id, email, full_name FROM users
             WHERE reset_token = ? AND reset_token_expiry > NOW()
             LIMIT 1"
        );
        $stmt->execute([$token]);
        $user = $stmt->fetch() ?: null;
        if ($user) {
            // Invalidate the token immediately so it cannot be replayed
            $db->prepare(
                "UPDATE users SET reset_token = NULL, reset_token_expiry = NULL WHERE id = ? AND reset_token = ?"
            )->execute([(int)$user['id'], $token]);
        }
        return $user;
    } catch (\Throwable $e) {
        error_log('claimPasswordResetToken error: ' . $e->getMessage());
        return null;
    }
}

/* ── 6. RE-AUTHENTICATION CHECK ────────────────────────────────────
 * For sensitive actions (password change, document deletion, etc.)
 * require the user to have authenticated within the last $maxAge seconds.
 * Returns true if re-auth is needed, false if still fresh.
 *
 * Usage:
 *   if (reAuthRequired()) {
 *       header('Location: /auth/reauth.php?next=' . urlencode($_SERVER['REQUEST_URI']));
 *       exit;
 *   }
 */
function reAuthRequired(int $maxAge = 300): bool {
    $lastAuth = $_SESSION['_last_auth_at'] ?? 0;
    return (time() - (int)$lastAuth) > $maxAge;
}

function markReAuthenticated(): void {
    $_SESSION['_last_auth_at'] = time();
}

/* ── 7. TIMING-SAFE EMAIL EXISTENCE CHECK ──────────────────────────
 * Always spend roughly the same time whether the email exists or not,
 * preventing user-enumeration via timing attacks on the forgot-password
 * and registration endpoints.
 */
function timingSafeEmailLookup(string $email): ?array {
    try {
        $db   = getDB();
        $stmt = $db->prepare("SELECT id, full_name, email, status FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1");
        $stmt->execute([$email]);
        $user = $stmt->fetch() ?: null;
    } catch (\Throwable) {
        $user = null;
    }
    // Always run a dummy bcrypt operation to equalise timing
    // whether the email was found or not
    password_verify('dummy_timing_pad', '$2y$12$invalidhashpaddingtomatchbcryptlengthXXXXXXXXXXXXXXXXXX');
    return $user;
}

/* ── 8. SENSITIVE ACTION RATE LIMITER ──────────────────────────────
 * Stricter rate limit for sensitive write actions (password change,
 * document delete, admin actions).  Separate from the login limiter.
 * Returns true if the action should be blocked.
 */
function sensitiveActionRateLimited(string $actionKey, int $maxPerHour = 10): bool {
    if (!function_exists('rateLimitExceeded')) return false;
    return rateLimitExceeded('sensitive:' . $actionKey, $maxPerHour, 3600);
}

/* ── 9. SECURITY SUMMARY FOR USER ─────────────────────────────────
 * Returns an array of recent security events for a given user,
 * used to populate a "Recent Activity" section on their profile page.
 */
function getUserSecuritySummary(int $userId, int $limit = 10): array {
    try {
        $db = getDB();
        $stmt = $db->prepare(
            "SELECT action, ip_address, user_agent, created_at
             FROM audit_log
             WHERE user_id = ?
               AND action IN ('login_success','login_failed','logout',
                              'password_changed','document_uploaded','document_downloaded',
                              'timesheet_submitted','rate_limit_login')
             ORDER BY created_at DESC
             LIMIT ?"
        );
        $stmt->execute([$userId, $limit]);
        return $stmt->fetchAll() ?: [];
    } catch (\Throwable) {
        return [];
    }
}

/* ── 10. SESSIONS TABLE USER-AGENT COLUMN GUARD ───────────────────
 * Alter the sessions table to add user_agent if it does not already
 * exist (safe to call multiple times; no-ops after first run).
 */
function ensureSessionsTableHasUserAgent(): void {
    try {
        $db = getDB();
        $check = $db->prepare(
            "SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sessions' AND COLUMN_NAME = 'user_agent'"
        );
        $check->execute();
        if ((int)$check->fetchColumn() === 0) {
            $db->exec("ALTER TABLE sessions ADD COLUMN user_agent VARCHAR(300) NULL AFTER ip_address");
        }
    } catch (\Throwable) { /* non-fatal */ }
}
