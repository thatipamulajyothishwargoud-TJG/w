<?php
/**
 * CloudFen — Secure Document Serve Endpoint  (v14 — Layer 2)
 *
 * SECURITY CHECKS (in order):
 *   1. Session authentication + role check
 *   2. HMAC-signed, short-lived URL token (15 min TTL)
 *   3. Token expiry
 *   4. Role-based document ownership
 *   5. Path-traversal guard via realpath()
 *   6. SHA-256 file integrity verification
 *   7. MIME type from hard-coded allow-list
 *   8. Session-based rate limit (max 30 downloads/user/minute)
 *   9. Download failure logging (new in v14)
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';

sendSecurityHeaders(true);
sendNoCacheHeaders();
startSecureSession();
checkIpBlock();

/* ── Auth ─────────────────────────────────────────────────── */
if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    exit(json_encode(['success' => false, 'message' => 'Unauthenticated.']));
}
$userId = (int)$_SESSION['user_id'];
$role   = $_SESSION['role'] ?? '';

/* ── Rate limit (session-based, no extra DB query) ────────── */
$rlKey   = 'dl_' . $userId;
$window  = 60;
$maxDl   = defined('SECURE_DL_RATE_LIMIT') ? (int)SECURE_DL_RATE_LIMIT : 30;
$now     = time();
$_SESSION['_dl_timestamps'] = array_filter(
    $_SESSION['_dl_timestamps'] ?? [],
    fn($t) => ($now - $t) < $window
);
if (count($_SESSION['_dl_timestamps']) >= $maxDl) {
    http_response_code(429);
    exit(json_encode(['success' => false, 'message' => 'Download rate limit exceeded. Please wait.']));
}
$_SESSION['_dl_timestamps'][] = $now;

/* ── Input validation ─────────────────────────────────────── */
$docId = filter_input(INPUT_GET, 'doc_id', FILTER_VALIDATE_INT);
$ts    = filter_input(INPUT_GET, 'ts',     FILTER_VALIDATE_INT);
$token = trim($_GET['token'] ?? '');

if (!$docId || !$ts || strlen($token) !== 64) {
    _failDownload($userId, null, 'invalid_params');
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Invalid request.']));
}

/* ── Token expiry ─────────────────────────────────────────── */
$ttl = defined('SECURE_DL_TOKEN_TTL') ? (int)SECURE_DL_TOKEN_TTL : 900;
if (($now - $ts) > $ttl) {
    _failDownload($userId, $docId, 'token_expired');
    http_response_code(403);
    exit(json_encode(['success' => false, 'message' => 'Download link has expired. Please refresh the page.']));
}

/* ── HMAC token verification ──────────────────────────────── */
$expected = generateDocToken($docId, $userId, $ts);
if (!hash_equals($expected, $token)) {
    _failDownload($userId, $docId, 'invalid_token');
    http_response_code(403);
    exit(json_encode(['success' => false, 'message' => 'Invalid or tampered download link.']));
}

/* ── Fetch document record ────────────────────────────────── */
$db   = getDB();
$stmt = $db->prepare("SELECT * FROM documents WHERE id = ? LIMIT 1");
$stmt->execute([$docId]);
$doc  = $stmt->fetch();

if (!$doc) {
    _failDownload($userId, $docId, 'not_found');
    http_response_code(404);
    exit(json_encode(['success' => false, 'message' => 'Document not found.']));
}

/* ── Role-based access control ────────────────────────────── */
$isAdmin = in_array($role, ['hr_admin', 'super_admin'], true);
if (!$isAdmin && (int)$doc['user_id'] !== $userId) {
    _failDownload($userId, $docId, 'access_denied');
    http_response_code(403);
    exit(json_encode(['success' => false, 'message' => 'Access denied.']));
}

/* ── Path traversal guard ─────────────────────────────────── */
$uploadBase = realpath(getUploadBasePath());
$realPath   = realpath($doc['file_path']);

$uploadRoot = $uploadBase ? rtrim($uploadBase, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR : '';
if ($realPath === false || !$uploadBase || ($realPath !== $uploadBase && strpos($realPath, $uploadRoot) !== 0) || !is_file($realPath)) {
    _failDownload($userId, $docId, 'path_invalid');
    http_response_code(404);
    exit(json_encode(['success' => false, 'message' => 'File not found on server.']));
}

/* ── SHA-256 integrity check ──────────────────────────────── */
if (!empty($doc['file_hash'])) {
    $actualHash = hash_file('sha256', $realPath);
    if (!hash_equals($doc['file_hash'], $actualHash)) {
        _failDownload($userId, $docId, 'integrity_fail');
        error_log("CloudFen: file integrity check FAILED for doc_id={$docId}, path={$realPath}");
        http_response_code(500);
        exit(json_encode(['success' => false, 'message' => 'File integrity check failed. Contact administrator.']));
    }
}

/* ── MIME type from allow-list (never trust DB value for headers) */
$allowedMimes = [
    'application/pdf' => 'application/pdf',
    'image/jpeg'      => 'image/jpeg',
    'image/png'       => 'image/png',
];
$safeMime = $allowedMimes[$doc['mime_type']] ?? 'application/octet-stream';

/* ── Audit log the access ─────────────────────────────────── */
$isDownload = (isset($_GET['download']) && $_GET['download'] === '1') || (isset($_GET['dl']) && $_GET['dl'] === '1');
$auditAction = $isDownload ? 'document_downloaded' : 'document_viewed';
auditLog($auditAction, 'documents', $docId, [
    'user_id'   => $userId,
    'doc_type'  => $doc['doc_type'],
    'is_admin'  => $isAdmin,
]);

/* ── Stream the file ──────────────────────────────────────── */
$safeName = preg_replace('/[^a-zA-Z0-9._\-]/', '_', basename($doc['file_name'] ?? basename($realPath)));

header('Content-Type: ' . $safeMime);
header('Content-Disposition: ' . ($isDownload ? 'attachment' : 'inline') . '; filename="' . $safeName . '"');
header('Content-Length: ' . filesize($realPath));
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
header('Expires: 0');

readfile($realPath);
exit;

/* ── Failure logger ───────────────────────────────────────── */
function _failDownload(int $userId, ?int $docId, string $reason): void {
    try {
        $db = getDB();
        $ip = getClientIpSecure();
        $db->prepare(
            "INSERT INTO download_failures (user_id, doc_id, ip_address, reason)
             VALUES (?, ?, ?, ?)"
        )->execute([$userId, $docId, $ip, $reason]);
        // Auto-block IP if it has accumulated too many failures recently
        autoBlockIpOnDownloadAbuse($ip, 10, 15);
    } catch (\Throwable) { /* non-fatal */ }
    auditLog('document_download_failed', 'documents', $docId, [
        'user_id' => $userId,
        'reason'  => $reason,
    ]);
}
