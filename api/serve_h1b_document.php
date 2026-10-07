<?php
/**
 * CloudFen - H1B Document Serving Endpoint
 * All authenticated roles may view/download (upload stays HR/Admin-only,
 * enforced in employee/h1b_documents.php). Signed, time-limited tokens —
 * same pattern as api/serve_employee_project_document.php.
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';

sendSecurityHeaders(true);
sendNoCacheHeaders();
startSecureSession();
checkIpBlock();

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    exit(json_encode(['success' => false, 'message' => 'Unauthenticated.']));
}

$userId = (int)$_SESSION['user_id'];

$rlKey  = 'h1b_dl_' . $userId;
$window = 60;
$maxDl  = defined('SECURE_DL_RATE_LIMIT') ? (int)SECURE_DL_RATE_LIMIT : 30;
$now    = time();

$_SESSION['_h1b_dl_timestamps'] = array_filter(
    $_SESSION['_h1b_dl_timestamps'] ?? [],
    fn($t) => ($now - $t) < $window
);
if (count($_SESSION['_h1b_dl_timestamps']) >= $maxDl) {
    http_response_code(429);
    exit(json_encode(['success' => false, 'message' => 'Download rate limit exceeded. Please wait.']));
}
$_SESSION['_h1b_dl_timestamps'][] = $now;

$docId = filter_input(INPUT_GET, 'doc_id', FILTER_VALIDATE_INT);
$ts    = filter_input(INPUT_GET, 'ts', FILTER_VALIDATE_INT);
$token = trim($_GET['token'] ?? '');

if (!$docId || !$ts || strlen($token) !== 64) {
    auditLog('h1b_document_failed', 'h1b_documents', $docId ?: null, ['reason' => 'invalid_params']);
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Invalid request.']));
}

$ttl = defined('SECURE_DL_TOKEN_TTL') ? (int)SECURE_DL_TOKEN_TTL : 900;
if (($now - $ts) > $ttl) {
    auditLog('h1b_document_failed', 'h1b_documents', $docId, ['reason' => 'token_expired']);
    http_response_code(403);
    exit(json_encode(['success' => false, 'message' => 'Download link has expired. Please refresh the page.']));
}

$expected = generateDocToken($docId, $userId, $ts);
if (!hash_equals($expected, $token)) {
    auditLog('h1b_document_failed', 'h1b_documents', $docId, ['reason' => 'invalid_token']);
    http_response_code(403);
    exit(json_encode(['success' => false, 'message' => 'Invalid or tampered download link.']));
}

$db = getDB();
$stmt = $db->prepare("SELECT * FROM h1b_documents WHERE id = ? LIMIT 1");
$stmt->execute([$docId]);
$doc = $stmt->fetch();

if (!$doc) {
    auditLog('h1b_document_failed', 'h1b_documents', $docId, ['reason' => 'not_found']);
    http_response_code(404);
    exit(json_encode(['success' => false, 'message' => 'Document not found.']));
}

$uploadBase = realpath(getUploadBasePath());
$realPath   = realpath($doc['file_path']);
$uploadRoot = $uploadBase ? rtrim($uploadBase, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR : '';

if ($realPath === false || !$uploadBase || ($realPath !== $uploadBase && strpos($realPath, $uploadRoot) !== 0) || !is_file($realPath)) {
    auditLog('h1b_document_failed', 'h1b_documents', $docId, ['reason' => 'path_invalid']);
    http_response_code(404);
    exit(json_encode(['success' => false, 'message' => 'File not found on server.']));
}

if (!empty($doc['file_hash'])) {
    $actualHash = hash_file('sha256', $realPath);
    if (!hash_equals((string)$doc['file_hash'], $actualHash)) {
        auditLog('h1b_document_failed', 'h1b_documents', $docId, ['reason' => 'integrity_fail']);
        http_response_code(500);
        exit(json_encode(['success' => false, 'message' => 'File integrity check failed. Contact administrator.']));
    }
}

$allowedMimes = allowedH1bDocumentMimeTypes();
$safeMime     = array_key_exists((string)$doc['mime_type'], $allowedMimes)
    ? (string)$doc['mime_type']
    : 'application/octet-stream';
$isDownload   = (isset($_GET['download']) && $_GET['download'] === '1') || (isset($_GET['dl']) && $_GET['dl'] === '1');
$safeName     = preg_replace('/[^a-zA-Z0-9._\-]/', '_', basename((string)($doc['file_name'] ?? basename($realPath))));

auditLog($isDownload ? 'h1b_document_downloaded' : 'h1b_document_viewed', 'h1b_documents', $docId, [
    'document_name' => (string)$doc['document_name'],
]);

header('Content-Type: ' . $safeMime);
header('Content-Disposition: ' . ($isDownload ? 'attachment' : 'inline') . '; filename="' . $safeName . '"');
header('Content-Length: ' . filesize($realPath));
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
header('Expires: 0');

readfile($realPath);
exit;
