<?php
/**
 * CloudFen HR Portal — Timesheet Attachment Download
 * Path: /api/download_attachment.php
 *
 * Access rules:
 *   - employee      : own attachments only
 *   - hr_admin      : any attachment (read-only, for review/approval workflow)
 *   - super_admin   : any attachment + delete
 *
 * Security hardened (v3.2):
 *   - Path-traversal guard: realpath() verified inside UPLOAD_BASE_PATH
 *   - mime_type header taken from allow-list, NOT raw DB value
 *   - Audit log on every download
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';

sendSecurityHeaders();
sendNoCacheHeaders();
startSecureSession();
$user   = requireAnyRole();
$db     = getDB();
$userId = (int)$user['id'];
$role   = $user['role'];
$isSA   = ($role === 'super_admin');
$isHR   = ($role === 'hr_admin');

$attId = (int)($_GET['id'] ?? 0);
if (!$attId) { http_response_code(400); die('Invalid request.'); }

$window = 60;
$maxDl  = defined('SECURE_DL_RATE_LIMIT') ? (int)SECURE_DL_RATE_LIMIT : 30;
$now    = time();
$_SESSION['_attachment_dl_timestamps'] = array_filter(
    $_SESSION['_attachment_dl_timestamps'] ?? [],
    fn($t) => ($now - $t) < $window
);
if (count($_SESSION['_attachment_dl_timestamps']) >= $maxDl) {
    http_response_code(429);
    die('Download rate limit exceeded. Please wait.');
}
$_SESSION['_attachment_dl_timestamps'][] = $now;

// Load attachment + owner info
$stmt = $db->prepare(
    "SELECT ta.*, t.user_id AS owner_id
     FROM timesheet_attachments ta
     JOIN timesheets t ON t.id = ta.timesheet_id
     WHERE ta.id = ? LIMIT 1"
);
$stmt->execute([$attId]);
$att = $stmt->fetch();

if (!$att) { http_response_code(404); die('File not found.'); }

// ── Access control ──────────────────────────────────────────
// super_admin and hr_admin can view all; employees only their own
if (!$isSA && !$isHR && (int)$att['owner_id'] !== $userId) {
    http_response_code(403); die('Not authorized.');
}

// ── Path-traversal guard ────────────────────────────────────
$uploadBase = getUploadBasePath();
$realPath   = realpath($att['file_path']);
$realBase   = realpath($uploadBase);

$uploadRoot = $realBase ? rtrim($realBase, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR : '';
if ($realPath === false || $realBase === false || ($realPath !== $realBase && strpos($realPath, $uploadRoot) !== 0)) {
    error_log('CloudFen: path-traversal attempt or missing file. att_id=' . $attId . ' path=' . $att['file_path']);
    http_response_code(403); die('Access denied.');
}

if (!is_readable($realPath)) {
    http_response_code(404); die('File missing from disk. Contact admin.');
}

// ── MIME type from safe allow-list (never trust raw DB value in header) ──
$safeTypes = [
    'application/pdf' => 'application/pdf',
    'image/jpeg'      => 'image/jpeg',
    'image/png'       => 'image/png',
];
$contentType = $safeTypes[$att['mime_type']] ?? 'application/octet-stream';

// ── Safe filename (strip non-ASCII and dangerous chars) ─────
$safeName = preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', basename($att['file_name']));
if (empty($safeName)) { $safeName = 'attachment_' . $attId; }

$isView      = isset($_GET['view']) && $_GET['view'] === '1';
$disposition = $isView ? 'inline' : 'attachment';
$auditAction = $isView ? 'attachment_viewed' : 'attachment_downloaded';

header('Content-Type: ' . $contentType);
header('Content-Disposition: ' . $disposition . '; filename="' . $safeName . '"');
header('Content-Length: ' . filesize($realPath));
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Cache-Control: private, no-cache, no-store');
header('Pragma: no-cache');

auditLog($auditAction, 'timesheet_attachments', $attId);
readfile($realPath);
exit;
