<?php
/**
 * CloudFen - Document Access Redirector
 * Validates access, then redirects to the signed document-serving endpoint.
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';

sendSecurityHeaders(true);   // allow same-origin iframe (document preview)
sendNoCacheHeaders();
$user = requireLogin();
$db   = getDB();

$docId = sanitizeInt($_GET['id'] ?? 0, 1);
if (!$docId) {
    http_response_code(400);
    die('Invalid document ID.');
}

$stmt = $db->prepare(
    "SELECT d.id, d.user_id, u.role AS owner_role
     FROM documents d
     JOIN users u ON u.id = d.user_id
     WHERE d.id = ?
     LIMIT 1"
);
$stmt->execute([$docId]);
$doc = $stmt->fetch();

if (!$doc) {
    http_response_code(404);
    die('Document not found.');
}

$isOwner      = (int)$doc['user_id'] === (int)$user['id'];
$isSuperAdmin = $user['role'] === 'super_admin';
$isHrAdmin    = $user['role'] === 'hr_admin';
// hr_admin reviews employee AND peer hr_admin onboarding docs (same scoping as
// the compliance queue in admin/documents.php) — only a super_admin's own
// documents are out of another hr_admin's reach.
$ownerIsSuperAdmin = $doc['owner_role'] === 'super_admin';
$authorized   = $isOwner || $isSuperAdmin || ($isHrAdmin && !$ownerIsSuperAdmin);
if (!$authorized) {
    auditLog('unauthorized_doc_access', 'documents', $docId, [
        'attempted_by' => $user['id'],
        'owner'        => $doc['user_id'],
    ]);
    http_response_code(403);
    die('Access denied.');
}

$download = isset($_GET['dl']) && $_GET['dl'] === '1';
$targetUrl = getDocumentServeUrl($docId, (int)$user['id'], $download);
header('Location: ' . $targetUrl, true, 302);
exit;
