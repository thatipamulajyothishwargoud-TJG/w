<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';

sendSecurityHeaders();
header('Content-Type: application/json');
header('Cache-Control: no-store, no-cache');

if (empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    http_response_code(403);
    echo json_encode(['error' => 'Forbidden']);
    exit;
}

startSecureSession();

if (empty($_SESSION['user_id'])) {
    echo json_encode(['count' => 0]);
    exit;
}

// Release session lock so other requests aren't blocked
session_write_close();

try {
    $db   = getDB();
    $stmt = $db->prepare("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0");
    $stmt->execute([(int)$_SESSION['user_id']]);
    $count = (int)$stmt->fetchColumn();
    echo json_encode(['count' => $count, 'ts' => time()]);
} catch (\Throwable $e) {
    echo json_encode(['count' => 0]);
}
