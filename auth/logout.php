<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/security_headers.php';

// Only accept POST — prevents logout CSRF via image tags / links
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /auth/login.php');
    exit;
}

startSecureSession();

// If session already expired / user not logged in — nothing to log out
// Silently redirect to login instead of showing a CSRF error
if (empty($_SESSION['user_id'])) {
    header('Location: /auth/login.php');
    exit;
}

verifyCsrfToken();

$userId = $_SESSION['user_id'] ?? null;
if ($userId) {
    auditLog('logout', 'users', (int)$userId);
}

// ── Clear browser cache, cookies, and storage for this origin ──────────
// Instructs modern browsers to wipe any stored data so a subsequent user
// on the same device cannot access cached pages or local storage.
clearSiteData();

// Destroy session completely
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $p['path'], $p['domain'], $p['secure'], $p['httponly']);
}
session_destroy();

header('Location: /auth/login.php');
exit;
