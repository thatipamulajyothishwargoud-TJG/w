<?php
require_once __DIR__ . '/config/config.php';

header('Content-Type: text/plain; charset=utf-8');

if (defined('APP_STATIC_PREVIEW') && APP_STATIC_PREVIEW) {
    http_response_code(200);
    echo "ok - static preview\n";
    exit;
}

try {
    $dsn = 'mysql:host=' . DB_HOST . ';port=' . DB_PORT . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;
    $db = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 3,
    ]);
    $db->query('SELECT 1');

    http_response_code(200);
    echo "ok\n";
} catch (Throwable $error) {
    error_log('CloudFen health check failed: ' . $error->getMessage());
    http_response_code(503);
    echo "unavailable\n";
}
