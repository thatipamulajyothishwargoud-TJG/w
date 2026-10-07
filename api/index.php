<?php
/**
 * Vercel front controller for the existing PHP portal.
 * The community PHP runtime invokes this file, while the requested path is
 * forwarded in the `path` query parameter by vercel.json.
 */

$root = realpath(__DIR__ . '/..');
$requestPath = (string)($_GET['path'] ?? parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/');
$requestPath = '/' . ltrim(rawurldecode($requestPath), '/');

// Keep deployment internals and private project files unreachable.
if ($requestPath === '' || str_contains($requestPath, '..') || preg_match('#(^|/)(?:\.|config|tools|tests|vendor|cron|deploy)(?:/|$)#i', $requestPath)) {
    http_response_code(404);
    exit('Not found');
}

if ($requestPath === '/') {
    $requestPath = '/index.php';
}

$target = realpath($root . $requestPath);
$rootPrefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

if ($target === false || !is_file($target) || !str_starts_with($target, $rootPrefix)) {
    http_response_code(404);
    exit('Page not found');
}

// Only PHP pages are executed by this function. Assets are served directly
// by Vercel and should never be interpreted as server-side code here.
if (strtolower(pathinfo($target, PATHINFO_EXTENSION)) !== 'php') {
    http_response_code(404);
    exit('Not found');
}

require $target;
