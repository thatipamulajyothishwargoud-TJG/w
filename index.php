<?php
ob_start();

ini_set('display_errors', 0);
ini_set('log_errors',     1);
error_reporting(E_ALL);

// CloudFen HR Portal — Entry Point (PHP 8.2)
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/security.php';

startSecureSession();

// Showcase deployments are intentionally database-free. Route them before the
// normal pseudo-cron and authenticated-home logic can request a database.
if (defined('APP_STATIC_PREVIEW') && APP_STATIC_PREVIEW) {
    require __DIR__ . '/preview-dashboard.php';
    exit;
}

// ── Pseudo-cron: fire background tasks on page visits (no cPanel cron needed) ──
// This is a non-blocking background call — visitors never feel any delay.
maybeTriggerPseudoCron();

require __DIR__.'/includes/reference-home.php';
