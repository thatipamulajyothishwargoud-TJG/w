<?php
/**
 * CloudFen — Config Loader
 *
 * SECURITY: The real config.php lives OUTSIDE public_html so it can never
 * be downloaded by a web request, even if Apache/PHP fails.
 *
 * On Turbify your directory structure should be:
 *   /home/YOUR_ACCOUNT/
 *       cf_config/          <-- put real config.php here (NOT in public_html)
 *           config.php
 *       public_html/
 *           hrportal/
 *               config/
 *                   config.php  <-- this loader file (safe to be here)
 *
 * Upload cf_config/config.php to /home/YOUR_ACCOUNT/cf_config/config.php
 */

// Walk up from this file to find the account home directory
// __DIR__ = /home/YOUR_ACCOUNT/public_html/hrportal/config
// Three levels up = /home/YOUR_ACCOUNT
$accountRoot = dirname(dirname(dirname(dirname(__FILE__))));
$configCandidates = [
    $accountRoot . '/cf_config/config.php'
];
$realConfig = null;
foreach ($configCandidates as $candidate) {
    if (file_exists($candidate)) {
        $realConfig = $candidate;
        break;
    }
}

if ($realConfig === null) {
    // Fallback error — never expose path details to browser
    require_once __DIR__ . '/environment.php';
    return;
}

require_once $realConfig;
