<?php
// Environment variables are supplied by the host, never committed secrets.
$defaults = ['APP_NAME'=>'CloudFen HR Workspace','APP_URL'=>'','DB_HOST'=>'127.0.0.1','DB_NAME'=>'hrportal','DB_USER'=>'hrportal','DB_PASS'=>'','DB_CHARSET'=>'utf8mb4','SESSION_LIFETIME'=>1800,'SESSION_WARN'=>300,'MAX_DOC_SIZE'=>10485760,'MAX_POST_BYTES'=>23068672,'JWT_SECRET'=>'','MAIL_FROM'=>'','MAIL_FROM_NAME'=>'CloudFen HR','SMTP_HOST'=>'','SMTP_USERNAME'=>'','SMTP_PASSWORD'=>'','SMTP_PORT'=>587,'SMTP_ENCRYPTION'=>'tls','UPLOAD_BASE_PATH'=>dirname(__DIR__,2).'/hrportal-private/uploads'];
foreach ($defaults as $key=>$fallback) { $value=getenv($key); define($key,$value===false?$fallback:(is_int($fallback)?(int)$value:$value)); }
define('DB_PORT', (int)(getenv('DB_PORT') ?: 3306));
define('APP_DEMO_MODE', filter_var(getenv('APP_DEMO_MODE') ?: 'false', FILTER_VALIDATE_BOOLEAN));
date_default_timezone_set(getenv('APP_TIMEZONE') ?: 'UTC');
ini_set('display_errors','0'); ini_set('log_errors','1');
$missingProductionConfig = strlen(JWT_SECRET) < 32 || DB_PASS === '';
if ($missingProductionConfig && !APP_DEMO_MODE) {
    http_response_code(503);
    exit('Workspace setup is required. Configure the database credentials and a random JWT_SECRET of at least 32 characters.');
}
// A showcase deployment intentionally has no database. Keep the UI available
// while making it explicit to the templates that writes and authentication are disabled.
define('APP_STATIC_PREVIEW', $missingProductionConfig && APP_DEMO_MODE);
