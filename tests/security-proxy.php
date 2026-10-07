<?php
define('TRUSTED_PROXIES', ['10.0.0.8']);
require_once __DIR__ . '/../includes/security.php';

function assertSecureRequest(bool $expected, string $scenario): void
{
    if (isSecureRequest() !== $expected) {
        throw new RuntimeException('Secure request detection failed: ' . $scenario);
    }
}

$_SERVER = ['REMOTE_ADDR' => '198.51.100.24', 'HTTP_X_FORWARDED_PROTO' => 'https'];
assertSecureRequest(false, 'untrusted forwarded protocol');

$_SERVER = ['REMOTE_ADDR' => '198.51.100.24', 'HTTP_CF_VISITOR' => '{"scheme":"https"}'];
assertSecureRequest(false, 'untrusted Cloudflare metadata');

$_SERVER = ['REMOTE_ADDR' => '10.0.0.8', 'HTTP_X_FORWARDED_PROTO' => 'https'];
assertSecureRequest(true, 'trusted forwarded protocol');

$_SERVER = ['REMOTE_ADDR' => '10.0.0.8', 'HTTP_X_FORWARDED_SSL' => 'on'];
assertSecureRequest(true, 'trusted forwarded SSL');

$_SERVER = ['REMOTE_ADDR' => '198.51.100.24', 'HTTPS' => 'on'];
assertSecureRequest(true, 'direct HTTPS connection');

echo "PASS trusted proxy and direct HTTPS detection\n";
