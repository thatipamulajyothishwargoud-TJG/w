<?php
/**
 * CloudFen HR Portal - Web Cron Runner (PHP 8.2)
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';

$startTime = microtime(true);
$ip        = filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: 'unknown';
$submittedToken = trim($_GET['token'] ?? '');

if ($submittedToken === '') {
    http_response_code(403);
    die('Forbidden');
}

try {
    $db = getDB();

    $secretStmt = $db->prepare(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'cron_secret' LIMIT 1"
    );
    $secretStmt->execute();
    $storedSecret = (string)($secretStmt->fetchColumn() ?? '');

    if ($storedSecret === '' || $storedSecret === 'CHANGE_THIS_SECRET_BEFORE_GOING_LIVE') {
        http_response_code(500);
        die('Cron secret not configured. Set it in Admin -> Automated Tasks.');
    }

    if (!hash_equals($storedSecret, $submittedToken)) {
        auditLog('cron_invalid_token', 'cron', null, ['ip' => $ip]);
        http_response_code(403);
        die('Forbidden');
    }
} catch (\Throwable $ex) {
    http_response_code(500);
    error_log('CloudFen cron setup error: ' . $ex->getMessage());
    die('Setup error. Check error log.');
}

$lockAcquired = false;
try {
    $lockStmt = $db->query("SELECT GET_LOCK('cloudfen_daily_runner', 1)");
    $lockAcquired = ((int)$lockStmt->fetchColumn() === 1);
} catch (\Throwable $ex) {
    http_response_code(500);
    error_log('CloudFen cron lock error: ' . $ex->getMessage());
    die('Cron lock error. Check error log.');
}

if (!$lockAcquired) {
    http_response_code(409);
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'skipped',
        'reason' => 'Another cron run is already in progress.',
    ]);
    exit;
}

try {
    $lastRunStmt = $db->query("SELECT ran_at FROM cron_log ORDER BY ran_at DESC LIMIT 1");
    $lastRun     = $lastRunStmt->fetchColumn();

    if ($lastRun && (time() - strtotime($lastRun)) < 1800) {
        http_response_code(200);
        header('Content-Type: application/json');
        echo json_encode([
            'status'   => 'skipped',
            'reason'   => 'Already ran recently (within 30 min)',
            'last_run' => $lastRun,
        ]);
        exit;
    }

    $triggeredBy = match (true) {
        !empty($_GET['manual']) => 'manual_hr',
        ($_GET['trigger'] ?? '') === 'pseudo' => 'pseudo_cron',
        default => 'web_hook',
    };

    define('CLOUDFEN_CRON_AUTHORIZED', true);

    try {
        $result = require __DIR__ . '/daily.php';
    } catch (\Throwable $ex) {
        $result = [
            'tasks'       => [],
            'emails_sent' => 0,
            'errors'      => ['Fatal error: ' . $ex->getMessage()],
        ];
    }

    $durationMs = (int)round((microtime(true) - $startTime) * 1000);

    try {
        $db->prepare(
            "INSERT INTO cron_log (triggered_by, triggered_ip, tasks_run, emails_sent, errors, duration_ms)
             VALUES (?, ?, ?, ?, ?, ?)"
        )->execute([
            $triggeredBy,
            $ip,
            json_encode($result['tasks'] ?? []),
            (int)($result['emails_sent'] ?? 0),
            !empty($result['errors']) ? json_encode($result['errors']) : null,
            $durationMs,
        ]);
    } catch (\Throwable $ex) {
        error_log('cron_log insert failed: ' . $ex->getMessage());
    }

    auditLog('cron_ran', 'cron', null, [
        'triggered_by' => $triggeredBy,
        'tasks'        => count($result['tasks'] ?? []),
        'emails'       => $result['emails_sent'] ?? 0,
        'errors'       => count($result['errors'] ?? []),
        'ip'           => $ip,
    ]);

    http_response_code(200);
    header('Content-Type: application/json');
    echo json_encode([
        'status'       => empty($result['errors']) ? 'ok' : 'completed_with_errors',
        'triggered_by' => $triggeredBy,
        'tasks'        => $result['tasks'] ?? [],
        'emails_sent'  => $result['emails_sent'] ?? 0,
        'errors'       => $result['errors'] ?? [],
        'duration_ms'  => $durationMs,
        'ran_at'       => date('Y-m-d H:i:s'),
    ]);
} finally {
    try {
        if ($lockAcquired) {
            $db->query("DO RELEASE_LOCK('cloudfen_daily_runner')");
        }
    } catch (\Throwable) {
        // Non-fatal
    }
}
