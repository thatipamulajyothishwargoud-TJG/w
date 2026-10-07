<?php
/**
 * CloudFen HR Portal — Real-Time Notification Stream (SSE)
 *
 * Pushes events every 3 seconds:
 *   • notification  — unread count + new notification rows (ALL roles)
 *   • dashboard     — live queue/stat data tailored to the user's role:
 *       HR/Super Admin → pending doc counts, doc queue, timesheet queue
 *       Employee       → own doc statuses, unread count, recent notifications feed
 *
 * CRITICAL: session_write_close() is called immediately after reading session
 * data so this long-running script never blocks other page requests.
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';

const MAX_RUNTIME = 55;
const SLEEP_SEC   = 3;

// ── SSE headers ──────────────────────────────────────────────
header('Content-Type: text/event-stream');
header('Cache-Control: no-store, no-cache');
header('X-Accel-Buffering: no');
header('Connection: keep-alive');
header('Content-Encoding: none');

if (function_exists('apache_setenv')) @apache_setenv('no-gzip', 1);
@ini_set('output_buffering', 'off');
@ini_set('zlib.output_compression', false);
while (ob_get_level()) ob_end_flush();
ob_implicit_flush(true);

// Push an initial padding block so proxies/buffers flush SSE immediately.
echo ":" . str_repeat(' ', 2048) . "\n";
echo "retry: 2000\n\n";
flush();

// ── Auth ─────────────────────────────────────────────────────
startSecureSession();

if (empty($_SESSION['user_id'])) {
    echo "event: auth\ndata: {\"error\":\"unauthenticated\"}\n\n";
    flush();
    exit;
}

$userId   = (int)$_SESSION['user_id'];
$userRole = $_SESSION['role'] ?? 'employee';
$isAdmin  = in_array($userRole, ['hr_admin', 'super_admin'], true);
$isEmp    = ($userRole === 'employee');

// Release session lock immediately — critical for SSE
session_write_close();

// ── Helpers ──────────────────────────────────────────────────
function sendSSE(string $event, array $payload): void {
    echo "event: {$event}\n";
    echo "data: " . json_encode($payload) . "\n\n";
    flush();
}

// ── DB ───────────────────────────────────────────────────────
try {
    $db = getDB();
} catch (\Throwable $e) {
    sendSSE('error', ['message' => 'DB unavailable']);
    exit;
}

// ── State ────────────────────────────────────────────────────
$startTime    = time();
$lastCount    = -1;
$lastEventId  = 0;
$lastDashHash = '';

if (!empty($_SERVER['HTTP_LAST_EVENT_ID'])) {
    $lastEventId = (int)$_SERVER['HTTP_LAST_EVENT_ID'];
}

sendSSE('connected', ['uid' => $userId, 'role' => $userRole, 'ts' => time()]);

// ── Main loop ────────────────────────────────────────────────
while (true) {
    if ((time() - $startTime) >= MAX_RUNTIME) {
        sendSSE('reconnect', ['reason' => 'keepalive']);
        exit;
    }
    if (connection_aborted()) exit;

    try {
        // ── 1. Notifications (all roles) ──────────────────────
        $cntStmt = $db->prepare("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0");
        $cntStmt->execute([$userId]);
        $count = (int)$cntStmt->fetchColumn();

        $newStmt = $db->prepare(
            "SELECT id, type, title, message, link, created_at
             FROM notifications
             WHERE user_id=? AND id > ?
             ORDER BY id ASC LIMIT 10"
        );
        $newStmt->execute([$userId, $lastEventId]);
        $newRows = $newStmt->fetchAll(\PDO::FETCH_ASSOC);

        if ($count !== $lastCount || !empty($newRows)) {
            $maxId = $lastEventId;
            foreach ($newRows as $row) {
                if ((int)$row['id'] > $maxId) $maxId = (int)$row['id'];
            }
            echo "id: {$maxId}\n";
            sendSSE('notification', [
                'count' => $count,
                'new'   => array_values($newRows),
                'ts'    => time(),
            ]);
            $lastCount   = $count;
            if ($maxId > $lastEventId) $lastEventId = $maxId;
        }

        // ── 2. Dashboard data (role-specific) ─────────────────
        if ($isAdmin) {
            // HR / Super Admin — pending queues
            $pending_docs       = (int)$db->query("SELECT COUNT(*) FROM documents WHERE status='pending'")->fetchColumn();
            $pending_timesheets = (int)$db->query("SELECT COUNT(*) FROM timesheets WHERE status='pending'")->fetchColumn();
            $overtime_pending   = (int)$db->query("SELECT COUNT(*) FROM timesheets WHERE status='pending' AND is_overtime=1")->fetchColumn();
            $active_employees   = (int)$db->query("SELECT COUNT(*) FROM users WHERE role='employee' AND status='active'")->fetchColumn();

            $docQueue = $db->query(
                "SELECT d.id, d.doc_type, d.uploaded_at, u.full_name
                 FROM documents d JOIN users u ON u.id=d.user_id
                 WHERE d.status='pending'
                 ORDER BY d.uploaded_at ASC LIMIT 8"
            )->fetchAll(\PDO::FETCH_ASSOC);

            $tsQueue = $db->query(
                "SELECT t.id, t.week_start, t.total_hours, t.is_overtime, u.full_name
                 FROM timesheets t JOIN users u ON u.id=t.user_id
                 WHERE t.status='pending'
                 ORDER BY t.submitted_at ASC LIMIT 8"
            )->fetchAll(\PDO::FETCH_ASSOC);

            $dashData = [
                'role'               => 'admin',
                'pending_docs'       => $pending_docs,
                'pending_timesheets' => $pending_timesheets,
                'overtime_pending'   => $overtime_pending,
                'active_employees'   => $active_employees,
                'doc_queue'          => $docQueue,
                'ts_queue'           => $tsQueue,
                'ts'                 => time(),
            ];

        } elseif ($isEmp) {
            // Employee — their own doc statuses + recent notifications
            $docStmt = $db->prepare(
                "SELECT status, COUNT(*) as cnt FROM documents WHERE user_id=? GROUP BY status"
            );
            $docStmt->execute([$userId]);
            $docStats = array_column($docStmt->fetchAll(\PDO::FETCH_ASSOC), 'cnt', 'status');

            $tsStmt = $db->prepare(
                "SELECT status, COUNT(*) as cnt FROM timesheets WHERE user_id=? GROUP BY status"
            );
            $tsStmt->execute([$userId]);
            $tsStats = array_column($tsStmt->fetchAll(\PDO::FETCH_ASSOC), 'cnt', 'status');

            // Recent 5 notifications for the feed panel
            $feedStmt = $db->prepare(
                "SELECT id, type, title, message, link, is_read, created_at
                 FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 5"
            );
            $feedStmt->execute([$userId]);
            $feed = $feedStmt->fetchAll(\PDO::FETCH_ASSOC);

            // Current week timesheet status
            $thisWeek = date('Y-m-d', strtotime('monday this week'));
            $tsNow = $db->prepare("SELECT status, total_hours, is_overtime, rejection_reason FROM timesheets WHERE user_id=? AND week_start=? LIMIT 1");
            $tsNow->execute([$userId, $thisWeek]);
            $currentTs = $tsNow->fetch(\PDO::FETCH_ASSOC) ?: null;

            $dashData = [
                'role'         => 'employee',
                'docs_approved'=> (int)($docStats['approved'] ?? 0),
                'docs_pending' => (int)($docStats['pending']  ?? 0),
                'ts_approved'  => (int)($tsStats['approved']  ?? 0),
                'unread_notifs'=> $count,
                'notif_feed'   => array_values($feed),
                'current_ts'   => $currentTs,
                'ts'           => time(),
            ];
        } else {
            $dashData = null;
        }

        if ($dashData) {
            $dashHash = md5(json_encode($dashData));
            if ($dashHash !== $lastDashHash) {
                sendSSE('dashboard', $dashData);
                $lastDashHash = $dashHash;
            }
        }

        // Heartbeat keeps the stream alive through aggressive intermediaries.
        echo ": ping " . time() . "\n\n";
        flush();

    } catch (\Throwable $e) {
        sendSSE('error', ['message' => 'query failed']);
    }

    sleep(SLEEP_SEC);
}
