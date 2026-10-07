<?php
/**
 * CloudFen HR Portal — Daily Task Runner
 * 
 * Called internally by cron/runner.php.
 * Can also be triggered manually by HR Admin via admin/cron_status.php.
 * NOT directly web-accessible (blocked by .htaccess on the cron/ folder).
 */

// This file is included by runner.php which handles auth.
// Direct web access is blocked by .htaccess.
if (!defined('CLOUDFEN_CRON_AUTHORIZED')) {
    http_response_code(403);
    die('403 Forbidden');
}

$log        = [];
$emailsSent = 0;
$errors     = [];

function cloudfenBirthdayAlreadySent(PDO $db, int $birthdayUserId, int $recipientUserId, string $sentOn): bool
{
    $stmt = $db->prepare(
        "SELECT id
         FROM birthday_notifications_sent
         WHERE birthday_user_id = ?
           AND recipient_user_id = ?
           AND sent_on = ?
         LIMIT 1"
    );
    $stmt->execute([$birthdayUserId, $recipientUserId, $sentOn]);

    return (bool)$stmt->fetchColumn();
}

function cloudfenMarkBirthdaySent(PDO $db, int $birthdayUserId, int $recipientUserId, string $sentOn): void
{
    $stmt = $db->prepare(
        "INSERT INTO birthday_notifications_sent (birthday_user_id, recipient_user_id, sent_on)
         VALUES (?, ?, ?)"
    );
    $stmt->execute([$birthdayUserId, $recipientUserId, $sentOn]);
}

function cloudfenHasBirthdayNotification(PDO $db, int $userId, string $sentOn): bool
{
    $stmt = $db->prepare(
        "SELECT id
         FROM notifications
         WHERE user_id = ?
           AND type = 'birthday_message'
           AND DATE(created_at) = ?
         LIMIT 1"
    );
    $stmt->execute([$userId, $sentOn]);

    return (bool)$stmt->fetchColumn();
}

// ── 1. Document expiry alerts ────────────────────────────────────────────────
try {
    $expStmt = $db->prepare(
        "SELECT d.id, d.doc_type, d.expiry_date,
                d.expiry_alerted_60, d.expiry_alerted_30,
                u.id AS user_id, u.email, u.full_name
         FROM documents d
         JOIN users u ON u.id = d.user_id
         WHERE d.expiry_date IS NOT NULL
           AND d.status = 'approved'
           AND d.expiry_date >= CURDATE()
           AND d.expiry_date <= DATE_ADD(CURDATE(), INTERVAL 60 DAY)"
    );
    $expStmt->execute();
    $expiringDocs = $expStmt->fetchAll();

    $hrEmails = $db->query(
        "SELECT email FROM users WHERE role IN ('hr_admin','super_admin') AND status = 'active'"
    )->fetchAll(PDO::FETCH_COLUMN);

    $docLabels = array(
        'work_authorization' => 'Work Authorization',
        'h1b_i797'           => 'H-1B Approval',
        'passport'           => 'Passport',
        'drivers_license'    => "Driver's License",
        'social_security'    => 'Social Security Card',
        'education'          => 'Educational Certificate',
        'direct_deposit'     => 'Direct Deposit Form',
        'i9'                 => 'Form I-9',
    );

    foreach ($expiringDocs as $doc) {
        $daysLeft  = (int)floor((strtotime($doc['expiry_date']) - time()) / 86400);
        $label     = $docLabels[$doc['doc_type']] ?? $doc['doc_type'];
        $expiryFmt = date('M j, Y', strtotime($doc['expiry_date']));
        $empName   = $doc['full_name'];

        if ($daysLeft <= 60 && $daysLeft > 30 && !$doc['expiry_alerted_60']) {
            $subject = "Document Expiry: {$label} - 60 Days Remaining";
            $empBody = "<p>Hi " . e($empName) . ",</p>
                        <p>Your <strong>" . e($label) . "</strong> expires in <strong>{$daysLeft} days</strong> ({$expiryFmt}).</p>
                        <p>Please prepare an updated document and upload it to the HR portal.</p>
                        <a href='" . e(APP_URL) . "/employee/documents.php' style='background:#2b8fd4;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:16px;'>Upload Document</a>";
            if (sendMail($doc['email'], $subject, emailTemplate('Document Expiring in 60 Days', $empBody))) $emailsSent++;
            foreach ($hrEmails as $hrEmail) {
                $hrBody = "<p>Employee <strong>" . e($empName) . "</strong>'s <strong>" . e($label) . "</strong> expires in <strong>{$daysLeft} days</strong> ({$expiryFmt}).</p>";
                if (sendMail($hrEmail, $subject, emailTemplate('Document Expiry Alert - 60 Days', $hrBody))) $emailsSent++;
            }
            $db->prepare("UPDATE documents SET expiry_alerted_60 = 1 WHERE id = ?")->execute([$doc['id']]);
            // Notify employee
            createNotification((int)$doc['user_id'], 'doc_expiry_60', 'Document Expiring in 60 Days',
                "Your " . e($label) . " expires on {$expiryFmt}. Please upload a renewed document.",
                '/employee/documents.php');
            // Notify all HR admins + super admins
            $hrAdminIds = $db->query("SELECT id FROM users WHERE role IN ('hr_admin','super_admin') AND status = 'active'")->fetchAll(PDO::FETCH_COLUMN);
            foreach ($hrAdminIds as $hrId) {
                createNotification((int)$hrId, 'doc_expiry_hr_60', '⏰ Document Expiring in 60 Days',
                    "{$empName}'s " . e($label) . " expires on {$expiryFmt}.",
                    '/admin/documents.php');
            }
            $log[] = "60d alert: {$empName} — {$label}";
        }

        if ($daysLeft <= 30 && $daysLeft >= 0 && !$doc['expiry_alerted_30']) {
            $subject = "URGENT: {$label} Expires in {$daysLeft} Days";
            $empBody = "<p>Hi " . e($empName) . ",</p>
                        <p>URGENT: Your <strong>" . e($label) . "</strong> expires in <strong>{$daysLeft} day(s)</strong> ({$expiryFmt}).</p>
                        <p>Please upload an updated document immediately.</p>
                        <a href='" . e(APP_URL) . "/employee/documents.php' style='background:#ef4444;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:16px;'>Upload Now</a>";
            if (sendMail($doc['email'], $subject, emailTemplate('Document Expiring in 30 Days', $empBody))) $emailsSent++;
            foreach ($hrEmails as $hrEmail) {
                $hrBody = "<p>URGENT: <strong>" . e($empName) . "</strong>'s <strong>" . e($label) . "</strong> expires in <strong>{$daysLeft} day(s)</strong> ({$expiryFmt}).</p>";
                if (sendMail($hrEmail, $subject, emailTemplate('Document Expiry Alert - 30 Days', $hrBody))) $emailsSent++;
            }
            $db->prepare("UPDATE documents SET expiry_alerted_30 = 1 WHERE id = ?")->execute([$doc['id']]);
            // Notify employee
            createNotification((int)$doc['user_id'], 'doc_expiry_30', '🚨 URGENT: Document Expiring in 30 Days',
                "URGENT: Your " . e($label) . " expires in {$daysLeft} days. Upload an updated document immediately.",
                '/employee/documents.php');
            // Notify all HR admins + super admins
            $hrAdminIds30 = $db->query("SELECT id FROM users WHERE role IN ('hr_admin','super_admin') AND status = 'active'")->fetchAll(PDO::FETCH_COLUMN);
            foreach ($hrAdminIds30 as $hrId) {
                createNotification((int)$hrId, 'doc_expiry_hr_30', '🚨 URGENT: Document Expiring in 30 Days',
                    "URGENT: {$empName}'s " . e($label) . " expires in {$daysLeft} days!",
                    '/admin/documents.php');
            }
            $log[] = "30d alert: {$empName} — {$label}";
        }
    }
    $log[] = "Expiry check: " . count($expiringDocs) . " doc(s) checked";
} catch (Throwable $ex) {
    $errors[] = "Expiry alerts failed: " . $ex->getMessage();
}

// ── 2. Auto-reject documents pending for more than 1 week ────────────────────
try {
    $staleDocs = $db->prepare(
        "SELECT d.id, d.doc_type, d.user_id, d.uploaded_at,
                u.email, u.full_name
         FROM documents d
         JOIN users u ON u.id = d.user_id
         WHERE d.status = 'pending'
           AND d.uploaded_at <= DATE_SUB(NOW(), INTERVAL 7 DAY)"
    );
    $staleDocs->execute();
    $staleRows = $staleDocs->fetchAll();

    $staleDocLabels = [
        'drivers_license'    => "Driver's License / State ID",
        'i9'                 => 'Form I-9',
        'passport'           => 'Passport',
        'work_authorization' => 'Work Authorization / EAD',
        'h1b_i797'           => 'H-1B Approval (I-797)',
        'social_security'    => 'Social Security Card',
        'education'          => 'Educational Certificates',
        'direct_deposit'     => 'Direct Deposit / Voided Check',
    ];

    $staleReason = 'Your document was not reviewed within 1 week of submission. It has been automatically rejected. Please contact your HR Admin to have it reviewed and approved manually.';

    $rejectStmt = $db->prepare(
        "UPDATE documents SET status='rejected', rejection_reason=?, reviewed_at=NOW() WHERE id=?"
    );

    foreach ($staleRows as $doc) {
        $rejectStmt->execute([$staleReason, (int)$doc['id']]);

        $dLabel      = $staleDocLabels[$doc['doc_type']] ?? ucfirst(str_replace('_', ' ', $doc['doc_type']));
        $uploadedFmt = date('M j, Y', strtotime($doc['uploaded_at']));

        auditLog('document_auto_rejected', 'documents', (int)$doc['id'], [
            'reason'      => 'pending_too_long',
            'uploaded_at' => $doc['uploaded_at'],
        ]);

        // Notify employee in-app
        createNotification(
            (int)$doc['user_id'],
            'doc_auto_rejected',
            '📄 Document Auto-Rejected',
            "Your {$dLabel} (submitted {$uploadedFmt}) was not reviewed within 1 week and has been auto-rejected. Please contact HR.",
            '/employee/documents.php'
        );

        // Email the employee
        if ($doc['email']) {
            $empBody = "
                <p>Hi <strong>" . htmlspecialchars($doc['full_name'], ENT_QUOTES, 'UTF-8') . "</strong>,</p>
                <p>Your <strong>" . htmlspecialchars($dLabel, ENT_QUOTES, 'UTF-8') . "</strong> submitted on <strong>{$uploadedFmt}</strong> was <strong style='color:#e05c5c;'>automatically rejected</strong> because it was not reviewed within 1 week.</p>
                <div style='background:#1a1a1a;border-left:4px solid #e05c5c;padding:14px 18px;border-radius:6px;margin:16px 0;'>
                  <p style='color:#e05c5c;font-weight:700;margin:0 0 6px;'>Reason:</p>
                  <p style='margin:0;'>Document not reviewed within 1 week of submission. Please contact your HR Admin to have it reviewed and approved manually.</p>
                </div>
                <a href='" . htmlspecialchars(APP_URL, ENT_QUOTES, 'UTF-8') . "/employee/documents.php' style='background:#1fa0c0;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:16px;'>View My Documents</a>";
            if (sendMail($doc['email'], 'Document Auto-Rejected — Please Contact HR', emailTemplate('Document Auto-Rejected', $empBody))) {
                $emailsSent++;
            }
        }

        $log[] = "Doc auto-rejected (pending >1 week): {$doc['full_name']} — {$dLabel}";
    }

    $log[] = "Stale document check: " . count($staleRows) . " auto-rejected";
} catch (Throwable $ex) {
    $errors[] = "Stale document auto-reject failed: " . $ex->getMessage();
}

// ── 3. Friday timesheet reminder ─────────────────────────────────────────────
try {
    if (date('N') === '5') {
        $weekStart = date('Y-m-d', strtotime('monday this week'));
        $weekLabel = date('M j', strtotime($weekStart)) . ' to ' . date('M j, Y', strtotime($weekStart . ' +6 days'));
        $noTS = $db->prepare(
            "SELECT u.id, u.email, u.full_name
             FROM users u
             WHERE u.role = 'employee' AND u.status = 'active'
               AND u.id NOT IN (
                 SELECT user_id FROM timesheets
                 WHERE week_start = ? AND status IN ('pending','approved','draft')
               )"
        );
        $noTS->execute([$weekStart]);
        $missing = $noTS->fetchAll();
        foreach ($missing as $emp) {
            $body = "<p>Hi " . e($emp['full_name']) . ",</p>
                     <p>Reminder: you have not yet submitted your timesheet for the week of <strong>{$weekLabel}</strong>.</p>
                     <a href='" . e(APP_URL) . "/employee/timesheets.php' style='background:#2b8fd4;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:16px;'>Submit Timesheet</a>";
            if (sendMail($emp['email'], 'Reminder: Submit Your Timesheet', emailTemplate('Timesheet Reminder', $body))) $emailsSent++;
            createNotification((int)$emp['id'], 'ts_reminder', 'Timesheet Reminder',
                "Don't forget to submit your timesheet for the week of {$weekLabel}.",
                '/employee/timesheets.php');
            $log[] = "Friday reminder: {$emp['full_name']}";
        }
        $log[] = "Friday reminders: " . count($missing) . " sent";
    } else {
        $log[] = "Friday reminder: not Friday, skipped";
    }
} catch (Throwable $ex) {
    $errors[] = "Friday reminders failed: " . $ex->getMessage();
}

// ── 4. Remind HR to action pending timesheets (>= 3 days unreviewed) ─────────
try {
    $staleTsStmt = $db->prepare(
        "SELECT t.id, t.week_start, t.submitted_at, t.rejection_reason,
                u.id AS user_id, u.full_name
         FROM timesheets t
         JOIN users u ON u.id = t.user_id
         WHERE t.status = 'pending'
           AND t.submitted_at <= DATE_SUB(NOW(), INTERVAL 3 DAY)"
    );
    $staleTsStmt->execute();
    $stalePendingTs = $staleTsStmt->fetchAll();

    if ($stalePendingTs) {
        $hrAdminEmails = $db->query(
            "SELECT id, email FROM users WHERE role IN ('hr_admin','super_admin') AND status = 'active'"
        )->fetchAll();

        $tsReminderRows = '';
        foreach ($stalePendingTs as $ts) {
            $wl          = date('M j, Y', strtotime($ts['week_start']));
            $submittedOn = date('M j, Y', strtotime($ts['submitted_at']));
            $isFlagged   = str_starts_with((string)($ts['rejection_reason'] ?? ''), '⚠️');
            $flagNote    = $isFlagged ? ' <span style="color:#f59e0b;font-weight:700;">⚠️ Flagged</span>' : '';
            $tsReminderRows .= "<tr>
              <td style='padding:8px 12px;border-bottom:1px solid #333;'>" . htmlspecialchars($ts['full_name'], ENT_QUOTES, 'UTF-8') . "</td>
              <td style='padding:8px 12px;border-bottom:1px solid #333;'>{$wl}</td>
              <td style='padding:8px 12px;border-bottom:1px solid #333;'>{$submittedOn}{$flagNote}</td>
              <td style='padding:8px 12px;border-bottom:1px solid #333;'>
                <a href='" . htmlspecialchars(APP_URL, ENT_QUOTES, 'UTF-8') . "/admin/timesheets.php?ts_id=" . (int)$ts['id'] . "' style='color:#2b8fd4;text-decoration:none;font-weight:700;'>Review →</a>
              </td>
            </tr>";
        }

        $hrReminderSubject = '⏳ Action Required: ' . count($stalePendingTs) . ' Timesheet(s) Awaiting Your Review';
        $hrReminderBody = "
            <p>The following timesheet(s) have been pending for 3 or more days and require your decision (approve or reject):</p>
            <table style='width:100%;border-collapse:collapse;background:#111;border-radius:8px;overflow:hidden;'>
              <thead>
                <tr style='background:#1e1e1e;'>
                  <th style='padding:10px 12px;text-align:left;font-size:.82rem;color:#aaa;text-transform:uppercase;'>Employee</th>
                  <th style='padding:10px 12px;text-align:left;font-size:.82rem;color:#aaa;text-transform:uppercase;'>Week</th>
                  <th style='padding:10px 12px;text-align:left;font-size:.82rem;color:#aaa;text-transform:uppercase;'>Submitted</th>
                  <th style='padding:10px 12px;text-align:left;font-size:.82rem;color:#aaa;text-transform:uppercase;'>Action</th>
                </tr>
              </thead>
              <tbody>{$tsReminderRows}</tbody>
            </table>
            <p style='margin-top:20px;'>Please log in and <strong>approve or reject</strong> each timesheet. Employees are waiting on your decision.</p>
            <a href='" . htmlspecialchars(APP_URL, ENT_QUOTES, 'UTF-8') . "/admin/timesheets.php?status=pending' style='background:#2b8fd4;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:8px;'>Go to Pending Timesheets</a>";

        foreach ($hrAdminEmails as $hr) {
            if (!empty($hr['email'])) {
                if (sendMail($hr['email'], $hrReminderSubject, emailTemplate('Pending Timesheets Reminder', $hrReminderBody))) {
                    $emailsSent++;
                }
            }
            createNotification(
                (int)$hr['id'],
                'ts_hr_reminder',
                '⏳ ' . count($stalePendingTs) . ' Timesheet(s) Need Your Review',
                count($stalePendingTs) . ' timesheet(s) have been pending for 3+ days. Please approve or reject them.',
                '/admin/timesheets.php?status=pending'
            );
        }
        $log[] = "HR timesheet reminder: " . count($stalePendingTs) . " pending timesheet(s) flagged for HR";
    } else {
        $log[] = "HR timesheet reminder: no stale pending timesheets";
    }
} catch (Throwable $ex) {
    $errors[] = "HR timesheet reminder failed: " . $ex->getMessage();
}

// ── 5. Clean up expired rate limits ──────────────────────────────────────────
try {
    $cleanStmt = $db->prepare("DELETE FROM rate_limit WHERE expires_at < NOW()");
    $cleanStmt->execute();
    $deleted = $cleanStmt->rowCount();
    $log[] = "Rate limit cleanup: {$deleted} row(s) removed";
} catch (Throwable $ex) {
    $errors[] = "Rate limit cleanup failed: " . $ex->getMessage();
}

// ── 6. Clean up expired sessions ─────────────────────────────────────────────
try {
    $cutoff = date('Y-m-d H:i:s', time() - SESSION_LIFETIME);
    $stmt   = $db->prepare("DELETE FROM sessions WHERE last_active < ?");
    $stmt->execute([$cutoff]);
    $log[]  = "Session cleanup: done";
} catch (Throwable $ex) {
    $errors[] = "Session cleanup failed: " . $ex->getMessage();
}

// Birthday notifications
try {
    $today = date('Y-m-d');

    $birthdayStmt = $db->prepare(
        "SELECT id, full_name, role, employee_type
         FROM users
         WHERE status = 'active'
           AND date_of_birth IS NOT NULL
           AND MONTH(date_of_birth) = MONTH(CURDATE())
           AND DAY(date_of_birth) = DAY(CURDATE())
         ORDER BY full_name ASC"
    );
    $birthdayStmt->execute();
    $birthdayUsers = $birthdayStmt->fetchAll();

    if (!$birthdayUsers) {
        $log[] = 'Birthday notifications: none today';
    } else {
        $recipientStmt = $db->prepare(
            "SELECT id, email
             FROM users
             WHERE status = 'active'
               AND email IS NOT NULL
               AND email <> ''
             ORDER BY full_name ASC"
        );
        $recipientStmt->execute();
        $activeRecipients = $recipientStmt->fetchAll();

        foreach ($birthdayUsers as $birthdayUser) {
            $birthdayUserId = (int)$birthdayUser['id'];
            $birthdayName   = trim((string)$birthdayUser['full_name']);
            $roleParts      = [];

            if (!empty($birthdayUser['role'])) {
                $roleParts[] = ucwords(str_replace('_', ' ', (string)$birthdayUser['role']));
            }
            if (!empty($birthdayUser['employee_type'])) {
                $roleParts[] = (string)$birthdayUser['employee_type'];
            }

            $roleSuffix = $roleParts ? ' (' . implode(' / ', $roleParts) . ')' : '';
            $subject = 'Birthday Celebration: ' . $birthdayName;
            $body = emailTemplate(
                'Birthday Celebration',
                "<p>Team,</p>
                 <p>Today is <strong>" . e($birthdayName) . "'s birthday</strong>" . e($roleSuffix) . ".</p>
                 <p>Please join us in wishing them a wonderful birthday.</p>"
            );

            foreach ($activeRecipients as $recipient) {
                $recipientId = (int)$recipient['id'];

                if (cloudfenBirthdayAlreadySent($db, $birthdayUserId, $recipientId, $today)) {
                    continue;
                }

                if (sendMail((string)$recipient['email'], $subject, $body)) {
                    $emailsSent++;
                    cloudfenMarkBirthdaySent($db, $birthdayUserId, $recipientId, $today);
                }
            }

            if (!cloudfenHasBirthdayNotification($db, $birthdayUserId, $today)) {
                createNotification(
                    $birthdayUserId,
                    'birthday_message',
                    'Happy Birthday!',
                    'Wishing you a wonderful birthday from the CloudFen team.'
                );
            }

            $log[] = "Birthday notice: {$birthdayName}";
        }
    }
} catch (Throwable $ex) {
    $errors[] = "Birthday notifications failed: " . $ex->getMessage();
}

// Return results for logging
return array(
    'tasks'       => $log,
    'emails_sent' => $emailsSent,
    'errors'      => $errors,
);
