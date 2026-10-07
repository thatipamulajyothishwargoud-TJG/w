<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
startSecureSession();
$user   = requireAnyRole();
$db     = getDB();
$userId = (int)$user['id'];
$isSA   = $user['role'] === 'super_admin';
$canAccessTimesheets = userCanAccessTimesheetsModule($userId, (string)$user['role']);
$timesheetRestrictionMessage = getComplianceRestrictionMessage();

$msg = ''; $msgType = '';

if (!$canAccessTimesheets && isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => $timesheetRestrictionMessage]);
    exit;
}

// ── AJAX: count drafts ──────────────────────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'draft_count' && isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    header('Content-Type: application/json');
    $s = $db->prepare("SELECT COUNT(*) FROM timesheets WHERE user_id=? AND status='draft'");
    $s->execute([$userId]);
    echo json_encode(['count' => (int)$s->fetchColumn()]);
    exit;
}

// ── AJAX: load last week ────────────────────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'last_week' && isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    header('Content-Type: application/json');
    $stmt = $db->prepare("SELECT * FROM timesheets WHERE user_id=? AND status NOT IN ('draft') ORDER BY week_start DESC LIMIT 1");
    $stmt->execute([$userId]);
    $last = $stmt->fetch();
    if ($last) {
        $eStmt = $db->prepare("SELECT * FROM timesheet_entries WHERE timesheet_id=? ORDER BY id");
        $eStmt->execute([(int)$last['id']]);
        $last['entries'] = $eStmt->fetchAll();
    }
    echo json_encode(['success' => (bool)$last, 'data' => $last ?: null]);
    exit;
}

// ── AJAX: load draft ────────────────────────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'load_draft' && isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    header('Content-Type: application/json');
    $draftId = (int)($_GET['id'] ?? 0);
    if (!$draftId) { echo json_encode(['success'=>false]); exit; }
    $stmt = $db->prepare("SELECT * FROM timesheets WHERE id=? AND user_id=? AND status='draft' LIMIT 1");
    $stmt->execute([$draftId, $userId]);
    $draft = $stmt->fetch();
    if ($draft) {
        $eStmt = $db->prepare("SELECT * FROM timesheet_entries WHERE timesheet_id=? ORDER BY id");
        $eStmt->execute([$draftId]);
        $draft['entries'] = $eStmt->fetchAll();
    }
    echo json_encode(['success' => (bool)$draft, 'data' => $draft ?: null]);
    exit;
}

// ── POST: Save / Submit / Delete Draft / Upload ─────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true); // rotate token after use
    $postAction = $_POST['action'] ?? '';
    if (!$canAccessTimesheets) {
        $msg = $timesheetRestrictionMessage;
        $msgType = 'error';
        goto renderPage;
    }

    // ── Delete draft ────────────────────────────────────────
    if ($postAction === 'delete_draft') {
        $draftId = (int)($_POST['draft_id'] ?? 0);
        if ($draftId) {
            $db->prepare("DELETE FROM timesheets WHERE id=? AND user_id=? AND status='draft'")->execute([$draftId, $userId]);
            auditLog('timesheet_draft_deleted', 'timesheets', $draftId);
            $msg = 'Draft deleted.'; $msgType = 'success';
        }

    // ── Upload attachment ────────────────────────────────────
    } elseif ($postAction === 'upload_attachment') {
        $tsId = (int)($_POST['ts_id'] ?? 0);

        // If no saved timesheet yet, auto-create a blank draft for the selected week
        if (!$tsId) {
            $autoWeek = sanitizeDate($_POST['week_start'] ?? '') ?? date('Y-m-d', strtotime('monday this week'));
            if (date('N', strtotime($autoWeek)) !== '1') {
                $autoWeek = date('Y-m-d', strtotime('monday this week', strtotime($autoWeek)));
            }
            // Check if one already exists (race guard)
            $existQ = $db->prepare("SELECT id FROM timesheets WHERE user_id=? AND week_start=? LIMIT 1");
            $existQ->execute([$userId, $autoWeek]);
            $existRow = $existQ->fetch();
            if ($existRow) {
                $tsId = (int)$existRow['id'];
            } else {
                $db->prepare(
                    "INSERT INTO timesheets (user_id, week_start, mon_hours, tue_hours, wed_hours, thu_hours,
                     fri_hours, sat_hours, sun_hours, status)
                     VALUES (?, ?, 0,0,0,0,0,0,0,'draft')"
                )->execute([$userId, $autoWeek]);
                $tsId = (int)$db->lastInsertId();
                auditLog('timesheet_draft_auto_created', 'timesheets', $tsId, ['week' => $autoWeek]);
            }
        }

        if (!$tsId) { $msg = 'Could not create timesheet record.'; $msgType = 'error'; }
        else {
            // Verify ownership using fully-parameterised query (no raw interpolation)
            // super_admin can upload to any timesheet; employees only their own
            if ($isSA) {
                $ownsStmt = $db->prepare("SELECT id, status FROM timesheets WHERE id=? LIMIT 1");
                $ownsStmt->execute([$tsId]);
            } else {
                $ownsStmt = $db->prepare("SELECT id, status FROM timesheets WHERE id=? AND user_id=? LIMIT 1");
                $ownsStmt->execute([$tsId, $userId]);
            }
            $tsRow = $ownsStmt->fetch();

            if (!$tsRow) {
                $msg = 'Not authorized.'; $msgType = 'error';
            } elseif (!$isSA && $tsRow['status'] === 'approved') {
                // Employees cannot attach files to an already-approved timesheet
                $msg = 'This timesheet is approved and cannot be modified.'; $msgType = 'error';
            } elseif (!isset($_FILES['ts_file']) || $_FILES['ts_file']['error'] !== UPLOAD_ERR_OK) {
                $msg = 'No file uploaded or upload error.'; $msgType = 'error';
            } else {
                $file    = $_FILES['ts_file'];
                $maxSize = 3 * 1024 * 1024;
                $allowed = ['application/pdf','image/jpeg','image/png'];
                // Always verify MIME from actual file bytes, never from $_FILES['type']
                $finfo   = new finfo(FILEINFO_MIME_TYPE);
                $mime    = $finfo->file($file['tmp_name']);
                if ($file['size'] > $maxSize) {
                    $msg = 'File too large (max 3 MB).'; $msgType = 'error';
                } elseif (!in_array($mime, $allowed, true)) {
                    $msg = 'Only PDF, JPG, PNG allowed.'; $msgType = 'error';
                } else {
                    // ── Virus scan (scans tmp file before moving it) ─────────
                    $avResult = scanFileForVirus($file['tmp_name']);
                    if (!$avResult['clean']) {
                        $msg = $avResult['reason']; $msgType = 'error';
                        goto renderPage;
                    }

                    $uploadBase = getUploadBasePath();
                    $dir = $uploadBase . 'timesheets' . DIRECTORY_SEPARATOR . 'user_' . $userId . DIRECTORY_SEPARATOR;
                    if (!is_dir($dir)) mkdir($dir, 0750, true);
                    $ext  = ['application/pdf'=>'pdf','image/jpeg'=>'jpg','image/png'=>'png'][$mime];
                    $uuid = bin2hex(random_bytes(16));
                    // Build destination and verify it stays inside uploadBase (path-traversal guard)
                    $dest    = $dir . 'ts_' . $tsId . '_' . $uuid . '.' . $ext;
                    $realBase = realpath($uploadBase);
                    // After move, realpath will resolve; pre-check the canonical dir
                    $realDir  = realpath($dir);
                    if ($realBase === false || $realDir === false || substr($realDir, 0, strlen($realBase . DIRECTORY_SEPARATOR)) !== $realBase . DIRECTORY_SEPARATOR) {
                        $msg = 'Upload path error. Contact admin.'; $msgType = 'error';
                    } elseif (move_uploaded_file($file['tmp_name'], $dest)) {
                        // Store only the original filename sanitised — never a user-controlled path
                        $safeOrigName = preg_replace('/[^\w\-\. ]/', '_', basename($file['name']));
                        $db->prepare(
                            "INSERT INTO timesheet_attachments (timesheet_id, user_id, file_name, file_path, file_size, mime_type)
                             VALUES (?,?,?,?,?,?)"
                        )->execute([$tsId, $userId, $safeOrigName, $dest, $file['size'], $mime]);
                        auditLog('timesheet_file_uploaded', 'timesheets', $tsId);
                        $msg = 'File uploaded successfully.'; $msgType = 'success';
                    } else {
                        $msg = 'Failed to save file.'; $msgType = 'error';
                    }
                }
            }
        }

    // ── Delete attachment (super_admin only) ─────────────────
    } elseif ($postAction === 'delete_attachment' && $isSA) {
        $attId = (int)($_POST['att_id'] ?? 0);
        if ($attId) {
            $att = $db->prepare("SELECT * FROM timesheet_attachments WHERE id=? LIMIT 1");
            $att->execute([$attId]);
            $a = $att->fetch();
            if ($a) {
                if (file_exists($a['file_path'])) @unlink($a['file_path']);
                $db->prepare("DELETE FROM timesheet_attachments WHERE id=?")->execute([$attId]);
                auditLog('timesheet_file_deleted', 'timesheets', $attId);
                $msg = 'Attachment deleted.'; $msgType = 'success';
            }
        }

    // ── Save draft / submit ──────────────────────────────────
    } elseif (in_array($postAction, ['save_draft','submit','resubmit'], true)) {
        $weekStart = sanitizeDate($_POST['week_start'] ?? '') ?? '';
        if ($weekStart && date('N', strtotime($weekStart)) !== '1') {
            $weekStart = date('Y-m-d', strtotime('monday this week', strtotime($weekStart)));
        }

        if (!$weekStart) {
            $msg = 'Invalid week selected.'; $msgType = 'error';
        } else {
            // Draft limit: max 2 per employee (super_admin exempt)
            if ($postAction === 'save_draft' && !$isSA) {
                $draftCheck = $db->prepare("SELECT COUNT(*) FROM timesheets WHERE user_id=? AND status='draft'");
                $draftCheck->execute([$userId]);
                $draftCount = (int)$draftCheck->fetchColumn();
                // Check if this week already has a draft (editing existing draft is fine)
                $existCheck = $db->prepare("SELECT id FROM timesheets WHERE user_id=? AND week_start=? AND status='draft' LIMIT 1");
                $existCheck->execute([$userId, $weekStart]);
                $existingDraft = $existCheck->fetchColumn();
                if (!$existingDraft && $draftCount >= 2) {
                    $msg = 'You can only save 2 drafts at a time. Please delete or submit an existing draft first.';
                    $msgType = 'error';
                    goto renderPage;
                }
            }

            // Collect project-based rows
            $rows  = $_POST['rows'] ?? [];
            $notes = sanitizeString($_POST['notes'] ?? '', 2000);
            $dayNames = ['mon','tue','wed','thu','fri','sat','sun'];

            // Calculate day totals from project rows
            $dayTotals = array_fill_keys($dayNames, 0);
            if (is_array($rows)) {
                foreach ($rows as $row) {
                    $dayHours = $row['day_hours'] ?? [];
                    if (is_array($dayHours)) {
                        foreach ($dayHours as $di => $h) {
                            $di = (int)$di;
                            if ($di >= 0 && $di < 7) {
                                $dayTotals[$dayNames[$di]] += max(0, min(24, (float)$h));
                            }
                        }
                    }
                }
            }

            $newStatus = in_array($postAction, ['submit','resubmit'], true) ? 'pending' : 'draft';

            // ── VALIDATION FLAGS (submit/resubmit only) ─────────────
            // Timesheets are no longer auto-rejected. Instead, issues are
            // flagged for HR to manually review and approve or reject.
            $autoRejectReason = null; // kept for DB compatibility (stores the HR flag reason)
            if ($newStatus === 'pending') {
                $totalSubmitHours = array_sum(array_values($dayTotals));
                $wStartTs  = strtotime($weekStart);
                $todayTs   = strtotime(date('Y-m-d'));
                $ageDays   = ($todayTs - $wStartTs) / 86400;

                // ── Submission window rules ─────────────────────────────────────
                // Employees may submit any timesheet whose week falls in the same
                // calendar month as today, at any point during that month.
                // Additionally, once the month rolls over, they get a 1-week grace
                // period into the next month to catch any last week of the month.
                //
                //   ALLOWED: week's month == today's month  → submit any time this month
                //   ALLOWED: week's month == last month AND today ≤ 7 days into new month
                //   FLAGGED: anything older than that
                $wYear      = (int)date('Y', $wStartTs);
                $wMonth     = (int)date('n', $wStartTs);
                $todayYear  = (int)date('Y');
                $todayMonth = (int)date('n');
                // Same calendar month as today → always allowed
                $sameMonth = ($wYear === $todayYear && $wMonth === $todayMonth);
                // Previous month with grace period: today is within 7 days of the new month
                $dayOfMonth = (int)date('j'); // day-of-month for today (1–31)
                $prevMonthGrace = (!$sameMonth && $dayOfMonth <= 7 && (
                    // timesheet month is the month immediately before today's month
                    ($todayMonth > 1  && $wYear === $todayYear  && $wMonth === $todayMonth - 1) ||
                    ($todayMonth === 1 && $wYear === $todayYear - 1 && $wMonth === 12)
                ));
                $withinSubmissionWindow = $sameMonth || $prevMonthGrace;

                // Flag 1: No hours recorded
                if ($totalSubmitHours < 1) {
                    $autoRejectReason = '⚠️ HR Review Required: Timesheet has 0 recorded hours. Please verify with the employee before approving.';

                // Flag 2: Hours exceed weekly cap
                } elseif ($totalSubmitHours > 60) {
                    $autoRejectReason = "⚠️ HR Review Required: Total hours ({$totalSubmitHours}h) exceed the weekly maximum of 60. Please confirm overtime was pre-approved before approving.";

                // Flag 3: Future week
                } elseif ($wStartTs > $todayTs) {
                    $autoRejectReason = '⚠️ HR Review Required: This timesheet is for a future week. Please verify with the employee before approving.';

                // Flag 4: Late/stale submission — outside the allowed submission window
                } elseif (!$withinSubmissionWindow) {
                    $autoRejectReason = '⚠️ HR Review Required: This timesheet is outside the allowed submission window. Timesheets must be submitted within the same calendar month, or within the first 7 days of the following month. Please review manually before approving.';

                } else {
                    // Flag 5: No valid project entries (project name + hours both required)
                    $hasValidRow = false;
                    if (is_array($rows)) {
                        foreach ($rows as $row) {
                            $rProject = trim($row['project'] ?? '');
                            $rHours   = array_sum(array_map('floatval', $row['day_hours'] ?? []));
                            if ($rProject !== '' && $rHours > 0) { $hasValidRow = true; break; }
                        }
                    }
                    if (!$hasValidRow) {
                        $autoRejectReason = '⚠️ HR Review Required: No valid project entries found. Please verify entries with the employee before approving.';
                    }
                }
                // Timesheet stays as 'pending' regardless — HR must approve or reject
            }
            // ────────────────────────────────────────────────────────

            $stmt = $db->prepare("SELECT id, status FROM timesheets WHERE user_id=? AND week_start=? LIMIT 1");
            $stmt->execute([$userId, $weekStart]);
            $existing = $stmt->fetch();

            if ($existing && $existing['status'] === 'approved' && !$isSA) {
                $msg = 'This timesheet is approved and cannot be edited.'; $msgType = 'error';
                goto renderPage;
            }

            try {
                if ($existing) {
                    $db->prepare(
                        "UPDATE timesheets SET mon_hours=?,tue_hours=?,wed_hours=?,thu_hours=?,
                         fri_hours=?,sat_hours=?,sun_hours=?,notes=?,status=?,
                         rejection_reason=?,reviewed_at=IF(?='rejected',NOW(),NULL),
                         submitted_at=IF(?='pending',NOW(),submitted_at)
                         WHERE id=?"
                    )->execute([
                        $dayTotals['mon'],$dayTotals['tue'],$dayTotals['wed'],$dayTotals['thu'],
                        $dayTotals['fri'],$dayTotals['sat'],$dayTotals['sun'],
                        $notes, $newStatus, $autoRejectReason, $newStatus, $newStatus, (int)$existing['id']
                    ]);
                    $tsId = (int)$existing['id'];
                } else {
                    $db->prepare(
                        "INSERT INTO timesheets
                         (user_id,week_start,mon_hours,tue_hours,wed_hours,thu_hours,fri_hours,sat_hours,sun_hours,notes,status,rejection_reason,reviewed_at,submitted_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,IF(?='rejected',NOW(),NULL),IF(?='pending',NOW(),NULL))"
                    )->execute([
                        $userId,$weekStart,
                        $dayTotals['mon'],$dayTotals['tue'],$dayTotals['wed'],$dayTotals['thu'],
                        $dayTotals['fri'],$dayTotals['sat'],$dayTotals['sun'],
                        $notes, $newStatus, $autoRejectReason, $newStatus, $newStatus
                    ]);
                    $tsId = (int)$db->lastInsertId();
                }

                // Save project rows in timesheet_entries
                $db->prepare("DELETE FROM timesheet_entries WHERE timesheet_id=?")->execute([$tsId]);
                if (is_array($rows)) {
                    $eStmt = $db->prepare(
                        "INSERT INTO timesheet_entries
                         (timesheet_id, project, task, hours, description)
                         VALUES (?,?,?,?,?)"
                    );
                    foreach ($rows as $row) {
                        $client   = sanitizeString($row['client']  ?? '', 100);
                        $project  = sanitizeString($row['project'] ?? '', 100);
                        $task     = sanitizeString($row['task']    ?? '', 100);
                        $dayHoursRaw = $row['day_hours'] ?? [];
                        $dayHours = [];
                        $rowTotal = 0;
                        for ($i = 0; $i < 7; $i++) {
                            $h = max(0, min(24, (float)($dayHoursRaw[$i] ?? 0)));
                            $dayHours[$i] = $h;
                            $rowTotal += $h;
                        }
                        if ($client || $project || $task || $rowTotal > 0) {
                            $meta = json_encode(['client' => $client, 'day_hours' => $dayHours]);
                            $eStmt->execute([$tsId, $project, $task, $rowTotal, $meta]);
                        }
                    }
                }

                // ── Inline file attachment (from main form ts_file field) ─
                if (isset($_FILES['ts_file']) && $_FILES['ts_file']['error'] === UPLOAD_ERR_OK) {
                    $tsFileRaw = $_FILES['ts_file'];
                    $maxSize   = 3 * 1024 * 1024;
                    $allowed   = ['application/pdf','image/jpeg','image/png'];
                    $finfo     = new finfo(FILEINFO_MIME_TYPE);
                    $tsMime    = $finfo->file($tsFileRaw['tmp_name']);
                    if ($tsFileRaw['size'] > $maxSize) {
                        $msg .= ' (Attachment skipped: file too large — max 3 MB.)';
                    } elseif (!in_array($tsMime, $allowed, true)) {
                        $msg .= ' (Attachment skipped: only PDF, JPG, PNG allowed.)';
                    } else {
                        $avr = scanFileForVirus($tsFileRaw['tmp_name']);
                        if (!$avr['clean']) {
                            $msg .= ' (Attachment skipped: ' . $avr['reason'] . ')';
                        } else {
                            $upBase  = getUploadBasePath();
                            $tsDir   = $upBase . 'timesheets' . DIRECTORY_SEPARATOR . 'user_' . $userId . DIRECTORY_SEPARATOR;
                            if (!is_dir($tsDir)) mkdir($tsDir, 0750, true);
                            $tsExt   = ['application/pdf'=>'pdf','image/jpeg'=>'jpg','image/png'=>'png'][$tsMime];
                            $tsUuid  = bin2hex(random_bytes(16));
                            $tsDest  = $tsDir . 'ts_' . $tsId . '_' . $tsUuid . '.' . $tsExt;
                            $realBase = realpath($upBase);
                            $realDir  = realpath($tsDir);
                            if ($realBase && $realDir && strncmp($realDir, $realBase . DIRECTORY_SEPARATOR, strlen($realBase . DIRECTORY_SEPARATOR)) === 0) {
                                if (move_uploaded_file($tsFileRaw['tmp_name'], $tsDest)) {
                                    $safeOrig = preg_replace('/[^\w\-\. ]/', '_', basename($tsFileRaw['name']));
                                    $db->prepare(
                                        "INSERT INTO timesheet_attachments (timesheet_id, user_id, file_name, file_path, file_size, mime_type)
                                         VALUES (?,?,?,?,?,?)"
                                    )->execute([$tsId, $userId, $safeOrig, $tsDest, $tsFileRaw['size'], $tsMime]);
                                    auditLog('timesheet_file_uploaded', 'timesheets', $tsId);
                                }
                            }
                        }
                    }
                }
                // ─────────────────────────────────────────────────────────

                $wl = date('M j, Y', strtotime($weekStart));

                if ($newStatus === 'pending') {
                    auditLog('timesheet_' . $postAction, 'timesheets', $tsId, ['week' => $weekStart]);

                    // Notify HR/super_admin about the submission
                    $hrAdminRows = $db->query("SELECT id, email FROM users WHERE role IN ('hr_admin','super_admin') AND status = 'active'")->fetchAll();
                    if ($autoRejectReason) {
                        // Flagged submission — send urgent reminder to HR to force a decision
                        foreach ($hrAdminRows as $hr) {
                            createNotification((int)$hr['id'], 'ts_flagged_review',
                                '🚨 Timesheet Needs Your Review',
                                "{$user['name']}'s timesheet for week of {$wl} requires your attention — please approve or reject. " . strip_tags($autoRejectReason),
                                '/admin/timesheets.php?ts_id=' . $tsId);
                            if (!empty($hr['email'])) {
                                sendMail(
                                    $hr['email'],
                                    "⚠️ Action Required: Timesheet Flagged — {$user['name']}",
                                    emailTemplate('Timesheet Flagged — HR Action Required',
                                        "<p>Hi,</p>
                                        <p><strong>{$user['name']}</strong> has submitted a timesheet for the week of <strong>{$wl}</strong> that requires your manual review.</p>
                                        <div style='background:#1a1a1a;border-left:4px solid #f59e0b;padding:14px 18px;border-radius:6px;margin:16px 0;'>
                                          <p style='color:#f59e0b;font-weight:700;margin:0 0 6px;'>⚠️ Flag Reason:</p>
                                          <p style='margin:0;'>" . htmlspecialchars(strip_tags($autoRejectReason), ENT_QUOTES, 'UTF-8') . "</p>
                                        </div>
                                        <p>Please log in to the HR portal and <strong>approve or reject</strong> this timesheet. It will remain pending until you take action.</p>
                                        <a href='" . htmlspecialchars(APP_URL, ENT_QUOTES, 'UTF-8') . "/admin/timesheets.php?ts_id={$tsId}' style='background:#f59e0b;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:16px;'>Review Timesheet Now</a>")
                                );
                            }
                        }
                    } else {
                        // Normal submission — standard HR notification
                        foreach ($hrAdminRows as $hr) {
                            createNotification((int)$hr['id'], 'ts_submitted',
                                '⏱️ Timesheet Submitted',
                                "{$user['name']} submitted a timesheet for week of {$wl}.",
                                '/admin/timesheets.php?ts_id=' . $tsId);
                        }
                    }

                    $tsEmail = $_SESSION['email'] ?? '';
                    if ($tsEmail) sendMail($tsEmail,
                        'Timesheet Submitted - CloudFen HR Portal',
                        emailTemplate('Timesheet Submitted',
                            "<p>Your timesheet for week of <strong>{$wl}</strong> has been submitted and is pending HR review.</p>"));
                    $msg = 'Timesheet submitted for approval.';
                } else {
                    auditLog('timesheet_' . $postAction, 'timesheets', $tsId, ['week' => $weekStart]);
                    $draftS = $db->prepare("SELECT COUNT(*) FROM timesheets WHERE user_id=? AND status='draft'");
                    $draftS->execute([$userId]);
                    $draftN = (int)$draftS->fetchColumn();
                    $msg = "Draft saved. ({$draftN}/2 drafts used)";
                }
                $msgType = 'success';
            } catch (\Throwable $e) {
                error_log('Timesheet save error: ' . $e->getMessage());
                $msg = 'Error saving timesheet.'; $msgType = 'error';
            }
        }
    }
}

renderPage:

// ── LOAD DATA ───────────────────────────────────────────────
$selectedWeek = sanitizeDate($_GET['week'] ?? '') ?? date('Y-m-d', strtotime('monday this week'));
if (date('N', strtotime($selectedWeek)) !== '1') {
    $selectedWeek = date('Y-m-d', strtotime('monday this week', strtotime($selectedWeek)));
}

$tsStmt = $db->prepare("SELECT * FROM timesheets WHERE user_id=? AND week_start=? LIMIT 1");
$tsStmt->execute([$userId, $selectedWeek]);
$currentTs = $tsStmt->fetch() ?: null;

$entries = [];
if ($currentTs) {
    $eStmt = $db->prepare("SELECT * FROM timesheet_entries WHERE timesheet_id=? ORDER BY id");
    $eStmt->execute([(int)$currentTs['id']]);
    $entries = $eStmt->fetchAll();
}

// Load attachments for current timesheet
$attachments = [];
if ($currentTs) {
    try {
        $aStmt = $db->prepare("SELECT * FROM timesheet_attachments WHERE timesheet_id=? ORDER BY id");
        $aStmt->execute([(int)$currentTs['id']]);
        $attachments = $aStmt->fetchAll();
    } catch (\Throwable $e) { $attachments = []; }
}

// Saved drafts
$draftStmt = $db->prepare("SELECT id, week_start, total_hours, created_at FROM timesheets WHERE user_id=? AND status='draft' ORDER BY created_at DESC LIMIT 2");
$draftStmt->execute([$userId]);
$savedDrafts = $draftStmt->fetchAll();
$draftCount  = count($savedDrafts);

// Past timesheets (non-draft, read-only for employees)
$pastStmt = $db->prepare(
    "SELECT id, week_start, total_hours, status, rejection_reason, submitted_at, reviewed_at
     FROM timesheets WHERE user_id=? AND status != 'draft' ORDER BY week_start DESC LIMIT 20"
);
$pastStmt->execute([$userId]);
$pastList = $pastStmt->fetchAll();

$isReadonly = $currentTs && $currentTs['status'] === 'approved' && !$isSA;
$canEdit    = !$currentTs || in_array($currentTs['status'], ['draft','rejected'], true) || $isSA;

$prevWeek  = date('Y-m-d', strtotime($selectedWeek . ' -1 week'));
$nextWeek  = date('Y-m-d', strtotime($selectedWeek . ' +1 week'));
$weekLabel = date('M j', strtotime($selectedWeek)) . ' – ' . date('M j, Y', strtotime($selectedWeek . ' +6 days'));

// Day info for the selected week
$dayDefs = [
    ['key'=>'mon','label'=>'Mon'],['key'=>'tue','label'=>'Tue'],['key'=>'wed','label'=>'Wed'],
    ['key'=>'thu','label'=>'Thu'],['key'=>'fri','label'=>'Fri'],['key'=>'sat','label'=>'Sat'],['key'=>'sun','label'=>'Sun'],
];
foreach ($dayDefs as $i => &$dd) {
    $dd['date']   = date('Y-m-d', strtotime($selectedWeek . ' +' . $i . ' days'));
    $dd['label2'] = date('D, M j', strtotime($selectedWeek . ' +' . $i . ' days'));
    $dd['index']  = $i;
}
unset($dd);

// Parse saved entries into project rows (project-based weekly grid)
$projectRows = [];

// ── If we arrived via a failed POST (goto renderPage before save),
//    restore the rows the user had typed so nothing is lost ──────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['rows']) && $msgType === 'error') {
    foreach ($_POST['rows'] as $row) {
        $dayHoursRaw = $row['day_hours'] ?? [];
        $dayHours    = [];
        for ($i = 0; $i < 7; $i++) {
            $dayHours[$i] = max(0, min(24, (float)($dayHoursRaw[$i] ?? 0)));
        }
        $projectRows[] = [
            'client'    => htmlspecialchars_decode(strip_tags($row['client']  ?? ''), ENT_QUOTES),
            'project'   => htmlspecialchars_decode(strip_tags($row['project'] ?? ''), ENT_QUOTES),
            'task'      => htmlspecialchars_decode(strip_tags($row['task']    ?? ''), ENT_QUOTES),
            'day_hours' => $dayHours,
        ];
    }
}

// Fall back to DB entries if POST restore didn't produce rows
if (empty($projectRows)) {
    foreach ($entries as $ent) {
        $meta = json_decode($ent['description'] ?? '{}', true) ?: [];
        $projectRows[] = [
            'client'    => $meta['client']    ?? '',
            'project'   => $ent['project']   ?? '',
            'task'      => $ent['task']       ?? '',
            'day_hours' => $meta['day_hours'] ?? array_fill(0, 7, 0),
        ];
    }
}
if (empty($projectRows)) {
    $projectRows = [
        ['client'=>'','project'=>'','task'=>'','day_hours'=>array_fill(0,7,0)],
    ];
}
// Build rowsByDay for day totals compatibility
$rowsByDay = array_fill(0, 7, []);
foreach ($projectRows as $pr) {
    foreach ($pr['day_hours'] as $di => $h) {
        if ($h > 0) $rowsByDay[$di][] = ['shift_hours' => $h];
    }
}

$dayTotalsForView = array_fill(0, 7, 0.0);
foreach ($rowsByDay as $di => $dayRows) {
    foreach ($dayRows as $row) {
        $dayTotalsForView[(int)$di] += (float)($row['shift_hours'] ?? 0);
    }
}
$currentWeekTotal   = array_sum($dayTotalsForView);
$attachmentCount    = count($attachments);
$currentStatusLabel = $currentTs ? ucfirst((string)$currentTs['status']) : 'New';
$lastTouchedLabel   = $currentTs
    ? date('M j, Y g:i A', strtotime($currentTs['updated_at'] ?? $currentTs['created_at']))
    : 'Not saved yet';

$flashType  = $msgType;
$flashTitle = $msg ? ($msgType === 'success' ? 'Saved' : 'Error') : '';
pageHead('My Timesheets', $flashType, $flashTitle, $msg);
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id'=>$userId,'name'=>$user['name'],'role'=>$user['role']], 'my_timesheets'); ?>
  <div class="main-content">
    <?php renderTopbar('My Timesheets', $user); ?>
    <?php if ($user['role'] === 'hr_admin'): ?>
    <!-- Sub-tabs for hr_admin: View Submitted Timesheets / My Timesheets -->
    <div style="padding:0 28px;border-bottom:1px solid var(--border);background:var(--surface);display:flex;gap:0;">
      <a href="/admin/submitted_timesheets.php" style="padding:13px 22px;font-size:.88rem;font-weight:600;text-decoration:none;color:var(--gray-400);border-bottom:2px solid transparent;display:inline-block;">View Submitted Timesheets</a>
      <a href="/employee/timesheets.php" style="padding:13px 22px;font-size:.88rem;font-weight:600;text-decoration:none;color:var(--cyan);border-bottom:2px solid var(--cyan);display:inline-block;">My Timesheets</a>
    </div>
    <?php endif; ?>
    <div class="page-body">

      <div class="page-header flex-between">
        <div>
          <h1>⏱️ My Timesheets</h1>
          <p>Log hours by project and task for each day of the week.</p>
        </div>
        <?php if ($canAccessTimesheets): ?>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end;">
          <span id="ts-dirty-indicator" class="ts-dirty-indicator">Saved</span>
          <button class="btn btn-outline btn-sm" type="button" onclick="copyLastWeek()">Copy Last Week</button>
          <button class="btn btn-outline btn-sm" type="button" onclick="addProjectRow()">+ Add Row</button>
          <button class="btn btn-outline btn-sm" type="button" onclick="clearWeek()">Clear Week</button>
        </div>
        <?php endif; ?>
      </div>

      <?php if (!$canAccessTimesheets): ?>
        <div class="alert alert-warn" style="margin-bottom:20px;"><?= e($timesheetRestrictionMessage) ?></div>
      <?php endif; ?>

      <?php if ($canAccessTimesheets): ?>
      <div class="card" style="margin-bottom:16px;">
        <div class="card-body" style="padding:14px 20px;">
          <div class="ts-mini-stats">
            <div class="ts-mini-stat">
              <span class="label">Status</span>
              <strong id="ts-status-value"><?= e($currentStatusLabel) ?></strong>
            </div>
            <div class="ts-mini-stat">
              <span class="label">Week Total</span>
              <strong><span id="week-total-stat"><?= e(number_format((float)$currentWeekTotal, 1)) ?></span> hrs</strong>
            </div>
            <div class="ts-mini-stat">
              <span class="label">Rows</span>
              <strong id="row-count-stat"><?= count($projectRows) ?></strong>
            </div>
            <div class="ts-mini-stat">
              <span class="label">Attachments</span>
              <strong><?= $attachmentCount ?></strong>
            </div>
            <div class="ts-mini-stat">
              <span class="label">Last Updated</span>
              <strong><?= e($lastTouchedLabel) ?></strong>
            </div>
          </div>
        </div>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType==='error'?'error':'success' ?>" data-auto-dismiss="5000">
          <?= $msgType==='success' ? '✅' : '⚠️' ?> <?= e($msg) ?>
        </div>
      <?php endif; ?>

      <?php if ($isSA): ?>
        <div class="alert" style="background:rgba(139,92,246,.12);border:1px solid rgba(139,92,246,.35);color:#c4b5fd;padding:10px 16px;border-radius:8px;font-size:.83rem;margin-bottom:16px;">
          🔑 <strong>Super Admin mode</strong> — you can edit, create, and delete all timesheets and attachments.
        </div>
      <?php endif; ?>

      <div class="grid-2" style="gap:24px;align-items:start;">

        <!-- ════ LEFT: Timecard Form ════ -->
        <div style="grid-column:1/-1;">

          <!-- Week Navigator -->
          <div class="card" style="margin-bottom:16px;">
            <div class="card-body" style="padding:12px 20px;">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
                <a href="?week=<?= e($prevWeek) ?>" class="btn btn-outline btn-sm">← Prev Week</a>
                <div style="text-align:center;">
                  <div style="font-weight:700;font-size:1rem;color:var(--text-1);"><?= e($weekLabel) ?></div>
                  <input type="date" id="week-picker" value="<?= e($selectedWeek) ?>"
                         style="margin-top:4px;padding:4px 8px;background:var(--surface-2);border:1px solid var(--surface-3);border-radius:6px;color:var(--text-2);font-size:.78rem;cursor:pointer;"
                         onchange="window.location.href='?week='+this.value">
                </div>
                <a href="?week=<?= e($nextWeek) ?>" class="btn btn-outline btn-sm">Next Week →</a>
              </div>
            </div>
          </div>

          <!-- Workflow status bar -->
          <?php
          $wfStatus = $currentTs['status'] ?? 'new';
          $wfLabels = ['Draft','Pending Approval','Approved'];
          $stepMap  = ['draft'=>['active','',''],'pending'=>['done','active',''],'approved'=>['done','done','done'],'rejected'=>['done','rejected',''],'new'=>['','','']];
          $sc       = $stepMap[$wfStatus] ?? ['','',''];
          ?>
          <div class="card" style="margin-bottom:16px;">
            <div class="card-body" style="padding:14px 20px;">
              <div class="ts-workflow">
                <?php for ($i=0;$i<3;$i++): ?>
                  <div class="ts-workflow-step <?= e($sc[$i]) ?>">
                    <div class="ts-workflow-dot"><?= $sc[$i]==='done'?'✓':($sc[$i]==='rejected'?'✗':($i+1)) ?></div>
                    <div class="ts-workflow-label"><?= e($wfLabels[$i]) ?></div>
                  </div>
                <?php endfor; ?>
              </div>
              <?php if ($currentTs && $currentTs['status']==='rejected' && $currentTs['rejection_reason']): ?>
                <div class="rejection-notice">
                  <strong style="font-size:.82rem;color:var(--rose);">❌ Rejected:</strong>
                  <div class="reason"><?= e($currentTs['rejection_reason']) ?></div>
                </div>
              <?php endif; ?>
            </div>
          </div>

          <!-- ── Saved Drafts panel ── -->
          <div class="card" style="margin-bottom:16px;">
            <div class="card-header" style="display:flex;align-items:center;justify-content:space-between;">
              <h3>💾 Saved Drafts <span style="font-size:.75rem;color:var(--text-3);font-weight:400;">(<?= $draftCount ?>/2 slots used)</span></h3>
              <?php if ($draftCount < 2): ?>
                <span style="font-size:.78rem;color:var(--cyan);"><?= 2 - $draftCount ?> slot<?= (2-$draftCount)!==1?'s':'' ?> available</span>
              <?php else: ?>
                <span style="font-size:.78rem;color:var(--rose);">Draft limit reached — delete one to save new</span>
              <?php endif; ?>
            </div>
            <div class="card-body" style="padding:<?= $savedDrafts ? '0' : '20px' ?>;">
              <?php if (!$savedDrafts): ?>
                <div style="text-align:center;color:var(--text-3);font-size:.84rem;padding:8px 0;">No drafts saved yet. Fill out the timecard below and click Save Draft.</div>
              <?php endif; ?>
              <?php foreach ($savedDrafts as $dr): ?>
                <div style="display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--surface-3);">
                  <div style="flex:1;">
                    <div style="font-weight:600;font-size:.88rem;color:var(--text-1);">
                      Week of <?= e(date('M j, Y', strtotime($dr['week_start']))) ?>
                    </div>
                    <div style="font-size:.76rem;color:var(--text-3);">
                      <?= e(number_format((float)$dr['total_hours'],1)) ?> hrs · Saved <?= e(date('M j g:ia', strtotime($dr['created_at']))) ?>
                    </div>
                  </div>
                  <button class="btn btn-outline btn-sm" onclick="loadDraft(<?= (int)$dr['id'] ?>, '<?= e($dr['week_start']) ?>')">📂 Load</button>
                  <form method="POST" style="margin:0;" onsubmit="return confirm('Delete this draft?')">
                    <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                    <input type="hidden" name="action" value="delete_draft">
                    <input type="hidden" name="draft_id" value="<?= (int)$dr['id'] ?>">
                    <button type="submit" class="btn btn-sm" style="background:rgba(239,68,68,.15);color:var(--rose);border:1px solid rgba(239,68,68,.3);">🗑 Delete</button>
                  </form>
                </div>
              <?php endforeach; ?>
            </div>
          </div>

          <!-- ── MAIN TIMECARD ── -->
          <div class="card">
            <div class="card-header" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
              <div>
                <h3 style="margin:0;">Timecard — <?= e($weekLabel) ?></h3>
                <div style="font-size:.78rem;color:var(--text-3);margin-top:2px;">
                  <?= e($user['name']) ?>
                  <?php if ($currentTs): ?>
                    · <span class="badge badge-<?= e($currentTs['status']) ?>"><?= e(ucfirst($currentTs['status'])) ?></span>
                  <?php else: ?>
                    · <span class="badge badge-draft">New</span>
                  <?php endif; ?>
                </div>
              </div>
              <?php if ($isReadonly): ?>
                <span style="font-size:.8rem;color:var(--rose);">🔒 Approved — read only</span>
              <?php endif; ?>
            </div>
            <div class="card-body" style="padding:0;">

              <?php if ($isReadonly): ?>
                <div class="alert alert-success" style="margin:16px 20px 0;">✅ This timesheet is approved. <?= $isSA ? 'As Super Admin, you may still edit.' : 'For changes, <a href="' . e(getHrContactUrl()) . '" style="color:inherit;text-decoration:underline;">Contact HR</a>.' ?></div>
              <?php endif; ?>

              <form method="POST" id="ts-form" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                <input type="hidden" name="week_start" value="<?= e($selectedWeek) ?>">
                <input type="hidden" name="action" id="ts-action" value="save_draft">

                <!-- ── Project-based weekly timesheet table ── -->
                <div style="overflow-x:auto;">
                  <table class="ts-project-table" id="project-table">
                    <thead>
                      <tr>
                        <th style="width:130px;">Client</th>
                        <th style="width:140px;">Project</th>
                        <th style="width:120px;">Task</th>
                        <?php foreach ($dayDefs as $dd): ?>
                        <th style="width:68px;text-align:center;" class="<?= in_array($dd['key'],['sat','sun'])?'weekend-col':'' ?>">
                          <div style="font-weight:700;font-size:.78rem;"><?= e($dd['label']) ?></div>
                          <div style="font-size:.7rem;color:var(--text-3);font-weight:400;"><?= e(date('j M', strtotime($dd['date']))) ?></div>
                        </th>
                        <?php endforeach; ?>
                        <th style="width:60px;text-align:center;">Total</th>
                        <?php if (!$isReadonly || $isSA): ?><th style="width:36px;"></th><?php endif; ?>
                      </tr>
                    </thead>
                    <tbody id="project-body">
                      <?php foreach ($projectRows as $ri => $pr): ?>
                      <tr class="project-row" data-ri="<?= $ri ?>">
                        <td>
                          <?php if (!$isReadonly || $isSA): ?>
                            <input type="text" name="rows[<?= $ri ?>][client]" value="<?= e($pr['client']) ?>"
                                   placeholder="Acme Corp" class="kronos-input project-client-input" required maxlength="100">
                          <?php else: ?>
                            <span class="kronos-readonly"><?= e($pr['client']) ?></span>
                          <?php endif; ?>
                        </td>
                        <td>
                          <?php if (!$isReadonly || $isSA): ?>
                            <input type="text" name="rows[<?= $ri ?>][project]" value="<?= e($pr['project']) ?>"
                                   placeholder="Website Design" class="kronos-input project-project-input" required maxlength="100">
                          <?php else: ?>
                            <span class="kronos-readonly"><?= e($pr['project']) ?></span>
                          <?php endif; ?>
                        </td>
                        <td>
                          <?php if (!$isReadonly || $isSA): ?>
                            <input type="text" name="rows[<?= $ri ?>][task]" value="<?= e($pr['task']) ?>"
                                   placeholder="Design" class="kronos-input kronos-input-sm project-task-input" required maxlength="100">
                          <?php else: ?>
                            <span class="kronos-readonly"><?= e($pr['task']) ?></span>
                          <?php endif; ?>
                        </td>
                        <?php foreach ($dayDefs as $dd):
                              $di  = $dd['index'];
                              $h   = (float)($pr['day_hours'][$di] ?? 0);
                              $isWe= in_array($dd['key'],['sat','sun']);
                        ?>
                        <td class="project-day-cell <?= $isWe?'weekend-col':'' ?>">
                          <?php if (!$isReadonly || $isSA): ?>
                            <input type="number" name="rows[<?= $ri ?>][day_hours][<?= $di ?>]"
                                   value="<?= $h > 0 ? e(number_format($h,1)) : '' ?>"
                                   min="0" max="24" step="0.5" placeholder="–"
                                   class="kronos-input kronos-input-sm project-hrs-input <?= $isWe?'weekend-hrs':'' ?>"
                                   data-ri="<?= $ri ?>" data-di="<?= $di ?>"
                                   oninput="recalcProjectTotals()">
                          <?php else: ?>
                            <span class="kronos-readonly"><?= $h > 0 ? e(number_format($h,1)) : '–' ?></span>
                          <?php endif; ?>
                        </td>
                        <?php endforeach; ?>
                        <td class="project-row-total" data-ri="<?= $ri ?>" style="text-align:center;font-weight:700;color:var(--cyan);font-size:.85rem;">
                          <?php
                            $rowT = array_sum($pr['day_hours']);
                            echo $rowT > 0 ? number_format($rowT,1) : '0.0';
                          ?>
                        </td>
                        <?php if (!$isReadonly || $isSA): ?>
                        <td style="text-align:center;">
                          <button type="button" class="kronos-del-btn" onclick="removeProjectRow(this)" title="Remove row">✕</button>
                        </td>
                        <?php endif; ?>
                      </tr>
                      <?php endforeach; ?>
                    </tbody>
                    <tfoot>
                      <tr class="kronos-total-row">
                        <td colspan="3" style="font-weight:700;font-size:.8rem;color:var(--text-2);text-transform:uppercase;letter-spacing:.07em;padding:10px 8px;">Daily Totals</td>
                        <?php foreach ($dayDefs as $dd):
                              $di = $dd['index'];
                              $dayT = 0;
                              foreach ($projectRows as $pr) $dayT += (float)($pr['day_hours'][$di] ?? 0);
                              $isWe = in_array($dd['key'],['sat','sun']);
                        ?>
                        <td class="project-day-total-cell <?= $isWe?'weekend-col':'' ?>" data-di="<?= $di ?>" style="text-align:center;font-weight:700;color:var(--text-1);font-size:.85rem;">
                          <?= $dayT > 0 ? number_format($dayT,1) : '–' ?>
                        </td>
                        <?php endforeach; ?>
                        <td style="text-align:center;font-weight:800;font-size:1rem;color:var(--cyan);padding:10px 8px;">
                          <span id="week-total">0.0</span>
                        </td>
                        <?php if (!$isReadonly || $isSA): ?><td></td><?php endif; ?>
                      </tr>
                    </tfoot>
                  </table>
                </div>

                <!-- Add row button (inline below table) -->
                <?php if (!$isReadonly || $isSA): ?>
                <div style="padding:12px 20px;border-top:1px solid var(--surface-3);display:flex;align-items:center;gap:12px;">
                  <button type="button" class="btn btn-outline btn-sm" onclick="addProjectRow()" style="font-size:.8rem;">+ Add row</button>
                </div>
                <?php endif; ?>

                                </div>

                <!-- Notes -->
                <div style="padding:16px 20px;border-top:1px solid var(--surface-3);">
                  <label style="font-weight:700;font-size:.8rem;color:var(--text-2);text-transform:uppercase;letter-spacing:.07em;display:block;margin-bottom:6px;">Notes / Comments</label>
                  <textarea name="notes" class="form-control" rows="2" maxlength="2000" placeholder="Add any notes about this timecard..." <?= ($isReadonly&&!$isSA)?'disabled':'' ?>><?= e($currentTs['notes'] ?? '') ?></textarea>
                </div>

                <!-- Action buttons -->
                <?php if (!$isReadonly || $isSA): ?>
                <div style="padding:0 20px 20px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
                  <button type="button" class="btn btn-navy" onclick="submitTs('save_draft', this)"
                    <?= (!$isSA && $draftCount >= 2 && (!$currentTs || $currentTs['status']!=='draft')) ? 'disabled title="Draft limit reached"' : '' ?>>
                    <span class="btn-text">💾 Save Draft</span>
                  </button>
                  <button type="button" class="btn btn-primary"
                    onclick="submitTs('<?= $currentTs&&$currentTs['status']==='rejected'?'resubmit':'submit' ?>', this)">
                    <span class="btn-text"><?= ($currentTs&&$currentTs['status']==='rejected') ? '🔄 Resubmit' : '📤 Submit for Approval' ?></span>
                  </button>
                  <?php if (!$currentTs || $currentTs['status']==='draft'): ?>
                    <span style="font-size:.78rem;color:var(--text-3);margin-left:4px;">
                      <?= $draftCount ?>/2 draft slots used
                    </span>
                  <?php endif; ?>
                </div>
                <?php endif; ?>
                <!-- Hidden file input lives inside the main form so it submits together -->
                <input type="file" name="ts_file" id="ts_file" accept=".pdf,.jpg,.jpeg,.png"
                       style="display:none;" onchange="handleFileSelect(this)">
              </form>
            </div>
          </div>

          <!-- ── File Attachments ── -->
          <div class="att-card card" style="margin-top:20px;">
            <div class="att-header">
              <div class="att-header-left">
                <span class="att-header-icon">📎</span>
                <span class="att-header-title">Attach a File <span style="font-weight:400;color:var(--text-3);font-size:.8rem;">(optional)</span></span>
                <?php if ($attachments): ?>
                  <span class="att-count-badge"><?= count($attachments) ?></span>
                <?php endif; ?>
              </div>
              <span class="att-header-hint">PDF · JPG · PNG &nbsp;|&nbsp; max 3 MB · uploaded with timesheet</span>
            </div>

            <div class="att-body">
              <!-- File picker — part of the MAIN ts-form (no separate submit) -->
              <div class="att-dropzone" id="upload-zone"
                   onclick="document.getElementById('ts_file').click()"
                   role="button" tabindex="0"
                   onkeydown="if(event.key==='Enter'||event.key===' ')document.getElementById('ts_file').click()">
                <div class="att-drop-inner" id="att-drop-inner">
                  <div class="att-drop-cloud">
                    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">
                      <polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/>
                      <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/>
                    </svg>
                  </div>
                  <p class="att-drop-title">Drop file here</p>
                  <p class="att-drop-sub">or <span class="att-drop-link">browse files</span> — file will upload when you save or submit</p>
                </div>
                <div class="att-drop-selected" id="att-drop-selected" style="display:none;">
                  <div class="att-drop-file-icon" id="att-drop-file-icon">📄</div>
                  <div class="att-drop-file-name" id="att-drop-file-name"></div>
                  <div class="att-drop-file-size" id="att-drop-file-size"></div>
                  <button type="button" class="att-drop-clear" onclick="clearFileSelect(event)" title="Remove">✕</button>
                </div>
              </div>
              <p class="att-inline-hint">✅ The file will be saved automatically when you click <strong>Save Draft</strong> or <strong>Submit for Approval</strong>.</p>

              <!-- Existing attachments -->
              <?php if ($attachments): ?>
              <div class="att-list">
                <div class="att-list-label">Uploaded files</div>
                <?php foreach ($attachments as $att): ?>
                <div class="att-file-row">
                  <div class="att-file-thumb">
                    <?= $att['mime_type'] === 'application/pdf' ? '📄' : '🖼️' ?>
                  </div>
                  <div class="att-file-info">
                    <div class="att-file-name"><?= e($att['file_name']) ?></div>
                    <div class="att-file-meta">
                      <?= e(number_format($att['file_size'] / 1024, 1)) ?> KB
                      &nbsp;·&nbsp;
                      <?= e(date('M j, Y', strtotime($att['created_at']))) ?>
                    </div>
                  </div>
                  <div class="att-file-actions">
                    <a href="/api/download_attachment.php?id=<?= (int)$att['id'] ?>&view=1"
                       class="att-btn att-btn-view" title="View" target="_blank"
                       style="display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:6px;background:var(--surface-2);color:var(--text-2);text-decoration:none;border:1px solid var(--border);">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                      </svg>
                    </a>
                    <a href="/api/download_attachment.php?id=<?= (int)$att['id'] ?>"
                       class="att-btn att-btn-dl" title="Download" target="_blank">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                      </svg>
                    </a>
                    <?php if ($isSA): ?>
                    <form method="POST" style="margin:0;" onsubmit="return confirm('Delete this attachment?')">
                      <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
                      <input type="hidden" name="action"     value="delete_attachment">
                      <input type="hidden" name="att_id"     value="<?= (int)$att['id'] ?>">
                      <button type="submit" class="att-btn att-btn-del" title="Delete">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
                          <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                      </button>
                    </form>
                    <?php endif; ?>
                  </div>
                </div>
                <?php endforeach; ?>
              </div>
              <?php endif; ?>
            </div><!-- /att-body -->
          </div><!-- /att-card -->

        </div><!-- /full-width left -->

        <!-- ════ BELOW: Past Timesheets (read-only) ════ -->
        <div style="grid-column:1/-1;">
          <div class="card">
            <div class="card-header" style="display:flex;align-items:center;justify-content:space-between;">
              <h3>📋 Past Timesheets</h3>
              <span style="font-size:.78rem;color:var(--text-3);">Click to view · <?= $isSA ? 'Super Admin can edit any' : 'Read-only for employees' ?></span>
            </div>
            <div class="card-body" style="padding:0;">
              <?php if (!$pastList): ?>
                <div style="padding:32px;text-align:center;color:var(--text-3);">No submitted timesheets yet.</div>
              <?php endif; ?>
              <?php foreach ($pastList as $ts):
                $isSel = $ts['week_start'] === $selectedWeek;
                $canEd = $isSA || in_array($ts['status'], ['draft','rejected'], true);
              ?>
                <div style="display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--surface-3);background:<?= $isSel?'var(--surface-2)':'transparent' ?>;">
                  <div style="flex:1;min-width:0;">
                    <div style="font-weight:600;font-size:.88rem;color:var(--text-1);">
                      Week of <?= e(date('M j, Y', strtotime($ts['week_start']))) ?>
                    </div>
                    <div style="font-size:.76rem;color:var(--text-3);margin-top:2px;">
                      <?= e(number_format((float)$ts['total_hours'],1)) ?> hrs
                      <?php if ($ts['submitted_at']): ?>
                        · Submitted <?= e(date('M j', strtotime($ts['submitted_at']))) ?>
                      <?php endif; ?>
                      <?php if ($ts['reviewed_at']): ?>
                        · Reviewed <?= e(date('M j', strtotime($ts['reviewed_at']))) ?>
                      <?php endif; ?>
                    </div>
                    <?php if ($ts['status']==='rejected' && $ts['rejection_reason']): ?>
                      <div style="font-size:.74rem;color:var(--rose);margin-top:2px;font-style:italic;">
                        "<?= e(substr($ts['rejection_reason'],0,80)) ?><?= strlen($ts['rejection_reason'])>80?'…':'' ?>"
                      </div>
                    <?php endif; ?>
                  </div>
                  <span class="badge badge-<?= e($ts['status']) ?>"><?= e(ucfirst($ts['status'])) ?></span>
                  <a href="?week=<?= e($ts['week_start']) ?>" class="btn btn-outline btn-sm">
                    <?= $canEd ? '✏️ Edit' : '👁 View' ?>
                  </a>
                </div>
              <?php endforeach; ?>
            </div>
          </div>

          <!-- Legend -->
          <div class="card" style="margin-top:16px;">
            <div class="card-header"><h3>📖 Status Guide</h3></div>
            <div class="card-body" style="display:flex;gap:20px;flex-wrap:wrap;font-size:.84rem;">
              <div style="display:flex;align-items:center;gap:8px;"><span class="badge badge-draft">Draft</span><span style="color:var(--text-2);">Saved, not submitted</span></div>
              <div style="display:flex;align-items:center;gap:8px;"><span class="badge badge-pending">Pending</span><span style="color:var(--text-2);">Awaiting HR review</span></div>
              <div style="display:flex;align-items:center;gap:8px;"><span class="badge badge-approved">Approved</span><span style="color:var(--text-2);">Locked — no edits</span></div>
              <div style="display:flex;align-items:center;gap:8px;"><span class="badge badge-rejected">Rejected</span><span style="color:var(--text-2);">Edit &amp; resubmit</span></div>
            </div>
          </div>
        </div>

      </div><!-- /grid -->
      <?php endif; ?>
    </div><!-- /page-body -->
  </div><!-- /main-content -->
</div><!-- /app-shell -->

<style>
/* ── Kronos Table ── */
.ts-kronos-table {
  width: 100%;
  border-collapse: collapse;
  font-size: .82rem;
  min-width: 780px;
}
.ts-kronos-table thead tr {
  background: var(--surface-2);
  border-bottom: 2px solid var(--surface-3);
}
.ts-kronos-table thead th {
  padding: 10px 8px;
  text-align: left;
  font-size: .73rem;
  font-weight: 700;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: .06em;
  white-space: nowrap;
}
.ts-kronos-table tbody tr {
  border-bottom: 1px solid var(--surface-3);
  transition: background .1s;
}
.ts-kronos-table tbody tr:hover { background: var(--surface-2); }
.ts-kronos-table tbody td {
  padding: 7px 8px;
  vertical-align: middle;
}
.kronos-date-cell {
  background: var(--surface-2);
  border-right: 2px solid var(--surface-3);
  text-align: center;
  vertical-align: top !important;
  padding-top: 10px !important;
}
.weekend-row { opacity: .55; }
.day-first-row td { border-top: 2px solid var(--surface-3); }
.kronos-total-row td {
  background: var(--surface-2);
  border-top: 2px solid var(--surface-3);
}
.kronos-input {
  width: 100%;
  background: var(--surface-2);
  border: 1px solid transparent;
  border-radius: 5px;
  color: var(--text-1);
  padding: 5px 7px;
  font-size: .82rem;
  transition: border .15s;
  box-sizing: border-box;
}
.kronos-input:focus { border-color: var(--cyan); outline: none; background: var(--surface-3); }
.kronos-input.field-error { border-color: var(--rose, #f87171) !important; background: rgba(239,68,68,.06) !important; }
.kronos-input-sm { width: 80px; }
.kronos-hrs { width: 66px; text-align: center; }
.kronos-readonly {
  color: var(--text-2);
  font-size: .82rem;
  padding: 2px 4px;
  display: block;
}
.kronos-calc {
  font-weight: 700;
  color: var(--cyan);
  font-size: .84rem;
}
.kronos-add-btn {
  width: 22px; height: 22px;
  border-radius: 50%;
  border: 1px solid var(--cyan);
  color: var(--cyan);
  background: transparent;
  font-size: .9rem;
  cursor: pointer;
  line-height: 1;
  display: inline-flex; align-items: center; justify-content: center;
}
.kronos-add-btn:hover { background: rgba(31,160,192,.15); }
.kronos-del-btn {
  width: 20px; height: 20px;
  border-radius: 50%;
  border: 1px solid var(--rose, #f87171);
  color: var(--rose, #f87171);
  background: transparent;
  font-size: .7rem;
  cursor: pointer;
  margin-top: 2px;
  display: inline-flex; align-items: center; justify-content: center;
}
.kronos-del-btn:hover { background: rgba(239,68,68,.12); }

/* ── Attachments card (redesigned) ───────────────────────── */
.att-card { overflow: hidden; }

.att-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  border-bottom: 1px solid var(--surface-3);
  background: var(--surface-2);
}
.att-header-left { display: flex; align-items: center; gap: 8px; }
.att-header-icon { font-size: 1rem; line-height: 1; }
.att-header-title { font-weight: 700; font-size: .9rem; color: var(--text-1); }
.att-count-badge {
  background: var(--cyan);
  color: #fff;
  font-size: .67rem;
  font-weight: 700;
  padding: 1px 8px;
  border-radius: 20px;
  letter-spacing: .04em;
  line-height: 1.6;
}
.att-header-hint {
  font-size: .73rem;
  color: var(--text-3);
}

.att-body { padding: 18px 20px 20px; }

.att-inline-hint {
  font-size: .78rem;
  color: var(--text-3);
  margin: 6px 0 18px;
  text-align: center;
}
.att-inline-hint strong { color: var(--text-2); }

/* Drop zone */
.att-dropzone {
  border: 2px dashed var(--surface-4);
  border-radius: 12px;
  padding: 30px 20px;
  text-align: center;
  cursor: pointer;
  transition: border-color .2s, background .2s;
  background: var(--surface-1);
  position: relative;
  user-select: none;
  outline: none;
}
.att-dropzone:hover, .att-dropzone:focus, .att-dropzone.drag-over {
  border-color: var(--cyan);
  background: rgba(31,160,192,.06);
}
.att-dropzone.drag-over { border-style: solid; }

.att-drop-inner { pointer-events: none; }
.att-drop-cloud {
  width: 48px; height: 48px;
  border-radius: 50%;
  background: rgba(31,160,192,.1);
  color: var(--cyan);
  display: flex; align-items: center; justify-content: center;
  margin: 0 auto 12px;
  transition: transform .2s;
}
.att-dropzone:hover .att-drop-cloud,
.att-dropzone.drag-over .att-drop-cloud { transform: translateY(-3px); }
.att-drop-title { font-size: .88rem; font-weight: 700; color: var(--text-1); margin: 0 0 4px; }
.att-drop-sub   { font-size: .8rem; color: var(--text-3); margin: 0; }
.att-drop-link  { color: var(--cyan); text-decoration: underline; text-underline-offset: 2px; }

/* Selected file state */
.att-drop-selected {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 8px;
  pointer-events: none;
  justify-content: center;
  flex-wrap: wrap;
}
.att-drop-file-icon { font-size: 1.6rem; line-height: 1; }
.att-drop-file-name {
  font-size: .84rem;
  font-weight: 700;
  color: var(--cyan);
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.att-drop-file-size { font-size: .75rem; color: var(--text-3); }
.att-drop-clear {
  pointer-events: all;
  width: 20px; height: 20px;
  border-radius: 50%;
  border: 1px solid var(--surface-4);
  background: var(--surface-2);
  color: var(--text-2);
  font-size: .65rem;
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: background .15s, color .15s;
  flex-shrink: 0;
}
.att-drop-clear:hover { background: rgba(239,68,68,.15); border-color: rgba(239,68,68,.4); color: var(--rose, #f87171); }

/* File list */
.att-list { display: flex; flex-direction: column; gap: 2px; }
.att-list-label {
  font-size: .72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .07em;
  color: var(--text-3);
  margin-bottom: 8px;
}
.att-file-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--surface-1);
  border: 1px solid var(--surface-3);
  transition: background .15s;
}
.att-file-row:hover { background: var(--surface-2); }
.att-file-thumb { font-size: 1.4rem; line-height: 1; flex-shrink: 0; }
.att-file-info  { flex: 1; min-width: 0; }
.att-file-name {
  font-size: .84rem;
  font-weight: 600;
  color: var(--text-1);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.att-file-meta { font-size: .72rem; color: var(--text-3); margin-top: 2px; }
.att-file-actions { display: flex; gap: 6px; align-items: center; flex-shrink: 0; }
.att-btn {
  width: 30px; height: 30px;
  border-radius: 7px;
  border: 1px solid var(--surface-4);
  background: var(--surface-2);
  color: var(--text-2);
  font-size: .75rem;
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  text-decoration: none;
  transition: background .15s, color .15s, border-color .15s;
}
.att-btn-dl:hover  { background: var(--cyan); border-color: var(--cyan); color: #fff; }
.att-btn-del:hover { background: rgba(239,68,68,.15); border-color: rgba(239,68,68,.4); color: var(--rose, #f87171); }

.att-empty {
  text-align: center;
  padding: 12px 0 4px;
  font-size: .81rem;
  color: var(--text-3);
  font-style: italic;
}

/* Workflow */
.ts-workflow { display:flex; gap:0; align-items:center; }
.ts-workflow-step { display:flex; flex-direction:column; align-items:center; flex:1; position:relative; }
.ts-workflow-step:not(:last-child)::after {
  content:''; position:absolute; top:14px; left:calc(50% + 14px);
  width:calc(100% - 28px); height:2px; background:var(--surface-3);
}
.ts-workflow-step.done::after, .ts-workflow-step.active::after { background:var(--cyan); }
.ts-workflow-dot {
  width:28px; height:28px; border-radius:50%;
  display:flex; align-items:center; justify-content:center;
  font-size:.78rem; font-weight:700;
  background:var(--surface-2); color:var(--text-3); border:2px solid var(--surface-3);
  position:relative; z-index:1;
}
.ts-workflow-step.active .ts-workflow-dot { background:var(--cyan); color:#000; border-color:var(--cyan); }
.ts-workflow-step.done .ts-workflow-dot { background:rgba(31,160,192,.2); color:var(--cyan); border-color:var(--cyan); }
.ts-workflow-step.rejected .ts-workflow-dot { background:rgba(239,68,68,.15); color:var(--rose); border-color:var(--rose); }
.ts-workflow-label { font-size:.7rem; color:var(--text-3); margin-top:5px; text-align:center; white-space:nowrap; }
.rejection-notice { margin-top:12px; background:rgba(239,68,68,.08); border:1px solid rgba(239,68,68,.25); border-radius:8px; padding:10px 14px; }
.rejection-notice .reason { font-size:.84rem; color:var(--text-2); margin-top:4px; }
.ts-dirty-indicator {
  font-size: .76rem;
  font-weight: 700;
  padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid var(--surface-3);
  background: var(--surface-2);
  color: var(--text-3);
}
.ts-dirty-indicator.dirty {
  color: var(--amber);
  border-color: rgba(245,158,11,.35);
  background: rgba(245,158,11,.1);
}
.ts-mini-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
}
.ts-mini-stat {
  padding: 12px 14px;
  border-radius: 10px;
  border: 1px solid var(--surface-3);
  background: var(--surface-2);
  transition: border-color .15s, transform .15s, box-shadow .15s;
}
.ts-mini-stat:hover {
  border-color: var(--cyan);
  box-shadow: var(--shadow-cyan);
  transform: translateY(-1px);
}
.ts-mini-stat .label {
  display: block;
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--text-3);
  margin-bottom: 4px;
}
.ts-mini-stat strong {
  color: var(--text-1);
  font-size: .92rem;
}
.ts-day-jump {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(108px, 1fr));
  gap: 10px;
}
.ts-day-chip {
  border: 1px solid var(--surface-3);
  background: var(--surface-2);
  color: var(--text-1);
  border-radius: 10px;
  padding: 10px 12px;
  text-align: left;
  cursor: pointer;
  transition: border-color .15s, transform .15s, box-shadow .15s;
}
.ts-day-chip:hover,
.ts-day-chip.active {
  border-color: var(--cyan);
  box-shadow: var(--shadow-cyan);
  transform: translateY(-1px);
}
.ts-day-chip .day,
.ts-day-chip .date,
.ts-day-chip .hours {
  display: block;
}
.ts-day-chip .day { font-weight: 700; font-size: .82rem; }
.ts-day-chip .date { font-size: .72rem; color: var(--text-3); margin-top: 2px; }
.ts-day-chip .hours { font-size: .78rem; color: var(--cyan); margin-top: 6px; }
.page-header button[onclick="autoFillWeek()"]:not([type]) { display: none; }
</style>

<script>
// ── PROJECT ROW COUNTER ────────────────────────────────────
var projectRowCounter = <?= count($projectRows) ?>;

// ── RECALC PROJECT TOTALS ──────────────────────────────────
function recalcProjectTotals() {
  var tbody = document.getElementById('project-body');
  if (!tbody) return;
  var rows = tbody.querySelectorAll('tr.project-row');
  var dayTotals = {};
  var grandTotal = 0;

  rows.forEach(function(tr) {
    var ri = tr.dataset.ri;
    var rowTotal = 0;
    tr.querySelectorAll('.project-hrs-input').forEach(function(inp) {
      var v = parseFloat(inp.value) || 0;
      var di = inp.dataset.di;
      dayTotals[di] = (dayTotals[di] || 0) + v;
      rowTotal += v;
    });
    var rowTotalCell = document.querySelector('.project-row-total[data-ri="' + ri + '"]');
    if (rowTotalCell) rowTotalCell.textContent = rowTotal.toFixed(1);
    grandTotal += rowTotal;
  });

  // Update day total footer cells
  for (var d = 0; d < 7; d++) {
    var cell = document.querySelector('.project-day-total-cell[data-di="' + d + '"]');
    if (cell) {
      var v = dayTotals[d] || 0;
      cell.textContent = v > 0 ? v.toFixed(1) : '–';
    }
  }

  var rounded = Math.round(grandTotal * 10) / 10;
  var wt = document.getElementById('week-total');
  if (wt) wt.textContent = rounded.toFixed(1);
  var stat = document.getElementById('week-total-stat');
  if (stat) stat.textContent = rounded.toFixed(1);
  var rc = document.getElementById('row-count-stat');
  if (rc) rc.textContent = rows.length;
}

function setDirty(flag) {
  window._tsDirty = flag;
  var el = document.getElementById('ts-dirty-indicator');
  if (!el) return;
  if (flag) {
    el.textContent = 'Unsaved changes';
    el.style.color = 'var(--amber)';
  } else {
    el.textContent = 'Saved';
    el.style.color = 'var(--green)';
  }
}

function clearWeek() {
  if (!confirm('Clear all hours for this week?')) return;
  document.querySelectorAll('.project-hrs-input').forEach(function(inp) { inp.value = ''; });
  recalcProjectTotals();
  setDirty(true);
}

function copyLastWeek() {
  if (!confirm('Copy project rows from last submitted week? This will replace current rows.')) return;
  fetch('?action=last_week', {headers:{'X-Requested-With':'XMLHttpRequest'}})
    .then(function(r){return r.json();})
    .then(function(data){
      if (!data.success || !data.data) {
        alert('No previous week data found.');
        return;
      }
      var entries = data.data.entries || [];
      var tbody = document.getElementById('project-body');
      tbody.innerHTML = '';
      projectRowCounter = 0;
      entries.forEach(function(ent) {
        var meta = {};
        try { meta = JSON.parse(ent.description || '{}'); } catch(e) {}
        var dayHours = meta.day_hours || Array(7).fill(0);
        addProjectRow({
          client: meta.client || '',
          project: ent.project || '',
          task: ent.task || '',
          day_hours: dayHours
        });
      });
      if (entries.length === 0) addProjectRow();
      recalcProjectTotals();
      setDirty(true);
      if (typeof Toast !== 'undefined') Toast.success('Copied', 'Last submitted week copied.');
    });
}

function addProjectRow(data, skipDirty) {
  var tbody = document.getElementById('project-body');
  var ri = projectRowCounter++;
  data = data || {};
  var dayHours = data.day_hours || Array(7).fill(0);

  var dayKeys = ['mon','tue','wed','thu','fri','sat','sun'];
  var dayCells = '';
  <?php foreach ($dayDefs as $dd): ?>
  (function() {
    var di = <?= $dd['index'] ?>;
    var isWe = <?= in_array($dd['key'],['sat','sun']) ? 'true' : 'false' ?>;
    var h = parseFloat(dayHours[di]) || 0;
    dayCells += '<td class="project-day-cell' + (isWe?' weekend-col':'') + '">' +
      '<input type="number" name="rows[' + ri + '][day_hours][' + di + ']"' +
      ' value="' + (h > 0 ? h.toFixed(1) : '') + '"' +
      ' min="0" max="24" step="0.5" placeholder="–"' +
      ' class="kronos-input kronos-input-sm project-hrs-input' + (isWe?' weekend-hrs':'') + '"' +
      ' data-ri="' + ri + '" data-di="' + di + '" oninput="recalcProjectTotals()">' +
      '</td>';
  })();
  <?php endforeach; ?>

  var tr = document.createElement('tr');
  tr.className = 'project-row';
  tr.dataset.ri = ri;
  tr.innerHTML =
    '<td><input type="text" name="rows[' + ri + '][client]" value="' + (data.client||'') + '" placeholder="Acme Corp" class="kronos-input project-client-input" required maxlength="100"></td>' +
    '<td><input type="text" name="rows[' + ri + '][project]" value="' + (data.project||'') + '" placeholder="Website Design" class="kronos-input project-project-input" required maxlength="100"></td>' +
    '<td><input type="text" name="rows[' + ri + '][task]" value="' + (data.task||'') + '" placeholder="Design" class="kronos-input kronos-input-sm project-task-input" required maxlength="100"></td>' +
    dayCells +
    '<td class="project-row-total" data-ri="' + ri + '" style="text-align:center;font-weight:700;color:var(--cyan);font-size:.85rem;">0.0</td>' +
    '<td style="text-align:center;"><button type="button" class="kronos-del-btn" onclick="removeProjectRow(this)" title="Remove">✕</button></td>';

  tbody.appendChild(tr);
  if (!skipDirty) { recalcProjectTotals(); setDirty(true); }
}

function removeProjectRow(btn) {
  var tr = btn.closest('tr');
  if (!tr) return;
  tr.classList.add('row-removing');
  setTimeout(function() {
    if (tr.parentNode) tr.parentNode.removeChild(tr);
    recalcProjectTotals();
    setDirty(true);
  }, 180);
}

function loadDraft(draftId, weekStart) {
  if (!confirm('Load this draft? Unsaved changes will be lost.')) return;
  window.location.href = '?week=' + weekStart;
}

function submitTs(action, btn) {
  // ── Mandatory field validation before submit/resubmit ───────
  if (action === 'submit' || action === 'resubmit') {
    var rows = document.querySelectorAll('#project-body .project-row');
    var valid = true;
    var firstBad = null;

    rows.forEach(function(row) {
      var client  = row.querySelector('.project-client-input');
      var project = row.querySelector('.project-project-input');
      var task    = row.querySelector('.project-task-input');
      var hrsInputs = row.querySelectorAll('.project-hrs-input');
      var rowTotal  = 0;
      hrsInputs.forEach(function(h){ rowTotal += parseFloat(h.value||0); });

      [client, project, task].forEach(function(inp) {
        if (inp && inp.value.trim() === '') {
          inp.classList.add('field-error');
          valid = false;
          if (!firstBad) firstBad = inp;
        } else if (inp) {
          inp.classList.remove('field-error');
        }
      });

      if (rowTotal === 0) {
        hrsInputs.forEach(function(h){ h.classList.add('field-error'); });
        valid = false;
        if (!firstBad) firstBad = hrsInputs[0];
      } else {
        hrsInputs.forEach(function(h){ h.classList.remove('field-error'); });
      }
    });

    if (!valid) {
      if (firstBad) firstBad.scrollIntoView({behavior:'smooth', block:'center'});
      showValidationBanner('Please fill in all required fields (Client, Project, Task, and at least one hour per row) before submitting.');
      return;
    }
    hideValidationBanner();
  }

  document.getElementById('ts-action').value = action;
  if (btn) btn.classList.add('btn-loading');
  setDirty(false);
  document.getElementById('ts-form').submit();
}

function showValidationBanner(msg) {
  var b = document.getElementById('ts-validation-banner');
  if (!b) {
    b = document.createElement('div');
    b.id = 'ts-validation-banner';
    b.style.cssText = 'background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);border-radius:8px;padding:10px 16px;font-size:.84rem;color:var(--rose,#f87171);margin:0 20px 12px;display:flex;align-items:center;gap:8px;';
    b.innerHTML = '<span style="font-size:1rem;">⚠️</span><span id="ts-validation-msg"></span>';
    var form = document.getElementById('ts-form');
    var btns = form ? form.querySelector('[style*="padding:0 20px 20px"]') : null;
    if (btns) btns.parentNode.insertBefore(b, btns);
  }
  document.getElementById('ts-validation-msg').textContent = msg;
  b.style.display = 'flex';
  b.scrollIntoView({behavior:'smooth', block:'nearest'});
}
function hideValidationBanner() {
  var b = document.getElementById('ts-validation-banner');
  if (b) b.style.display = 'none';
}

// Clear field-error on input
document.querySelectorAll('.kronos-input').forEach(function(inp) {
  inp.addEventListener('input', function(){ this.classList.remove('field-error'); hideValidationBanner(); });
});

// ── Attachment upload handlers ──────────────────────────────
function handleFileSelect(input) {
  var inner    = document.getElementById('att-drop-inner');
  var selected = document.getElementById('att-drop-selected');
  var nameEl   = document.getElementById('att-drop-file-name');
  var sizeEl   = document.getElementById('att-drop-file-size');
  var iconEl   = document.getElementById('att-drop-file-icon');

  if (!input.files || !input.files[0]) return;
  var f = input.files[0];

  var isPdf = f.type === 'application/pdf' || f.name.match(/\.pdf$/i);
  iconEl.textContent = isPdf ? '📄' : '🖼️';
  nameEl.textContent = f.name.length > 28 ? f.name.substring(0, 25) + '…' : f.name;
  sizeEl.textContent = (f.size / 1024).toFixed(1) + ' KB';

  if (inner)    inner.style.display    = 'none';
  if (selected) selected.style.display = 'flex';
  document.getElementById('upload-zone').classList.add('has-file');
}

function clearFileSelect(event) {
  event.stopPropagation();
  var inner    = document.getElementById('att-drop-inner');
  var selected = document.getElementById('att-drop-selected');
  var fi       = document.getElementById('ts_file');

  if (fi) fi.value = '';
  if (inner)    inner.style.display    = 'block';
  if (selected) selected.style.display = 'none';
  document.getElementById('upload-zone').classList.remove('has-file');
}

var zone = document.getElementById('upload-zone');
if (zone) {
  zone.addEventListener('dragover', function(e) {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', function(e) {
    if (!zone.contains(e.relatedTarget)) zone.classList.remove('drag-over');
  });
  zone.addEventListener('drop', function(e) {
    e.preventDefault();
    zone.classList.remove('drag-over');
    var fi = document.getElementById('ts_file');
    if (e.dataTransfer.files.length) {
      // Assign via DataTransfer
      try { fi.files = e.dataTransfer.files; } catch(ex) {}
      handleFileSelect(fi);
    }
  });
}

var tsForm = document.getElementById('ts-form');
if (tsForm) {
  tsForm.addEventListener('input', function(e) {
    setDirty(true);
  });
}

window.addEventListener('beforeunload', function(e) {
  if (!window._tsDirty) return;
  e.preventDefault();
  e.returnValue = '';
});

// ── AUTO DISMISS ALERTS ─────────────────────────────────────
document.querySelectorAll('.alert[data-auto-dismiss]').forEach(function(a) {
  var d = parseInt(a.dataset.autoDismiss,10) || 5000;
  setTimeout(function() {
    a.style.opacity='0'; a.style.transition='opacity .4s';
    setTimeout(function(){a&&a.parentNode&&a.parentNode.removeChild(a);},400);
  }, d);
});

// ── INITIAL CALC ─────────────────────────────────────────────
recalcProjectTotals();
setDirty(false);
</script>

<?php pageFooter(); ?>
</body>
</html>
