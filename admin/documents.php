<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

$empListQ = $db->query(
    "SELECT id, full_name, role
     FROM users
     WHERE role IN ('employee','hr_admin') AND status = 'active'
     ORDER BY full_name ASC"
);
$empList = $empListQ->fetchAll();

$ALLOWED_STATUSES = ['pending', 'approved', 'rejected', 'more_info_needed', 'all'];
$ALLOWED_DOC_TYPES = [
    'drivers_license', 'i9', 'passport', 'work_authorization',
    'h1b_i797', 'social_security', 'education', 'direct_deposit', 'other',
];
$docLabels = [
    'drivers_license'    => "Driver's License / State ID",
    'i9'                 => 'Form I-9',
    'passport'           => 'Passport',
    'work_authorization' => 'Work Authorization / EAD',
    'h1b_i797'           => 'H-1B Approval (I-797)',
    'social_security'    => 'Social Security Card',
    'education'          => 'Educational Certificates',
    'direct_deposit'     => 'Direct Deposit / Voided Check',
    'other'              => 'Other Document',
];

$msg = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true);

    if (isset($_POST['action']) && $_POST['action'] === 'hr_upload') {
        $targetUserId = sanitizeInt($_POST['target_user_id'] ?? 0, 1);
        $docType      = validateEnum($_POST['doc_type_upload'] ?? '', $ALLOWED_DOC_TYPES) ?? '';
        $documentName = $docType === 'other' ? sanitizeString($_POST['document_name'] ?? '', 180) : null;

        if (!$targetUserId || !$docType) {
            $msg = 'Please select an employee and document type.';
            $msgType = 'error';
        } elseif ($docType === 'other' && $documentName === '') {
            $msg = 'Please enter a title for this document.';
            $msgType = 'error';
        } elseif (empty($_FILES['doc_file']) || ($_FILES['doc_file']['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
            $msg = 'Please select a file to upload.';
            $msgType = 'error';
        } else {
            $empCheck = $db->prepare(
                "SELECT id, full_name, email
                 FROM users
                 WHERE id = ?
                   AND role IN ('employee','hr_admin')
                   AND status = 'active'
                 LIMIT 1"
            );
            $empCheck->execute([$targetUserId]);
            $targetEmp = $empCheck->fetch();

            if (!$targetEmp) {
                $msg = 'User not found or not eligible.';
                $msgType = 'error';
            } else {
                $result = handleDocumentUpload($_FILES['doc_file'], $docType, $targetUserId, true, null, $documentName);
                if ($result['success']) {
                    $label = $docType === 'other' ? ($documentName ?: 'Other Document') : ($docLabels[$docType] ?? $docType);
                    auditLog('hr_document_upload', 'documents', $result['id'] ?? null, [
                        'doc_type'     => $docType,
                        'uploaded_for' => $targetUserId,
                        'employee'     => $targetEmp['full_name'],
                        'uploaded_by'  => $user['id'],
                    ]);
                    createNotification(
                        (int)$targetUserId,
                        'doc_uploaded',
                        'Document Uploaded',
                        "HR has uploaded your {$label}. Please review it in your documents.",
                        '/employee/documents.php'
                    );
                    sendMail(
                        $targetEmp['email'],
                        'Document Uploaded - CloudFen HR Portal',
                        emailTemplate(
                            'Document Uploaded by HR',
                            "<p>HR has uploaded your <strong>" . e($label) . "</strong> on your behalf.</p>" .
                            "<a href='" . e(APP_URL) . "/employee/documents.php' style='background:#2b8fd4;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:16px;'>View My Documents</a>"
                        )
                    );
                    $msg = 'Document uploaded successfully for ' . e($targetEmp['full_name']) . '.';
                    $msgType = 'success';
                } else {
                    $msg = $result['message'];
                    $msgType = 'error';
                }
            }
        }
    } else {
        $docId  = sanitizeInt($_POST['doc_id'] ?? 0, 1);
        $EXPIRY_REQUIRED_TYPES = ['drivers_license', 'passport', 'work_authorization', 'h1b_i797'];
        $action = validateEnum($_POST['action'] ?? '', ['approve', 'reject', 'more_info', 'update_expiry']);
        $reason = sanitizeString($_POST['reason'] ?? '', 1000);

        if (!$docId || !$action) {
            $msg = 'Invalid request.';
            $msgType = 'error';
        } else {
            $ds = $db->prepare(
                "SELECT d.*, u.email, u.full_name, u.id AS emp_id, u.role AS owner_role
                 FROM documents d
                 JOIN users u ON u.id = d.user_id
                 WHERE d.id = ?
                 LIMIT 1"
            );
            $ds->execute([$docId]);
            $doc = $ds->fetch();

            if ($doc && $doc['owner_role'] === 'super_admin' && $user['role'] !== 'super_admin') {
                // Mirrors the list query's own scoping (u.role IN ('employee','hr_admin'))
                // — hr_admin peer-reviews other hr_admins' onboarding docs same as employees',
                // but a super_admin's documents are out of hr_admin's reach entirely.
                $doc = false;
            }

            if (!$doc) {
                $msg = 'Document not found.';
                $msgType = 'error';
            } elseif (in_array($action, ['approve', 'reject', 'more_info'], true) && (int)$doc['emp_id'] === (int)$user['id']) {
                // Reviewer cannot approve/reject their own uploaded compliance document.
                $msg = 'You cannot review your own document. Ask another HR/Super Admin to review it.';
                $msgType = 'error';
            } elseif (($action === 'reject' || $action === 'more_info') && !$reason) {
                $msg = 'A reason is required.';
                $msgType = 'error';
            } elseif ($action === 'update_expiry') {
                // Standalone action — must never touch status/reviewed_by/notifications.
                $expiry = sanitizeDate($_POST['expiry_date'] ?? '');
                if (!$expiry) {
                    $msg = 'Please provide a valid expiry date.'; $msgType = 'error';
                } else {
                    $db->prepare(
                        "UPDATE documents SET expiry_date = ?, expiry_alerted_60 = 0, expiry_alerted_30 = 0 WHERE id = ?"
                    )->execute([$expiry, $docId]);
                    auditLog('document_expiry_updated', 'documents', $docId, ['expiry_date' => $expiry]);
                    $msg = 'Expiry date updated successfully.'; $msgType = 'success';
                }
            } else {
                $newStatus = [
                    'approve'   => 'approved',
                    'reject'    => 'rejected',
                    'more_info' => 'more_info_needed',
                ][$action];

                $reviewStmt = $db->prepare(
                    "UPDATE documents
                     SET status = ?, rejection_reason = ?, reviewed_by = ?, reviewed_at = NOW()
                     WHERE id = ? AND status IN ('pending', 'more_info_needed')"
                );
                $reviewStmt->execute([$newStatus, $reason ?: null, $user['id'], $docId]);
                if ($reviewStmt->rowCount() === 0) {
                    // Already reviewed by someone else since this page loaded (double-submit/race)
                    // — nothing changed, so skip audit/notify/email entirely, not just skip_action.
                    $msg = 'This document was already reviewed (current status: ' . e($doc['status']) . '). Refresh to see the latest state.';
                    $msgType = 'error';
                    goto review_race_skip;
                }

                // For approve: check expiry is provided for doc types that require it
                if ($action === 'approve' && in_array($doc['doc_type'], $EXPIRY_REQUIRED_TYPES, true)) {
                    $expiry = sanitizeDate($_POST['expiry_date'] ?? '');
                    if (!$expiry) {
                        $msg = 'An expiry date is required to approve this document type.'; $msgType = 'error';
                        goto skip_action;
                    }
                    if (strtotime($expiry) <= time()) {
                        $msg = 'Expiry date must be in the future.'; $msgType = 'error';
                        goto skip_action;
                    }
                    $db->prepare(
                        "UPDATE documents SET expiry_date = ?, expiry_alerted_60 = 0, expiry_alerted_30 = 0 WHERE id = ?"
                    )->execute([$expiry, $docId]);
                } elseif ($action === 'approve' && !empty($_POST['expiry_date'])) {
                    $expiry = sanitizeDate($_POST['expiry_date'] ?? '');
                    if ($expiry) {
                        $db->prepare("UPDATE documents SET expiry_date = ?, expiry_alerted_60 = 0, expiry_alerted_30 = 0 WHERE id = ?")->execute([$expiry, $docId]);
                    }
                }

                skip_action:
                $label = $doc['doc_type'] === 'other' && !empty($doc['document_name'])
                    ? e($doc['document_name'])
                    : ($docLabels[$doc['doc_type']] ?? e($doc['doc_type']));
                auditLog('document_' . $action, 'documents', $docId, [
                    'doc_type' => $doc['doc_type'],
                    'reason'   => $reason,
                ]);

                $notifMap = [
                    'approved' => [
                        'Document Approved',
                        "Your {$label} has been approved.",
                    ],
                    'rejected' => [
                        'Document Rejected',
                        "Your {$label} was rejected. Reason: {$reason}",
                    ],
                    'more_info_needed' => [
                        'More Info Needed',
                        "More info is needed for your {$label}: {$reason}",
                    ],
                ];
                [$nTitle, $nMsg] = $notifMap[$newStatus];

                createNotification((int)$doc['emp_id'], 'doc_' . $action, $nTitle, $nMsg, '/employee/documents.php');

                if ($newStatus === 'approved') {
                    $empBody = "<p>Your <strong>" . e($label) . "</strong> has been <span style='color:#1ab89a;font-weight:700;'>approved</span>.</p>";
                } elseif ($newStatus === 'rejected') {
                    $empBody = "<p>Your <strong>" . e($label) . "</strong> was <span style='color:#ef4444;font-weight:700;'>rejected</span>.</p><p><strong>Reason:</strong> " . e($reason) . "</p><p>Please log in to re-upload.</p>";
                } else {
                    $empBody = "<p>HR needs more information for your <strong>" . e($label) . "</strong>.</p><p><strong>Note:</strong> " . e($reason) . "</p>";
                }

                $mailSent = sendMail(
                    $doc['email'],
                    $nTitle . ' - CloudFen HR Portal',
                    emailTemplate(
                        $nTitle,
                        $empBody . "<a href='" . e(APP_URL) . "/employee/documents.php' style='background:#2b8fd4;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:16px;'>View My Documents</a>"
                    )
                );
                if (!$mailSent) {
                    error_log('CloudFen: document status email failed to: ' . $doc['email']);
                }

                if ($newStatus === 'approved') {
                    checkOnboardingComplete((int)$doc['emp_id']);
                }

                $msg = 'Document ' . e($newStatus) . ' successfully.';
                $msgType = 'success';

                review_race_skip:
                ; // no-op — goto target
            }
        }
    }
}

$filterStatus = validateEnum($_GET['status'] ?? 'pending', $ALLOWED_STATUSES) ?? 'pending';
$filterType   = isset($_GET['doc_type']) ? (validateEnum($_GET['doc_type'], $ALLOWED_DOC_TYPES) ?? '') : '';
$focusDocId   = sanitizeInt($_GET['doc_id'] ?? 0, 1) ?? 0;

$where = ['1=1'];
$params = [];
if ($filterStatus !== 'all') {
    $where[] = 'd.status = ?';
    $params[] = $filterStatus;
}
if ($filterType) {
    $where[] = 'd.doc_type = ?';
    $params[] = $filterType;
}

$docQ = $db->prepare(
    "SELECT d.*, u.full_name, u.email, u.employee_type, r.full_name AS reviewer_name
     FROM documents d
     JOIN users u ON u.id = d.user_id
     LEFT JOIN users r ON r.id = d.reviewed_by
     WHERE u.role IN ('employee','hr_admin') AND " . implode(' AND ', $where) . "
     ORDER BY d.uploaded_at ASC
     LIMIT 100"
);
$docQ->execute($params);
$docs = $docQ->fetchAll();

$focusDoc = null;
if (!$focusDocId && !empty($docs)) {
    $focusDocId = (int)($docs[0]['id'] ?? 0);
}
if ($focusDocId) {
    $fs = $db->prepare(
        "SELECT d.*, u.full_name, u.email, u.employee_type, u.role AS owner_role
         FROM documents d
         JOIN users u ON u.id = d.user_id
         WHERE d.id = ?
         LIMIT 1"
    );
    $fs->execute([$focusDocId]);
    $focusDoc = $fs->fetch();
    if ($focusDoc && $focusDoc['owner_role'] === 'super_admin' && $user['role'] !== 'super_admin') {
        // Mirrors the list query's own scoping — see the POST handler above.
        $focusDoc = null;
    }
}

$focusDocMime = (string)($focusDoc['mime_type'] ?? '');
$focusDocIsPdf = $focusDocMime === 'application/pdf';
$focusDocIsImage = in_array($focusDocMime, ['image/jpeg', 'image/png'], true);
$focusDocViewUrl = $focusDoc ? '/admin/view_doc.php?id=' . (int)$focusDoc['id'] : '';
$focusDocDownloadUrl = $focusDoc ? '/admin/view_doc.php?id=' . (int)$focusDoc['id'] . '&dl=1' : '';

$flashType  = $msgType === 'success' ? 'success' : ($msgType === 'error' ? 'error' : '');
$flashTitle = $msg ? ($msgType === 'success' ? 'Action Successful' : 'Error') : '';
pageHead('Document Review', $flashType, $flashTitle, $msg);
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'documents'); ?>
  <div class="main-content">
    <?php renderTopbar('Document Review Queue', $user); ?>
    <div class="page-body">
      <div class="page-header">
        <h1>Document Review</h1>
        <p>Review, approve, reject, or request more information for employee-submitted documents.</p>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <?php
      $safeFilterStatus = (string)$filterStatus;
      $safeFilterType = (string)$filterType;
      ?>

      <div class="doc-shell-card doc-upload-card">
        <div class="card-body doc-shell-card-body">
          <div class="doc-section-heading">
            <div class="doc-section-icon">UP</div>
            <div>
              <strong>Upload Document for Employee</strong>
              <p>Select the employee, choose the document type, and upload the file.</p>
            </div>
          </div>
          <form method="POST" enctype="multipart/form-data" id="hr-upload-form">
            <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
            <input type="hidden" name="action" value="hr_upload">
            <div class="doc-upload-grid">
              <div class="doc-input-wrap">
                <label class="doc-input-label">Employee *</label>
                <select name="target_user_id" class="form-control doc-select" required>
                  <option value="">Select Employee...</option>
                  <?php foreach ($empList as $emp): ?>
                    <option value="<?= (int)$emp['id'] ?>"><?= e($emp['full_name']) ?><?= $emp['role'] === 'hr_admin' ? ' (HR Admin)' : '' ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="doc-input-wrap">
                <label class="doc-input-label">Document Type *</label>
                <select name="doc_type_upload" id="hr-doc-type-select" class="form-control doc-select" required onchange="hrToggleTitleField()">
                  <option value="">Select Type...</option>
                  <?php foreach ($docLabels as $k => $v): ?>
                    <option value="<?= e($k) ?>"><?= e($v) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
            </div>

            <div class="doc-input-wrap" id="hr-doc-title-wrap" style="display:none;margin-bottom:14px;">
              <label class="doc-input-label">Document Title *</label>
              <input type="text" name="document_name" id="hr-doc-title-input" maxlength="180"
                     placeholder="e.g. Bachelor's Degree Certificate" class="form-control doc-select">
            </div>

            <input type="file" name="doc_file" id="hr-doc-file" accept=".pdf,.jpg,.jpeg,.png" style="display:none;">
            <div class="att-dropzone" id="hr-drop-zone" tabindex="0" role="button" aria-label="Upload document" onclick="document.getElementById('hr-doc-file').click()">
              <div class="att-drop-inner" id="hr-drop-inner">
                <div class="att-drop-cloud">Upload</div>
                <p class="att-drop-title">Drop file here</p>
                <p class="att-drop-sub">or <span class="att-drop-link">browse files</span> - PDF, JPG, PNG - max 10MB</p>
              </div>
              <div class="att-drop-selected" id="hr-drop-selected" style="display:none;">
                <div class="att-drop-file-icon" id="hr-drop-file-icon">FILE</div>
                <div class="att-drop-file-name" id="hr-drop-file-name"></div>
                <div class="att-drop-file-size" id="hr-drop-file-size"></div>
                <button type="button" class="att-drop-clear" onclick="hrClearFile(event)" title="Remove">X</button>
              </div>
            </div>

            <div class="doc-upload-actions">
              <button type="submit" class="btn btn-primary" id="hr-upload-btn">Upload Document</button>
            </div>
          </form>
          <div id="hr-upload-status" class="doc-upload-status"></div>
        </div>
      </div>

      <div class="doc-shell-card" style="margin-bottom:20px;">
        <div class="card-body doc-filter-body">
          <form method="GET" class="doc-filter-row">
            <select name="status" class="form-control doc-select doc-filter-select" onchange="this.form.submit()">
              <option value="pending" <?= $filterStatus === 'pending' ? 'selected' : '' ?>>Pending Review</option>
              <option value="approved" <?= $filterStatus === 'approved' ? 'selected' : '' ?>>Approved</option>
              <option value="rejected" <?= $filterStatus === 'rejected' ? 'selected' : '' ?>>Rejected</option>
              <option value="more_info_needed" <?= $filterStatus === 'more_info_needed' ? 'selected' : '' ?>>More Info Needed</option>
              <option value="all" <?= $filterStatus === 'all' ? 'selected' : '' ?>>All Documents</option>
            </select>
            <select name="doc_type" class="form-control doc-select doc-filter-select" onchange="this.form.submit()">
              <option value="">All Document Types</option>
              <?php foreach ($docLabels as $k => $v): ?>
                <option value="<?= e($k) ?>" <?= $filterType === $k ? 'selected' : '' ?>><?= e($v) ?></option>
              <?php endforeach; ?>
            </select>
            <span class="doc-count"><?= count($docs) ?> document(s)</span>
          </form>
        </div>
      </div>

      <div class="grid-2" style="gap:24px;align-items:start;">
        <div class="card doc-shell-card">
          <div class="card-header"><h3>Queue</h3></div>
          <div class="card-body doc-queue-body">
            <?php if (!$docs): ?>
              <div class="doc-empty-state">No documents in this category.</div>
            <?php endif; ?>
            <?php foreach ($docs as $d): ?>
              <?php
              $queueDocType = (string)($d['doc_type'] ?? '');
              $queueDocLabel = $queueDocType === 'other' && !empty($d['document_name'])
                  ? (string)$d['document_name']
                  : (string)($docLabels[$queueDocType] ?? $queueDocType ?: 'Document');
              $queueEmployeeName = trim((string)($d['full_name'] ?? ''));
              $queueEmployeeType = trim((string)($d['employee_type'] ?? ''));
              $queueFileName = trim((string)($d['file_name'] ?? ''));
              $queueReviewerName = trim((string)($d['reviewer_name'] ?? ''));
              $queueStatus = (string)($d['status'] ?? 'pending');
              $queueUploadedAt = !empty($d['uploaded_at']) ? date('M j, Y g:i a', strtotime((string)$d['uploaded_at'])) : 'Upload time unavailable';
              ?>
              <a href="?status=<?= e($safeFilterStatus) ?>&doc_type=<?= e($safeFilterType) ?>&doc_id=<?= (int)$d['id'] ?>"
                 class="doc-queue-item<?= $focusDocId === (int)$d['id'] ? ' is-active' : '' ?>">
                <div class="doc-queue-icon">DOC</div>
                <div class="doc-queue-copy">
                  <div class="doc-queue-name"><?= e($queueEmployeeName !== '' ? $queueEmployeeName : 'Employee') ?></div>
                  <div class="doc-queue-meta"><?= e($queueDocLabel) ?> | <?= e($queueFileName !== '' ? $queueFileName : 'Unnamed file') ?></div>
                  <div class="doc-queue-time"><?= e($queueUploadedAt) ?><?php if ($queueReviewerName !== ''): ?> | Reviewed by <?= e($queueReviewerName) ?><?php endif; ?><?php if ($queueEmployeeType !== ''): ?> | <?= e($queueEmployeeType) ?><?php endif; ?></div>
                </div>
                <span class="badge badge-<?= $queueStatus === 'more_info_needed' ? 'info' : e($queueStatus) ?>">
                  <?= e(ucfirst(str_replace('_', ' ', $queueStatus))) ?>
                </span>
              </a>
            <?php endforeach; ?>
          </div>
        </div>

        <div>
          <?php if ($focusDoc): ?>
            <?php
            $focusDocType = (string)($focusDoc['doc_type'] ?? '');
            $focusDocLabel = $focusDocType === 'other' && !empty($focusDoc['document_name'])
                ? (string)$focusDoc['document_name']
                : (string)($docLabels[$focusDocType] ?? $focusDocType ?: 'Document');
            $focusEmployeeName = trim((string)($focusDoc['full_name'] ?? ''));
            $focusEmployeeType = trim((string)($focusDoc['employee_type'] ?? ''));
            $focusFileName = trim((string)($focusDoc['file_name'] ?? ''));
            $focusStatus = (string)($focusDoc['status'] ?? 'pending');
            $focusUploadedDate = !empty($focusDoc['uploaded_at']) ? date('M j, Y', strtotime((string)$focusDoc['uploaded_at'])) : 'Unknown date';
            $focusUploadedTime = !empty($focusDoc['uploaded_at']) ? date('g:i a', strtotime((string)$focusDoc['uploaded_at'])) : 'Unknown time';
            $focusFileSizeKb = isset($focusDoc['file_size']) ? (string)round(((int)$focusDoc['file_size']) / 1024) : '0';
            $focusDocumentCode = trim((string)($focusDoc['doc_id'] ?? ''));
            $focusReason = trim((string)($focusDoc['rejection_reason'] ?? ''));
            ?>
            <div class="card doc-shell-card">
              <div class="card-header">
                <div>
                  <h3><?= e($focusDocLabel) ?></h3>
                  <div style="font-size:.82rem;color:var(--text-3);"><?= e($focusEmployeeName !== '' ? $focusEmployeeName : 'Employee') ?><?php if ($focusEmployeeType !== ''): ?> | <?= e($focusEmployeeType) ?><?php endif; ?></div>
                </div>
                <span class="badge badge-<?= $focusStatus === 'more_info_needed' ? 'info' : e($focusStatus) ?>">
                  <?= e(ucfirst(str_replace('_', ' ', $focusStatus))) ?>
                </span>
              </div>
              <div class="card-body">
                <div class="doc-summary-grid">
                  <div class="doc-summary-card">
                    <div class="doc-summary-label">Employee</div>
                    <div class="doc-summary-value"><?= e($focusEmployeeName !== '' ? $focusEmployeeName : 'Employee') ?></div>
                    <div class="doc-summary-sub"><?= e($focusEmployeeType !== '' ? $focusEmployeeType : 'Employee record') ?></div>
                  </div>
                  <div class="doc-summary-card">
                    <div class="doc-summary-label">File</div>
                    <div class="doc-summary-value" style="word-break:break-word;"><?= e($focusFileName !== '' ? $focusFileName : 'Unnamed file') ?></div>
                    <div class="doc-summary-sub"><?= e($focusFileSizeKb) ?> KB</div>
                  </div>
                  <div class="doc-summary-card">
                    <div class="doc-summary-label">Uploaded</div>
                    <div class="doc-summary-value"><?= e($focusUploadedDate) ?></div>
                    <div class="doc-summary-sub"><?= e($focusUploadedTime) ?></div>
                  </div>
                  <div class="doc-summary-card">
                    <div class="doc-summary-label">Document ID</div>
                    <div class="doc-summary-value" style="font-family:monospace;font-size:.8rem;word-break:break-all;"><?= e($focusDocumentCode !== '' ? $focusDocumentCode : 'Not assigned') ?></div>
                  </div>
                </div>

                <?php if ($focusReason !== ''): ?>
                  <div class="alert alert-warn" style="margin-bottom:16px;font-size:.85rem;">Previous reason: <?= e($focusReason) ?></div>
                <?php endif; ?>

                <?php if ($focusStatus === 'pending'): ?>
                  <div class="doc-action-panel">
                    <div class="doc-action-head">
                      <div>
                        <div class="doc-preview-title">Review Action</div>
                        <div class="doc-preview-sub">You can view, download, approve, request more information, or reject from here.</div>
                      </div>
                      <div class="doc-preview-actions">
                        <a href="<?= e($focusDocViewUrl) ?>" target="_blank" class="btn btn-navy" data-doc-action="open">View</a>
                        <a href="<?= e($focusDocDownloadUrl) ?>" class="btn btn-outline" data-doc-action="download">Download</a>
                      </div>
                    </div>
                    <form method="POST" id="action-form">
                      <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
                      <input type="hidden" name="doc_id" value="<?= (int)$focusDoc['id'] ?>">
                      <?php
                        $adminExpiryRequired = ['drivers_license','passport','work_authorization','h1b_i797'];
                        $needsExpiry = in_array($focusDoc['doc_type'], $adminExpiryRequired, true);
                      ?>
                      <?php if ($needsExpiry): ?>
                        <div class="form-group">
                          <label>Expiry Date <span style="color:var(--rose);font-weight:700;">*</span> <small style="color:var(--text-3);font-weight:400;">(required to approve)</small></label>
                          <input type="date" name="expiry_date" class="form-control expiry-required-field"
                                 min="<?= date('Y-m-d', strtotime('+1 day')) ?>"
                                 value="<?= e($focusDoc['expiry_date'] ?? '') ?>"
                                 id="expiry-date-input">
                        </div>
                      <?php elseif (in_array($focusDoc['doc_type'], ['education','direct_deposit','i9','social_security'], true)): ?>
                        <div class="form-group">
                          <label>Expiry Date <small style="color:var(--text-3);font-weight:400;">(optional)</small></label>
                          <input type="date" name="expiry_date" class="form-control"
                                 value="<?= e($focusDoc['expiry_date'] ?? '') ?>">
                        </div>
                      <?php endif; ?>
                      <div class="form-group" style="margin-bottom:16px;">
                        <label>Reason / Note</label>
                        <textarea name="reason" class="form-control" rows="3" placeholder="Required for Reject or Request Info. Optional for Approve." maxlength="1000"></textarea>
                      </div>
                      <div class="doc-action-copy">
                        Use approve when the document is valid. Use request info when the employee can correct the same upload. Use reject when they need to upload a fresh document.
                      </div>
                      <div class="doc-action-buttons">
                        <button type="submit" name="action" value="approve" class="btn btn-success">Approve</button>
                        <button type="submit" name="action" value="more_info" class="btn btn-outline" style="border-color:var(--cyan);color:var(--cyan);">Request Info</button>
                        <button type="submit" name="action" value="reject" class="btn btn-danger">Reject</button>
                      </div>
                    </form>
                  </div>
                <?php else: ?>
                  <div class="doc-action-panel">
                    <div class="doc-action-head">
                      <div>
                        <div class="doc-preview-title">Document Actions</div>
                        <div class="doc-preview-sub">This document is already <?= e($focusDoc['status']) ?>.</div>
                      </div>
                      <div class="doc-preview-actions">
                        <a href="<?= e($focusDocViewUrl) ?>" target="_blank" class="btn btn-navy" data-doc-action="open">View</a>
                        <a href="<?= e($focusDocDownloadUrl) ?>" class="btn btn-outline" data-doc-action="download">Download</a>
                      </div>
                    </div>
                    <div class="alert alert-info" style="margin-bottom:0;">No review action is needed right now.</div>
                    <?php
                      $editExpiryTypes = ['drivers_license','passport','work_authorization','h1b_i797'];
                      $showEditExpiry  = in_array($focusDoc['doc_type'], $editExpiryTypes, true);
                    ?>
                    <?php if ($showEditExpiry): ?>
                    <form method="POST" style="margin-top:18px;padding-top:16px;border-top:1px solid rgba(255,255,255,.07);">
                      <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
                      <input type="hidden" name="doc_id" value="<?= (int)$focusDoc['id'] ?>">
                      <input type="hidden" name="action" value="update_expiry">
                      <div class="doc-preview-title" style="margin-bottom:10px;">✏️ Edit Expiry Date</div>
                      <div class="form-group" style="margin-bottom:12px;">
                        <label style="font-size:.82rem;">New Expiry Date <span style="color:var(--rose);">*</span></label>
                        <input type="date" name="expiry_date" class="form-control"
                               min="<?= date('Y-m-d', strtotime('+1 day')) ?>"
                               value="<?= e($focusDoc['expiry_date'] ?? '') ?>"
                               required>
                        <?php if ($focusDoc['expiry_date']): ?>
                          <div style="font-size:.75rem;color:var(--text-3);margin-top:4px;">
                            Current: <?= e(date('M j, Y', strtotime($focusDoc['expiry_date']))) ?>
                            &nbsp;·&nbsp; Saving a new date resets expiry alert flags so notifications fire again.
                          </div>
                        <?php endif; ?>
                      </div>
                      <button type="submit" class="btn btn-outline btn-sm">💾 Update Expiry Date</button>
                    </form>
                    <?php endif; ?>
                  </div>
                <?php endif; ?>

                <div class="doc-preview-shell">
                  <div class="doc-preview-head">
                    <div>
                      <div class="doc-preview-title">Document Preview</div>
                      <div class="doc-preview-sub">Review the document before taking action.</div>
                    </div>
                    <div class="doc-preview-actions">
                      <a href="<?= e($focusDocViewUrl) ?>" target="_blank" class="btn btn-navy" data-doc-action="open">Open in New Tab</a>
                      <a href="<?= e($focusDocDownloadUrl) ?>" class="btn btn-outline" data-doc-action="download">Download</a>
                    </div>
                  </div>
                  <div class="doc-preview-body">
                    <?php if ($focusDocIsPdf): ?>
                      <iframe src="<?= e($focusDocViewUrl) ?>" title="Document preview" class="doc-preview-frame"></iframe>
                    <?php elseif ($focusDocIsImage): ?>
                      <div class="doc-preview-image-wrap">
                        <img src="<?= e($focusDocViewUrl) ?>" alt="Submitted document preview" class="doc-preview-image">
                      </div>
                    <?php else: ?>
                      <div class="alert alert-info" style="margin-bottom:0;">
                        This file type does not support inline preview here. Use "Open in New Tab" or "Download" to review it.
                      </div>
                    <?php endif; ?>
                    <div id="doc-open-status" style="margin-top:10px;font-size:.82rem;color:var(--text-3);"></div>
                  </div>
                </div>
              </div>
            </div>
          <?php else: ?>
            <div class="card doc-shell-card">
              <div class="card-body doc-empty-state" style="padding:60px 24px;">
                <p>Select a document from the queue to review it.</p>
              </div>
            </div>
          <?php endif; ?>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
/* Enforce expiry date when clicking Approve for required doc types */
(function() {
  var form = document.getElementById('action-form');
  if (!form) return;
  var expiryInput = form.querySelector('.expiry-required-field');
  if (!expiryInput) return;

  form.addEventListener('submit', function(e) {
    var clickedBtn = form.querySelector('[type=submit]:focus') ||
                     document.activeElement;
    var action = clickedBtn ? clickedBtn.value : '';
    if (action !== 'approve') return; // only validate on approve
    if (!expiryInput.value) {
      e.preventDefault();
      expiryInput.style.border = '1.5px solid var(--rose)';
      expiryInput.focus();
      var msg = expiryInput.parentNode.querySelector('.expiry-err');
      if (!msg) {
        msg = document.createElement('div');
        msg.className = 'expiry-err';
        msg.style.cssText = 'color:var(--rose);font-size:.78rem;margin-top:4px;';
        msg.textContent = '⚠️ Expiry date is required to approve this document.';
        expiryInput.parentNode.appendChild(msg);
      }
    }
  });
  expiryInput.addEventListener('input', function() {
    expiryInput.style.border = '';
    var msg = expiryInput.parentNode.querySelector('.expiry-err');
    if (msg) msg.remove();
  });
})();

document.querySelectorAll('[data-doc-action]').forEach(function(link) {
  link.addEventListener('click', function() {
    var status = document.getElementById('doc-open-status');
    if (!status) return;
    status.textContent = link.dataset.docAction === 'download'
      ? 'Preparing secure download...'
      : 'Opening secure document...';
    window.setTimeout(function() {
      if (status.textContent !== '') {
        status.textContent = 'If the file did not open, refresh this page and try again.';
      }
    }, 4000);
  });
});
</script>

<style>
.doc-shell-card {
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 16px;
  background: linear-gradient(180deg, rgba(255,255,255,.02), rgba(255,255,255,.01));
  box-shadow: 0 14px 36px rgba(0,0,0,.16);
}
.doc-shell-card-body { padding: 22px 24px; }
.doc-upload-card { border-color: rgba(31,160,192,.24); }
.doc-section-heading {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  margin-bottom: 18px;
}
.doc-section-heading strong {
  display: block;
  font-size: 1rem;
  color: var(--text-1);
  margin-bottom: 4px;
}
.doc-section-heading p {
  margin: 0;
  font-size: .84rem;
  color: var(--text-3);
}
.doc-section-icon {
  width: 40px;
  height: 40px;
  border-radius: 12px;
  border: 1px solid rgba(31,160,192,.26);
  background: rgba(31,160,192,.12);
  color: var(--cyan);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: .72rem;
  font-weight: 700;
  flex-shrink: 0;
}
.doc-upload-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 14px;
  margin-bottom: 16px;
}
.doc-input-wrap { min-width: 0; }
.doc-input-label {
  display: block;
  font-size: .78rem;
  color: var(--text-3);
  margin-bottom: 6px;
  font-weight: 600;
}
.doc-select {
  width: 100%;
  min-height: 46px;
  border-radius: 12px;
}
.doc-upload-actions { margin-top: 14px; }
.doc-upload-status {
  margin-top: 10px;
  font-size: .84rem;
  color: var(--text-3);
}
.doc-filter-body { padding: 16px 24px; }
.doc-filter-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.doc-filter-select {
  width: min(220px, 100%);
}
.doc-count {
  color: var(--text-3);
  font-size: .88rem;
}
.doc-queue-body { padding: 8px 0; }
.doc-queue-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 14px 18px;
  margin: 0 12px 10px;
  border: 1px solid rgba(255,255,255,.06);
  border-radius: 14px;
  text-decoration: none;
  background: rgba(255,255,255,.015);
  transition: border-color .2s, background .2s, transform .2s;
}
.doc-queue-item:hover {
  border-color: rgba(31,160,192,.24);
  background: rgba(31,160,192,.04);
  transform: translateY(-1px);
}
.doc-queue-item.is-active {
  border-color: rgba(31,160,192,.3);
  background: rgba(31,160,192,.08);
}
.doc-queue-icon {
  width: 42px;
  height: 42px;
  border-radius: 12px;
  background: rgba(31,160,192,.1);
  border: 1px solid rgba(31,160,192,.18);
  color: var(--cyan);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: .7rem;
  font-weight: 700;
  flex-shrink: 0;
}
.doc-queue-copy {
  flex: 1;
  min-width: 0;
}
.doc-queue-name {
  font-weight: 700;
  font-size: .92rem;
  color: var(--text-1);
}
.doc-queue-meta {
  font-size: .79rem;
  color: var(--text-3);
  margin-top: 4px;
  word-break: break-word;
}
.doc-queue-time {
  font-size: .76rem;
  color: var(--gray-400);
  margin-top: 6px;
}
.doc-summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.doc-summary-card {
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 14px;
  padding: 14px;
  background: rgba(255,255,255,.02);
}
.doc-summary-label {
  font-size: .72rem;
  text-transform: uppercase;
  color: var(--text-3);
  margin-bottom: 6px;
  font-weight: 700;
}
.doc-summary-value {
  font-weight: 700;
  color: var(--text-1);
}
.doc-summary-sub {
  font-size: .8rem;
  color: var(--gray-400);
  margin-top: 4px;
}
.doc-preview-shell {
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 14px;
  overflow: hidden;
  background: rgba(255,255,255,.02);
  margin-bottom: 20px;
}
.doc-action-panel {
  border: 1px solid rgba(31,160,192,.16);
  border-radius: 14px;
  background: rgba(31,160,192,.04);
  padding: 16px;
  margin-bottom: 20px;
}
.doc-action-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}
.doc-action-copy {
  font-size: .83rem;
  color: var(--text-3);
  margin-bottom: 12px;
}
.doc-action-buttons {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
.doc-preview-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 16px;
  border-bottom: 1px solid rgba(255,255,255,.07);
  flex-wrap: wrap;
}
.doc-preview-title {
  font-weight: 700;
  color: var(--text-1);
}
.doc-preview-sub {
  font-size: .82rem;
  color: var(--text-3);
  margin-top: 2px;
}
.doc-preview-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
.doc-preview-body { padding: 16px; }
.doc-preview-frame {
  width: 100%;
  height: 520px;
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 10px;
  background: #fff;
}
.doc-preview-image-wrap {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 320px;
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 10px;
  padding: 18px;
}
.doc-preview-image {
  max-width: 100%;
  max-height: 520px;
  border-radius: 8px;
}
.doc-empty-state {
  text-align: center;
  color: var(--text-3);
}
.att-dropzone {
  border: 2px dashed var(--border, rgba(255,255,255,.15));
  border-radius: 16px;
  background: rgba(255,255,255,.02);
  padding: 30px 22px;
  text-align: center;
  cursor: pointer;
  transition: border-color .2s, background .2s;
  position: relative;
  max-width: 640px;
}
.att-dropzone:hover, .att-dropzone:focus, .att-dropzone.drag-over {
  border-color: var(--cyan, #1fa0c0);
  background: rgba(31,160,192,.06);
  outline: none;
}
.att-dropzone.drag-over { border-style: solid; }
.att-drop-inner { pointer-events: none; }
.att-drop-cloud {
  width: 52px;
  height: 52px;
  border-radius: 14px;
  border: 1px solid rgba(31,160,192,.24);
  background: rgba(31,160,192,.12);
  color: var(--cyan);
  font-size: .8rem;
  font-weight: 700;
  margin: 0 auto 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: transform .2s;
}
.att-dropzone:hover .att-drop-cloud,
.att-dropzone.drag-over .att-drop-cloud { transform: translateY(-3px); }
.att-drop-title { font-size: .95rem; font-weight: 700; color: var(--text-1); margin: 0 0 6px; }
.att-drop-sub   { font-size: .84rem; color: var(--text-3); margin: 0; }
.att-drop-link  { color: var(--cyan); text-decoration: underline; text-underline-offset: 2px; }
.att-drop-selected {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 0;
  pointer-events: auto;
}
.att-drop-file-icon {
  min-width: 44px;
  height: 44px;
  border-radius: 8px;
  border: 1px solid var(--surface-3);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: .75rem;
  font-weight: 700;
}
.att-drop-file-name {
  font-size: .85rem;
  font-weight: 600;
  color: var(--text-1);
  word-break: break-all;
  flex: 1;
  text-align: left;
}
.att-drop-file-size { font-size: .75rem; color: var(--text-3); }
.att-drop-clear {
  background: rgba(239,68,68,.08);
  border: 1px solid rgba(239,68,68,.25);
  color: var(--text-3);
  border-radius: 6px;
  width: 26px;
  height: 26px;
  font-size: .75rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
@media (max-width: 768px) {
  .doc-shell-card-body,
  .doc-filter-body,
  .doc-preview-body { padding: 16px; }
  .doc-preview-frame { height: 420px; }
  .doc-queue-item { margin-left: 10px; margin-right: 10px; }
}
</style>

<script>
(function() {
  var zone = document.getElementById('hr-drop-zone');
  var input = document.getElementById('hr-doc-file');
  var inner = document.getElementById('hr-drop-inner');
  var selected = document.getElementById('hr-drop-selected');
  var nameEl = document.getElementById('hr-drop-file-name');
  var sizeEl = document.getElementById('hr-drop-file-size');
  var iconEl = document.getElementById('hr-drop-file-icon');
  if (!zone || !input) return;

  function showFile(file) {
    if (!file) return;
    var ext = file.name.split('.').pop().toLowerCase();
    var icons = { pdf: 'PDF', jpg: 'IMG', jpeg: 'IMG', png: 'IMG' };
    if (iconEl) iconEl.textContent = icons[ext] || 'FILE';
    if (nameEl) nameEl.textContent = file.name;
    if (sizeEl) sizeEl.textContent = file.size > 1048576 ? (file.size / 1048576).toFixed(1) + ' MB' : Math.round(file.size / 1024) + ' KB';
    if (inner) inner.style.display = 'none';
    if (selected) selected.style.display = 'flex';
  }

  zone.addEventListener('dragover', function(e) {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', function() {
    zone.classList.remove('drag-over');
  });
  zone.addEventListener('drop', function(e) {
    e.preventDefault();
    zone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) {
      var dt = new DataTransfer();
      dt.items.add(e.dataTransfer.files[0]);
      input.files = dt.files;
      showFile(e.dataTransfer.files[0]);
    }
  });
  input.addEventListener('change', function() {
    if (input.files.length) showFile(input.files[0]);
  });

  var form = document.getElementById('hr-upload-form');
  if (form) {
    form.addEventListener('submit', function() {
      var btn = document.getElementById('hr-upload-btn');
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Uploading...';
      }
      var st = document.getElementById('hr-upload-status');
      if (st) {
        st.style.color = 'var(--cyan)';
        st.textContent = 'Uploading, please wait...';
      }
    });
  }
})();

function hrToggleTitleField() {
  var sel   = document.getElementById('hr-doc-type-select');
  var wrap  = document.getElementById('hr-doc-title-wrap');
  var input = document.getElementById('hr-doc-title-input');
  if (!sel || !wrap || !input) return;
  var isOther = sel.value === 'other';
  wrap.style.display = isOther ? 'block' : 'none';
  input.required = isOther;
  if (!isOther) input.value = '';
}

function hrClearFile(e) {
  e.stopPropagation();
  var input = document.getElementById('hr-doc-file');
  var inner = document.getElementById('hr-drop-inner');
  var selected = document.getElementById('hr-drop-selected');
  if (input) input.value = '';
  if (inner) inner.style.display = 'block';
  if (selected) selected.style.display = 'none';
}
</script>
<?php pageFooter(); ?>
</body>
</html>
