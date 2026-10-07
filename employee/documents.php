<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
startSecureSession();
$user   = requireAnyRole();
$userId = $user['id'];
$db     = getDB();

$DOC_TYPES = [
    'drivers_license'    => ["Driver's License / State ID", '🪪'],
    'i9'                 => ['Form I-9',                   '📋'],
    'passport'           => ['Passport',                   '📘'],
    'work_authorization' => ['Work Authorization / EAD',   '✅'],
    'h1b_i797'           => ['H-1B Approval (I-797)',      '📄'],
    'social_security'    => ['Social Security Card',       '🔐'],
    'education'          => ['Educational Certificates',   '🎓'],
    'direct_deposit'     => ['Direct Deposit / Voided Check','🏦'],
];

$msg = ''; $msgType = '';
$isXhr = isset($_SERVER['HTTP_X_REQUESTED_WITH']);

/* ── FILE UPLOAD (AJAX or regular POST) ───────────────────── */
// Expiry date is mandatory for ALL document uploads.
// (Previously only drivers_license, passport, work_authorization, h1b_i797 required it;
//  expanded to all types per new compliance requirements.)
$EXPIRY_REQUIRED = array_keys($DOC_TYPES);

// Document types that allow multiple file uploads (e.g. education may have multiple certificates)
$MULTI_UPLOAD_TYPES = ['education'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // This page renders many AJAX upload forms at once, so rotating the shared
    // session token on every upload makes the remaining forms stale.
    verifyCsrfToken(false);
    $docType = validateEnum($_POST['doc_type'] ?? '', array_merge(array_keys($DOC_TYPES), ['other']));
    $isMultiType = in_array($docType, $MULTI_UPLOAD_TYPES, true);
    $isOtherType = $docType === 'other';
    $documentName = null;

    if (!$docType) {
        $result = ['success' => false, 'message' => 'Invalid document type.'];
    } elseif ($isOtherType && trim((string)($_POST['document_name'] ?? '')) === '') {
        $result = ['success' => false, 'message' => 'Please enter a title for this document.'];
    } elseif (empty($_FILES['doc_file']) || (
        !$isMultiType && $_FILES['doc_file']['error'] === UPLOAD_ERR_NO_FILE
    ) || (
        $isMultiType && (empty($_FILES['doc_file']['name'][0]) || $_FILES['doc_file']['error'][0] === UPLOAD_ERR_NO_FILE)
    )) {
        $result = ['success' => false, 'message' => 'Please select a file to upload.'];
    } else {
        if ($isOtherType) {
            $documentName = sanitizeString($_POST['document_name'] ?? '', 180);
        }
        $expiryDate = null;
        if (in_array($docType, $EXPIRY_REQUIRED, true)) {
            $expiryDate = sanitizeDate($_POST['expiry_date'] ?? '');
            if (!$expiryDate) {
                $result = ['success' => false, 'message' => 'Expiry date is required for this document type.'];
                $expiryDate = null;
                goto send_result;
            }
            if (strtotime($expiryDate) <= time()) {
                $result = ['success' => false, 'message' => 'Expiry date must be in the future.'];
                goto send_result;
            }
        }

        if ($isMultiType) {
            // Handle multiple file uploads — upload each file independently
            $files     = $_FILES['doc_file'];
            $count     = is_array($files['name']) ? count($files['name']) : 1;
            $allOk     = true;
            $msgs      = [];
            for ($fi = 0; $fi < $count; $fi++) {
                $singleFile = [
                    'name'     => $files['name'][$fi],
                    'type'     => $files['type'][$fi],
                    'tmp_name' => $files['tmp_name'][$fi],
                    'error'    => $files['error'][$fi],
                    'size'     => $files['size'][$fi],
                ];
                if ($singleFile['error'] === UPLOAD_ERR_NO_FILE) continue;
                $r = handleDocumentUpload($singleFile, $docType, $userId, false, $expiryDate, $documentName);
                if (!$r['success']) { $allOk = false; }
                $msgs[] = basename($singleFile['name']) . ': ' . $r['message'];
            }
            $result = [
                'success' => $allOk,
                'message' => implode(' | ', $msgs) ?: ($allOk ? 'All files uploaded.' : 'Some uploads failed.'),
            ];
        } else {
            // doc_file[] always produces an array-of-arrays structure from PHP;
            // extract the single file entry for non-multi doc types
            $rawFile = $_FILES['doc_file'];
            if (is_array($rawFile['name'])) {
                $singleFile = [
                    'name'     => $rawFile['name'][0],
                    'type'     => $rawFile['type'][0],
                    'tmp_name' => $rawFile['tmp_name'][0],
                    'error'    => $rawFile['error'][0],
                    'size'     => $rawFile['size'][0],
                ];
            } else {
                $singleFile = $rawFile;
            }
            $result = handleDocumentUpload($singleFile, $docType, $userId, false, $expiryDate, $documentName);
        }
        send_result:
    }

    $result['csrf_token'] = generateCsrfToken();

    if ($isXhr) {
        header('Content-Type: application/json');
        echo json_encode($result);
        exit;
    }

    // Non-XHR fallback
    $msg     = $result['message'];
    $msgType = $result['success'] ? 'success' : 'error';
}

/* ── LOAD DOCS ────────────────────────────────────────────── */
$docsStmt = $db->prepare(
    "SELECT id, doc_type, document_name, status, rejection_reason, uploaded_at, expiry_date, file_name, file_size, mime_type
     FROM documents WHERE user_id=? ORDER BY uploaded_at DESC"
);
$docsStmt->execute([$userId]);
$allDocs = $docsStmt->fetchAll();

// Map: latest doc per type
$docMap = [];
foreach ($allDocs as $d) {
    if (!isset($docMap[$d['doc_type']])) $docMap[$d['doc_type']] = $d;
}

// "Others" — freeform, unlimited, titled documents (educational certs, etc).
// Not part of $DOC_TYPES / the onboarding checklist above.
$otherDocs = array_values(array_filter($allDocs, fn($d) => $d['doc_type'] === 'other'));

// Onboarding progress
$required = mandatoryOnboardingDocTypes();
$approved = array_filter($docMap, function($d) { return $d['status'] === 'approved'; });
$approvedRequired = array_filter($approved, function($d, $k) use ($required) { return in_array($k, $required, true); }, ARRAY_FILTER_USE_BOTH);
$progress = count($approvedRequired);
$total    = count($required);

$flashType  = $msgType;
$flashTitle = $msg ? ($msgType==='success' ? 'Upload Successful' : 'Upload Error') : '';
pageHead('My Documents', $flashType, $flashTitle, $msg);
?>
<body>
<div class="app-shell">
  <?php
  // hr_admin has a Documents dropdown in the sidebar; 'my_documents' highlights their sub-item.
  // Regular employees use 'documents' (plain link, no dropdown).
  $docsActivePage = ($user['role'] === 'hr_admin') ? 'my_documents' : 'documents';
  renderSidebar(['id'=>$userId,'name'=>$user['name'],'role'=>$user['role']], $docsActivePage);
  ?>
  <div class="main-content">
    <?php renderTopbar('My Documents', $user); ?>
    <div class="page-body">
      <div class="page-header">
        <h1>📁 My Documents</h1>
        <p>Upload and manage your HR documents for onboarding and compliance.</p>
      </div>

      <?php if (($_GET['required'] ?? '') === '1'): ?>
        <div class="alert alert-error">
          ⚠️ Please upload your required documents before continuing — this is mandatory for onboarding.
        </div>
      <?php endif; ?>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType==='error'?'error':'success' ?>" data-auto-dismiss="6000">
          <?= $msgType==='success' ? '✅' : '⚠️' ?> <?= e($msg) ?>
        </div>
      <?php endif; ?>

      <!-- Onboarding progress -->
      <div class="card" style="margin-bottom:22px;">
        <div class="card-body" style="padding:18px 22px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
            <span style="font-weight:700;font-size:.9rem;color:var(--text-1);">Onboarding Progress</span>
            <span style="font-weight:800;font-size:1.1rem;color:var(--cyan);"><?= $progress ?>/<?= $total ?></span>
          </div>
          <div class="progress-bar">
            <div class="progress-bar-fill" style="width:<?= $total > 0 ? round($progress / $total * 100) : 0 ?>%"></div>
          </div>
          <?php if ($progress === $total): ?>
            <div style="margin-top:10px;font-size:.84rem;color:var(--green);">🎉 All required documents approved! Onboarding complete.</div>
          <?php else: ?>
            <div style="margin-top:10px;font-size:.82rem;color:var(--text-3);">Required: Driver's License, I-9, Social Security, Direct Deposit</div>
          <?php endif; ?>
        </div>
      </div>

      <!-- Document table — matches "My Documents" design from screenshot -->
      <div class="card" style="overflow:hidden;">
        <div class="card-header" style="padding:14px 20px;border-bottom:1px solid var(--surface-3);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <?php
              $cntAll      = count($DOC_TYPES);
              $cntRequired = count(array_filter(array_keys($DOC_TYPES), fn($t) => in_array($t, $required, true)));
              $cntMissing  = count(array_filter(array_keys($DOC_TYPES), function($t) use ($docMap, $required) {
                $doc    = $docMap[$t] ?? null;
                $status = $doc ? $doc['status'] : 'missing';
                return !$doc || in_array($status, ['missing','rejected','more_info_needed'], true);
              }));
            ?>
            <button class="btn btn-sm btn-outline doc-filter active" data-filter="all"      style="font-size:.78rem;padding:5px 14px;">All <span class="filter-count"><?= $cntAll ?></span></button>
            <button class="btn btn-sm btn-outline doc-filter"        data-filter="required" style="font-size:.78rem;padding:5px 14px;">Required <span class="filter-count"><?= $cntRequired ?></span></button>
            <button class="btn btn-sm btn-outline doc-filter<?= $cntMissing ? ' filter-alert' : '' ?>" data-filter="missing"  style="font-size:.78rem;padding:5px 14px;">Missing / Action Needed <span class="filter-count"><?= $cntMissing ?></span></button>
          </div>
        </div>

        <div class="table-wrap" style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;font-size:.84rem;">
            <thead>
              <tr style="background:var(--surface-2);">
                <th style="padding:10px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;width:36px;"></th>
                <th style="padding:10px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">Document</th>
                <th style="padding:10px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">Status</th>
                <th style="padding:10px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">Updated</th>
                <th style="padding:10px 16px;text-align:right;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">Action</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($DOC_TYPES as $type => [$label, $icon]): ?>
              <?php
                $doc        = $docMap[$type] ?? null;
                $isRequired = in_array($type, $required, true);
                $status     = $doc ? $doc['status'] : 'missing';
                $isApproved = $status === 'approved';
                $isMissing  = !$doc || in_array($status, ['missing','rejected','more_info_needed'], true);
                $rowBg      = (!$doc || $status === 'missing') ? 'background:rgba(251,191,36,.04);' : '';
                // Sub-label
                $subLabel = '';
                if ($type === 'drivers_license') $subLabel = 'Required for I-9 verification';
                elseif ($type === 'i9')          $subLabel = 'Employment eligibility · due Fri May 1';
                elseif ($type === 'social_security') $subLabel = 'Or W-9 alternative';
                elseif ($type === 'direct_deposit')  $subLabel = 'Voided check accepted';
              ?>
              <?php
                // A row is "missing/needs action" if: no doc, or rejected, or more_info_needed
                $docMissingClass   = ($isMissing) ? 'doc-missing' : '';
                $docRequiredClass  = $isRequired  ? 'doc-required' : '';
              ?>
              <tr class="doc-row <?= $docRequiredClass ?> <?= $docMissingClass ?>"
                  style="border-bottom:1px solid var(--surface-3);<?= $rowBg ?>">
                <!-- Checkbox / approved tick -->
                <td style="padding:14px 8px 14px 16px;vertical-align:middle;">
                  <?php if ($isApproved): ?>
                    <span style="display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:4px;background:var(--cyan);color:#fff;font-size:.75rem;">✓</span>
                  <?php else: ?>
                    <span style="display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:4px;border:2px solid var(--surface-3);"></span>
                  <?php endif; ?>
                </td>

                <!-- Document name + sub-label -->
                <td style="padding:14px 16px;vertical-align:middle;">
                  <div style="font-weight:600;color:var(--text-1);">
                    <?= $icon ?> <?= e($label) ?>
                    <?php if ($isRequired): ?>
                      <span style="margin-left:6px;font-size:.68rem;font-weight:700;background:rgba(239,68,68,.12);color:#dc2626;border:1px solid rgba(239,68,68,.22);border-radius:20px;padding:1px 8px;vertical-align:middle;text-transform:uppercase;letter-spacing:.04em;">Required</span>
                    <?php endif; ?>
                  </div>
                  <?php if ($subLabel): ?>
                    <div style="font-size:.75rem;color:var(--text-3);margin-top:2px;"><?= e($subLabel) ?></div>
                  <?php elseif ($doc && $doc['file_name']): ?>
                    <div style="font-size:.75rem;color:var(--text-3);margin-top:2px;">
                      <?= e($doc['file_name']) ?> · <?= e(round($doc['file_size']/1024)) ?> KB
                      <?php if ($doc['expiry_date']): ?>
                        <?php $daysLeft = (int)((strtotime($doc['expiry_date']) - time()) / 86400); ?>
                        · Expires <?= e(date('M j, Y', strtotime($doc['expiry_date']))) ?>
                        <?php if ($daysLeft < 30): ?><span style="color:var(--amber);"> (<?= $daysLeft ?>d left)</span><?php endif; ?>
                      <?php endif; ?>
                    </div>
                  <?php endif; ?>
                  <?php if ($doc && $doc['status'] === 'rejected' && $doc['rejection_reason']): ?>
                    <div style="font-size:.74rem;color:var(--rose);margin-top:3px;">❌ <?= e($doc['rejection_reason']) ?></div>
                  <?php elseif ($doc && $doc['status'] === 'more_info_needed' && $doc['rejection_reason']): ?>
                    <div style="font-size:.74rem;color:var(--amber);margin-top:3px;">ℹ️ <?= e($doc['rejection_reason']) ?></div>
                  <?php endif; ?>
                </td>

                <!-- Status badge -->
                <td style="padding:14px 16px;vertical-align:middle;">
                  <?php if (!$doc || $status === 'missing'): ?>
                    <span class="badge" style="background:rgba(251,191,36,.15);color:#b45309;border-radius:20px;padding:3px 12px;font-size:.74rem;font-weight:700;">Missing</span>
                  <?php elseif ($status === 'approved'): ?>
                    <span class="badge" style="background:rgba(52,211,153,.15);color:#065f46;border-radius:20px;padding:3px 12px;font-size:.74rem;font-weight:700;">Approved</span>
                  <?php elseif ($status === 'pending'): ?>
                    <span class="badge" style="background:rgba(99,179,237,.15);color:#1e40af;border-radius:20px;padding:3px 12px;font-size:.74rem;font-weight:700;">In review</span>
                  <?php elseif ($status === 'rejected'): ?>
                    <span class="badge" style="background:rgba(252,165,165,.2);color:#991b1b;border-radius:20px;padding:3px 12px;font-size:.74rem;font-weight:700;">Rejected</span>
                  <?php else: ?>
                    <span class="badge badge-<?= e($status) ?>"><?= e(ucfirst(str_replace('_',' ',$status))) ?></span>
                  <?php endif; ?>
                </td>

                <!-- Updated -->
                <td style="padding:14px 16px;vertical-align:middle;color:var(--text-3);font-size:.82rem;white-space:nowrap;">
                  <?php if ($doc): ?>
                    <?php
                      $diff = time() - strtotime($doc['uploaded_at']);
                      if ($diff < 3600)       echo round($diff/60) . ' min ago';
                      elseif ($diff < 86400)  echo round($diff/3600) . ' hours ago';
                      elseif ($diff < 172800) echo '1 day ago';
                      else                    echo round($diff/86400) . ' days ago';
                    ?>
                  <?php else: ?>
                    <span style="color:var(--text-3);">—</span>
                  <?php endif; ?>
                </td>

                <!-- Action -->
                <td style="padding:14px 16px;vertical-align:middle;text-align:right;">
                  <?php if ($isMissing): ?>
                    <button type="button" class="btn btn-primary btn-sm pd-upload-btn" data-doc-type="<?= e($type) ?>" data-doc-label="<?= e($label) ?>" style="font-size:.78rem;min-width:72px;">Upload</button>
                  <?php elseif ($isApproved): ?>
                    <a href="<?= e(getDocumentServeUrl((int)$doc['id'], (int)$userId)) ?>" target="_blank"
                       class="btn btn-outline btn-sm" style="font-size:.78rem;min-width:72px;margin-right:6px;">View</a>
                    <button type="button" class="btn btn-outline btn-sm pd-upload-btn" data-doc-type="<?= e($type) ?>" data-doc-label="<?= e($label) ?>" style="font-size:.78rem;min-width:72px;">Upload New</button>
                  <?php else: ?>
                    <a href="<?= e(getDocumentServeUrl((int)$doc['id'], (int)$userId)) ?>" target="_blank"
                       class="btn btn-outline btn-sm" style="font-size:.78rem;min-width:72px;margin-right:6px;">View</a>
                    <button type="button" class="btn btn-outline btn-sm pd-upload-btn" data-doc-type="<?= e($type) ?>" data-doc-label="<?= e($label) ?>" style="font-size:.78rem;min-width:72px;">Replace</button>
                  <?php endif; ?>
                </td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Other documents — unlimited, titled, supplementary uploads -->
      <div class="card" style="margin-top:22px;overflow:hidden;">
        <div class="card-header" style="padding:14px 20px;border-bottom:1px solid var(--surface-3);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
          <div>
            <strong style="font-size:.95rem;">📎 Other Documents</strong>
            <p style="margin:2px 0 0;font-size:.78rem;color:var(--text-3);">Educational certificates or any other supplementary documents — upload as many as you need.</p>
          </div>
          <button type="button" class="btn btn-primary btn-sm" id="other-upload-btn" style="font-size:.78rem;">+ Add Document</button>
        </div>
        <?php if (!$otherDocs): ?>
          <div style="padding:24px;text-align:center;color:var(--text-3);font-size:.85rem;">No other documents uploaded yet.</div>
        <?php else: ?>
          <div class="table-wrap" style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:.84rem;">
              <thead>
                <tr style="background:var(--surface-2);">
                  <th style="padding:10px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">Title</th>
                  <th style="padding:10px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">Status</th>
                  <th style="padding:10px 16px;text-align:left;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">Uploaded</th>
                  <th style="padding:10px 16px;text-align:right;font-size:.72rem;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">Action</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($otherDocs as $doc): ?>
                <tr style="border-bottom:1px solid var(--surface-3);">
                  <td style="padding:14px 16px;vertical-align:middle;">
                    <div style="font-weight:600;color:var(--text-1);"><?= e($doc['document_name'] ?: $doc['file_name']) ?></div>
                    <div style="font-size:.75rem;color:var(--text-3);margin-top:2px;"><?= e($doc['file_name']) ?> · <?= e(round($doc['file_size']/1024)) ?> KB</div>
                    <?php if ($doc['status'] === 'rejected' && $doc['rejection_reason']): ?>
                      <div style="font-size:.74rem;color:var(--rose);margin-top:3px;">❌ <?= e($doc['rejection_reason']) ?></div>
                    <?php elseif ($doc['status'] === 'more_info_needed' && $doc['rejection_reason']): ?>
                      <div style="font-size:.74rem;color:var(--amber);margin-top:3px;">ℹ️ <?= e($doc['rejection_reason']) ?></div>
                    <?php endif; ?>
                  </td>
                  <td style="padding:14px 16px;vertical-align:middle;">
                    <?php $oStatus = $doc['status']; ?>
                    <?php if ($oStatus === 'approved'): ?>
                      <span class="badge" style="background:rgba(52,211,153,.15);color:#065f46;border-radius:20px;padding:3px 12px;font-size:.74rem;font-weight:700;">Approved</span>
                    <?php elseif ($oStatus === 'pending'): ?>
                      <span class="badge" style="background:rgba(99,179,237,.15);color:#1e40af;border-radius:20px;padding:3px 12px;font-size:.74rem;font-weight:700;">In review</span>
                    <?php elseif ($oStatus === 'rejected'): ?>
                      <span class="badge" style="background:rgba(252,165,165,.2);color:#991b1b;border-radius:20px;padding:3px 12px;font-size:.74rem;font-weight:700;">Rejected</span>
                    <?php else: ?>
                      <span class="badge badge-<?= e($oStatus) ?>"><?= e(ucfirst(str_replace('_',' ',$oStatus))) ?></span>
                    <?php endif; ?>
                  </td>
                  <td style="padding:14px 16px;vertical-align:middle;color:var(--text-3);font-size:.82rem;white-space:nowrap;">
                    <?= e(date('M j, Y', strtotime($doc['uploaded_at']))) ?>
                  </td>
                  <td style="padding:14px 16px;vertical-align:middle;text-align:right;">
                    <a href="<?= e(getDocumentServeUrl((int)$doc['id'], (int)$userId)) ?>" target="_blank"
                       class="btn btn-outline btn-sm" style="font-size:.78rem;min-width:72px;">View</a>
                  </td>
                </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php endif; ?>
      </div>

      <!-- ── UPLOAD MODAL ──────────────────────────────────── -->
      <div id="upload-modal" class="modal-overlay hidden" style="position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;padding:16px;">
        <div class="card" style="width:100%;max-width:480px;border-radius:12px;overflow:hidden;">
          <div class="card-header" style="padding:16px 20px;display:flex;align-items:center;justify-content:space-between;">
            <h3 id="modal-title" style="font-size:1rem;margin:0;">Upload Document</h3>
            <button data-modal-close style="background:none;border:none;cursor:pointer;font-size:1.1rem;color:var(--text-3);" title="Close">✕</button>
          </div>
          <div class="card-body" style="padding:20px;">
            <form method="POST" class="upload-form" data-upload data-upload-bound="1" enctype="multipart/form-data">
              <input type="hidden" name="csrf_token" value="<?= generateCsrfToken() ?>">
              <input type="hidden" name="doc_type" id="modal-doc-type" value="">

              <div id="modal-title-wrap" style="display:none;margin-bottom:16px;">
                <label style="font-size:.82rem;font-weight:700;color:var(--text-2);display:block;margin-bottom:5px;">
                  Document Title <span style="color:var(--rose);">*</span>
                </label>
                <input type="text" name="document_name" id="modal-doc-title-input" maxlength="180"
                       placeholder="e.g. Bachelor's Degree Certificate" class="form-control" style="font-size:.86rem;width:100%;">
              </div>

              <div class="upload-zone" id="modal-upload-zone" style="border:2px dashed var(--surface-3);border-radius:10px;padding:28px;text-align:center;cursor:pointer;margin-bottom:16px;">
                <!-- multiple is toggled on/off by JS based on doc type; direct-click on zone triggers input -->
                <input type="file" name="doc_file[]" id="modal-file-input" accept=".pdf,.jpg,.jpeg,.png" style="display:none;">
                <div class="upload-default-state">
                  <div class="upload-icon" style="font-size:2rem;margin-bottom:8px;">☁️</div>
                  <h4 id="modal-file-hint" style="margin:0 0 4px;font-size:.9rem;">Click to select file</h4>
                  <p style="color:var(--text-3);font-size:.78rem;margin:0;">PDF, JPEG or PNG · Max 10MB</p>
                  <div class="selected-filename" style="margin-top:10px;font-size:.78rem;color:var(--cyan);font-weight:600;"></div>
                </div>
                <div class="upload-loading-state" style="display:none;">
                  <div style="font-size:1.8rem;margin-bottom:8px;">⏳</div>
                  <h4 style="margin:0 0 4px;font-size:.9rem;">Uploading…</h4>
                  <p class="upload-pct-text" style="color:var(--text-3);font-size:.82rem;margin:0;">0%</p>
                </div>
              </div>

              <div class="upload-progress-wrap" style="display:none;margin-bottom:14px;">
                <div class="upload-progress-bar" style="height:5px;border-radius:3px;background:var(--surface-3);overflow:hidden;">
                  <div class="upload-progress-fill" style="height:100%;width:0;background:var(--cyan);transition:width .2s;"></div>
                </div>
                <div class="upload-progress-label" style="display:flex;justify-content:space-between;font-size:.75rem;color:var(--text-3);margin-top:4px;">
                  <span>Uploading…</span><span class="upload-progress-pct">0%</span>
                </div>
              </div>

              <div class="upload-result" style="display:none;margin-bottom:12px;"></div>

              <!-- Expiry date — mandatory for the fixed document types; hidden for "Other" -->
              <div id="modal-expiry-wrap" style="margin-bottom:16px;">
                <label style="font-size:.82rem;font-weight:700;color:var(--text-2);display:block;margin-bottom:5px;">
                  Expiry Date <span style="color:var(--rose);">*</span>
                </label>
                <input type="date" name="expiry_date" id="modal-expiry-input"
                       min="<?= date('Y-m-d', strtotime('+1 day')) ?>"
                       required
                       class="form-control"
                       style="font-size:.86rem;width:100%;">
                <div style="font-size:.72rem;color:var(--text-3);margin-top:4px;">Enter the expiry date printed on the document. Required for all documents.</div>
              </div>

              <button type="submit" class="btn btn-primary btn-block">
                <span class="btn-text">📤 Upload Document</span>
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
/* ── Modal: set doc_type + title when opened from a row button ── */
// Document types that support multiple file uploads (must match PHP $MULTI_UPLOAD_TYPES)
var MULTI_UPLOAD_TYPES = ['education'];

function openUploadModal(type, label) {
  var modal      = document.getElementById('upload-modal');
  var typeInput  = document.getElementById('modal-doc-type');
  var titleEl    = document.getElementById('modal-title');
  var hintEl     = document.getElementById('modal-file-hint');
  var fileInput  = document.getElementById('modal-file-input');
  var form       = modal ? modal.querySelector('.upload-form') : null;
  var isMulti    = MULTI_UPLOAD_TYPES.indexOf(type) !== -1;
  var isOther    = type === 'other';

  var titleWrap  = document.getElementById('modal-title-wrap');
  var titleInput = document.getElementById('modal-doc-title-input');
  var expiryWrap = document.getElementById('modal-expiry-wrap');
  var expiryInput= document.getElementById('modal-expiry-input');
  if (titleWrap && titleInput) {
    titleWrap.style.display = isOther ? 'block' : 'none';
    titleInput.required = isOther;
    if (!isOther) titleInput.value = '';
  }
  if (expiryWrap && expiryInput) {
    expiryWrap.style.display = isOther ? 'none' : 'block';
    expiryInput.required = !isOther;
  }

  /* Reset first, then set the hidden type so it is not wiped out. */
  if (form) {
    form.reset();
    var nameEl       = form.querySelector('.selected-filename');
    var progressWrap = form.querySelector('.upload-progress-wrap');
    var progressFill = form.querySelector('.upload-progress-fill');
    var progressPct  = form.querySelector('.upload-progress-pct');
    var resultEl     = form.querySelector('.upload-result');
    var defaultState = form.querySelector('.upload-default-state');
    var loadingState = form.querySelector('.upload-loading-state');
    if (nameEl)       nameEl.textContent = '';
    if (progressWrap) progressWrap.classList.remove('visible');
    if (progressFill) { progressFill.style.width = '0'; progressFill.classList.remove('complete'); }
    if (progressPct)  progressPct.textContent = '0%';
    if (resultEl)     { resultEl.style.display = 'none'; resultEl.innerHTML = ''; }
    if (defaultState) defaultState.style.display = 'block';
    if (loadingState) loadingState.style.display  = 'none';
    delete form.dataset.submitting;
  }

  // Toggle multiple attribute based on doc type
  if (fileInput) {
    if (isMulti) {
      fileInput.setAttribute('multiple', 'multiple');
    } else {
      fileInput.removeAttribute('multiple');
    }
  }
  if (hintEl) hintEl.textContent = isMulti ? 'Click to select one or more files' : 'Click to select file';

  if (typeInput) typeInput.value = type || '';
  if (titleEl)   titleEl.textContent = type && label ? ('Upload ' + label) : 'Upload Document';

  if (modal) modal.classList.remove('hidden');
}

/* ── Modal open/close wiring ─────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('[data-modal-open="upload-modal"]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      openUploadModal('', '');
    });
  });

  document.querySelectorAll('.pd-upload-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      openUploadModal(btn.dataset.docType || '', btn.dataset.docLabel || '');
    });
  });

  var otherBtn = document.getElementById('other-upload-btn');
  if (otherBtn) {
    otherBtn.addEventListener('click', function() {
      openUploadModal('other', 'Other Document');
    });
  }

  document.querySelectorAll('[data-modal-close]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var modal = document.getElementById('upload-modal');
      if (modal) modal.classList.add('hidden');
    });
  });

  var modal = document.getElementById('upload-modal');
  if (modal) {
    modal.addEventListener('click', function(e) {
      if (e.target === modal) modal.classList.add('hidden');
    });
  }
});


/* ── Upload submit handler ──────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('form[data-upload]').forEach(function(form) {
    form.addEventListener('submit', function(e) {
      e.preventDefault();

      if (form.dataset.submitting) return;
      form.dataset.submitting = '1';

      var fileInput = form.querySelector('input[type="file"]');
      var progressWrap = form.querySelector('.upload-progress-wrap');
      var progressFill = form.querySelector('.upload-progress-fill');
      var progressPct  = form.querySelector('.upload-progress-pct');
      var resultEl     = form.querySelector('.upload-result');

      if (!fileInput || !fileInput.files || !fileInput.files.length) {
        alert('Please select a file to upload.');
        delete form.dataset.submitting;
        return;
      }

      if (progressWrap) progressWrap.classList.add('visible');
      if (progressFill) progressFill.style.width = '0%';
      if (progressPct)  progressPct.textContent = '0%';

      var xhr = new XMLHttpRequest();
      xhr.open('POST', window.location.href, true);
      xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

      xhr.upload.onprogress = function(evt) {
        if (evt.lengthComputable) {
          var pct = Math.round((evt.loaded / evt.total) * 100);
          if (progressFill) progressFill.style.width = pct + '%';
          if (progressPct)  progressPct.textContent = pct + '%';
        }
      };

      xhr.onload = function() {
        delete form.dataset.submitting;
        var ok = xhr.status >= 200 && xhr.status < 300;
        if (!ok) {
          if (resultEl) {
            resultEl.style.display = 'block';
            resultEl.innerHTML = '<div class="alert alert-error">Upload failed.</div>';
          } else {
            alert('Upload failed.');
          }
          return;
        }
        var res = null;
        try { res = JSON.parse(xhr.responseText); } catch (err) {}
        if (res && res.success) {
          window.location.href = window.location.pathname + window.location.search;
        } else {
          var msg = (res && res.message) ? res.message : 'Upload failed.';
          if (resultEl) {
            resultEl.style.display = 'block';
            resultEl.innerHTML = '<div class="alert alert-error">' + msg.replace(/</g,'&lt;') + '</div>';
          } else {
            alert(msg);
          }
        }
      };

      xhr.onerror = function() {
        delete form.dataset.submitting;
        if (resultEl) {
          resultEl.style.display = 'block';
          resultEl.innerHTML = '<div class="alert alert-error">Upload failed.</div>';
        } else {
          alert('Upload failed.');
        }
      };

      xhr.send(new FormData(form));
    });
  });
});

/* ── Table filter buttons ─────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {

  /* Inject active-filter style so the active button stands out */
  var filterStyle = document.createElement('style');
  filterStyle.textContent = [
    '.doc-filter { transition:background .15s,color .15s,border-color .15s; }',
    '.doc-filter.active { background:var(--cyan) !important; color:#000 !important;',
    '  border-color:var(--cyan) !important; font-weight:700; }',
    '.filter-count { display:inline-flex;align-items:center;justify-content:center;',
    '  background:rgba(255,255,255,.12);border-radius:20px;',
    '  font-size:.68rem;font-weight:800;padding:0 6px;min-width:18px;height:16px;',
    '  margin-left:5px;vertical-align:middle;line-height:1; }',
    '.doc-filter.active .filter-count { background:rgba(0,0,0,.18);color:#000; }',
    '.filter-alert { border-color:var(--rose) !important; color:var(--rose) !important; }',
    '.filter-alert .filter-count { background:rgba(239,68,68,.15); }'
  ].join('');
  document.head.appendChild(filterStyle);

  document.querySelectorAll('.upload-zone').forEach(function(zone) {
    // Click on the zone triggers the hidden file input.
    // We stop propagation on the input's own click so it doesn't bubble
    // back to the zone and fire a second dialog open.
    var input = zone.querySelector('input[type="file"]');
    if (input) {
      input.addEventListener('click', function(e) { e.stopPropagation(); });
    }
    zone.addEventListener('click', function() {
      if (input) input.click();
    });

    // Show selected filenames in the zone label
    if (input) {
      input.addEventListener('change', function() {
        var nameEl = zone.querySelector('.selected-filename');
        if (!nameEl) return;
        if (input.files && input.files.length > 0) {
          var names = Array.from(input.files).map(function(f) { return f.name; });
          nameEl.textContent = names.length === 1 ? names[0] : names.length + ' files selected';
        } else {
          nameEl.textContent = '';
        }
      });
    }
  });

  document.querySelectorAll('.doc-filter').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.doc-filter').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');

      var filter = btn.dataset.filter;
      document.querySelectorAll('tr.doc-row').forEach(function(row) {
        var isRequired = row.classList.contains('doc-required');
        var isMissing  = row.classList.contains('doc-missing');

        var show = true;
        if      (filter === 'required') show = isRequired;
        else if (filter === 'missing')  show = isMissing;
        // 'all' → always show

        row.style.display = show ? '' : 'none';
      });

      /* Update "no results" empty state */
      var tbody = document.querySelector('table tbody');
      if (tbody) {
        var visible = Array.from(tbody.querySelectorAll('tr.doc-row')).filter(function(r) {
          return r.style.display !== 'none';
        });
        var existing = tbody.querySelector('.filter-empty-row');
        if (visible.length === 0) {
          if (!existing) {
            var tr = document.createElement('tr');
            tr.className = 'filter-empty-row';
            tr.innerHTML = '<td colspan="5" style="padding:32px;text-align:center;color:var(--text-3);font-size:.86rem;">No documents match this filter.</td>';
            tbody.appendChild(tr);
          }
        } else {
          if (existing) existing.remove();
        }
      }
    });
  });

});

/* ── Upload progress CSS (in case theme sheet omits it) ────── */
(function() {
  var s = document.createElement('style');
  s.textContent = '.upload-progress-wrap{display:none}.upload-progress-wrap.visible{display:block}';
  document.head.appendChild(s);
})();
</script>
<?php pageFooter(); ?>
</body>
</html>
