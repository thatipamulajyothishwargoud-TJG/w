<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();
$isSA = $user['role'] === 'super_admin';
$canAccess          = $isSA || userCanAccessProjectDetailsModule((int)$user['id'], (string)$user['role']);
$restrictionMsg     = getComplianceRestrictionMessage();
$projectsTableReady = tableExists('projects');
$projectSetupMsg    = 'Project setup is incomplete. Please run `cf_config/cloudfen_full_schema.sql` in phpMyAdmin.';

$docLabels = ['MSA' => 'MSA', 'PO' => 'PO'];
$msg       = '';
$msgType   = '';

/* ── Detect whether project_id column exists on employee_documents ── */
$hasProjectIdCol = false;
try {
    $colCheck = $db->prepare(
        "SELECT COUNT(*) FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee_documents' AND COLUMN_NAME = 'project_id'"
    );
    $colCheck->execute([DB_NAME]);
    $hasProjectIdCol = (int)$colCheck->fetchColumn() > 0;
} catch (\Throwable $e) { /* silent — fall back to employee_id queries */ }

/* ── Employee list ───────────────────────────────────────── */
$employeeStmt = $db->query(
    "SELECT id, full_name, role FROM users
     WHERE role IN ('employee','hr_admin') AND status = 'active'
     ORDER BY full_name ASC"
);
$employees = $employeeStmt->fetchAll();

/* ── URL params ──────────────────────────────────────────── */
$selectedProjectId     = sanitizeInt($_GET['project_id'] ?? $_POST['project_id'] ?? 0, 1);
$activeTab             = validateEnum($_GET['tab'] ?? $_POST['tab'] ?? 'details', ['details','documents']) ?? 'details';
$isNewProject          = (isset($_GET['new']) && $_GET['new'] === '1' && !$selectedProjectId);
$filterEmployeeId      = sanitizeInt($_GET['filter_emp'] ?? 0, 1);

function buildProjectUrl(int $projectId, string $tab, int $filterEmployeeId = 0): string {
    $params = [
        'project_id' => $projectId,
        'tab' => $tab,
    ];
    if ($filterEmployeeId > 0) {
        $params['filter_emp'] = $filterEmployeeId;
    }
    return '?' . http_build_query($params);
}

/* ═══════════════════════════════════════════════════════════ *
 *  POST HANDLING
 * ═══════════════════════════════════════════════════════════ */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $canAccess) {
    verifyCsrfToken(true);
    $action = validateEnum($_POST['action'] ?? '', ['save_project','upload_document','review_document']);

    if ($action === 'save_project') {
        $projectId      = sanitizeInt($_POST['project_id'] ?? 0, 1);
        $employeeId     = sanitizeInt($_POST['employee_id'] ?? 0, 1);
        $clientName     = sanitizeString($_POST['client_name'] ?? '', 120);
        $projectName    = sanitizeString($_POST['project_name'] ?? '', 120);
        $invoicingEmail = sanitizeEmail($_POST['invoicing_email'] ?? '');
        $phoneNumber    = sanitizeString($_POST['phone_number'] ?? '', 30);
        $poc            = sanitizeString($_POST['point_of_contact'] ?? '', 120);
        $brRaw          = trim((string)($_POST['billing_rate'] ?? ''));
        $netDays        = sanitizeInt($_POST['net_days'] ?? 0, 0) ?? 0;
        $billingRate    = ($brRaw !== '' && is_numeric($brRaw))
                          ? number_format((float)$brRaw, 2, '.', '') : null;

        if (!$projectsTableReady) {
            $msg = $projectSetupMsg; $msgType = 'error';
        } elseif (!$employeeId || !$clientName || !$projectName) {
            $msg = 'Employee, client name, and project name are required.'; $msgType = 'error';
        } else {
            if ($projectId) {
                $stmt = $db->prepare(
                    "UPDATE projects
                     SET employee_id=?, client_name=?, project_name=?, invoicing_email=?,
                         phone_number=?, point_of_contact=?, billing_rate=?, net_days=?
                     WHERE id=?"
                );
                $stmt->execute([
                    $employeeId, $clientName, $projectName,
                    $invoicingEmail ?: null, $phoneNumber ?: null, $poc ?: null,
                    $billingRate, $netDays, $projectId,
                ]);
                auditLog('project_updated','projects',$projectId,[
                    'employee_id'=>$employeeId,'project_name'=>$projectName,
                ]);
                $selectedProjectId = $projectId;
                $isNewProject      = false;
                $msg = 'Project updated successfully.'; $msgType = 'success';
            } else {
                // Duplicate guard: prevent creating a project with the same employee + client + name
                $dupCheck = $db->prepare(
                    "SELECT id FROM projects WHERE employee_id=? AND client_name=? AND project_name=? LIMIT 1"
                );
                $dupCheck->execute([$employeeId, $clientName, $projectName]);
                $dupRow = $dupCheck->fetch();
                if ($dupRow) {
                    $msg = 'A project with this name already exists for this employee and client. Please use a different project name or edit the existing project.';
                    $msgType = 'error';
                    $selectedProjectId = (int)$dupRow['id'];
                } else {
                    $stmt = $db->prepare(
                        "INSERT INTO projects
                         (employee_id, client_name, project_name, invoicing_email,
                          phone_number, point_of_contact, billing_rate, net_days, created_by)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    );
                    $stmt->execute([
                        $employeeId, $clientName, $projectName,
                        $invoicingEmail ?: null, $phoneNumber ?: null, $poc ?: null,
                        $billingRate, $netDays, (int)$user['id'],
                    ]);
                    $selectedProjectId = (int)$db->lastInsertId();
                    auditLog('project_created','projects',$selectedProjectId,[
                        'employee_id'=>$employeeId,'project_name'=>$projectName,
                    ]);
                    $isNewProject = false;
                    $msg = 'Project created successfully.'; $msgType = 'success';
                }
            }
        }
    }

    if ($action === 'upload_document') {
        $projectId    = sanitizeInt($_POST['project_id'] ?? 0, 1);
        $employeeId   = sanitizeInt($_POST['employee_id'] ?? 0, 1);
        $documentType = validateEnum($_POST['document_type'] ?? '', array_keys($docLabels));
        $description  = sanitizeString($_POST['description'] ?? '', 1000);

        if (!$employeeId || !$documentType) {
            $msg = 'Employee and document type are required.'; $msgType = 'error';
        } elseif (
            empty($_FILES['document_file']) ||
            ($_FILES['document_file']['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE
        ) {
            $msg = 'Please select a file to upload.'; $msgType = 'error';
        } else {
            /* Always save as NEW version — never replace/delete existing docs.
               Pass $projectId so version_no and is_current are scoped per-project
               and the project_id is saved atomically inside the transaction. */
            $result = handleEmployeeProjectDocumentUpload(
                $_FILES['document_file'],
                $employeeId,
                (string)$documentType,
                (int)$user['id'],
                $description !== '' ? $description : null,
                null,        /* replaceId = null → new version each time */
                'pending',
                $projectId ?: null   /* project_id — scopes version_no + is_current */
            );

            if ($result['success']) {
                auditLog('project_doc_uploaded','employee_documents',$result['id']??null,[
                    'employee_id'=>$employeeId,'project_id'=>$projectId,'document_type'=>$documentType,
                ]);
                $selectedProjectId = (int)($projectId ?: $selectedProjectId);
                $activeTab = 'documents';
                $msg = $result['message']; $msgType = 'success';
            } else {
                $msg = $result['message']; $msgType = 'error';
            }
        }
    }

    if ($action === 'review_document') {
        $docId        = sanitizeInt($_POST['doc_id'] ?? 0, 1);
        $reviewAction = validateEnum($_POST['review_action'] ?? '', ['approve', 'reject']);
        $activeTab    = 'documents';

        if (!$docId || !$reviewAction) {
            $msg = 'Invalid document review request.'; $msgType = 'error';
        } else {
            $docStmt = $db->prepare(
                "SELECT d.*, u.full_name AS emp_name
                 FROM employee_documents d JOIN users u ON u.id = d.employee_id
                 WHERE d.id = ? LIMIT 1"
            );
            $docStmt->execute([$docId]);
            $reviewDoc = $docStmt->fetch();

            if (!$reviewDoc) {
                $msg = 'Document not found.'; $msgType = 'error';
            } else {
                $newStatus = $reviewAction === 'approve' ? 'approved' : 'rejected';
                $upd = $db->prepare(
                    "UPDATE employee_documents SET status = ? WHERE id = ? AND status = 'pending'"
                );
                $upd->execute([$newStatus, $docId]);

                if ($upd->rowCount() === 0) {
                    $msg = 'This document was already reviewed (current status: ' . e($reviewDoc['status']) . '). Refresh to see the latest state.';
                    $msgType = 'error';
                } else {
                    auditLog('project_doc_' . $reviewAction . 'd', 'employee_documents', $docId, [
                        'employee_id'   => (int)$reviewDoc['employee_id'],
                        'document_type' => $reviewDoc['document_type'],
                    ]);
                    $label = $docLabels[$reviewDoc['document_type']] ?? $reviewDoc['document_type'];
                    createNotification(
                        (int)$reviewDoc['employee_id'],
                        'project_doc_' . $reviewAction,
                        'Document ' . ($newStatus === 'approved' ? 'Approved' : 'Rejected'),
                        "Your {$label} document was {$newStatus}.",
                        '/employee/documents.php'
                    );
                    $msg = 'Document ' . e($newStatus) . ' successfully.';
                    $msgType = 'success';
                }
                $selectedProjectId = (int)($reviewDoc['project_id'] ?: $selectedProjectId);
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════ *
 *  DATA LOADING
 * ═══════════════════════════════════════════════════════════ */
$allProjects = [];
if ($projectsTableReady) {
    if ($filterEmployeeId) {
        $allStmt = $db->prepare(
            "SELECT p.id, p.project_name, p.client_name, u.full_name AS employee_name
             FROM projects p JOIN users u ON u.id = p.employee_id
             WHERE p.employee_id = ?
             ORDER BY p.project_name ASC, p.id DESC"
        );
        $allStmt->execute([$filterEmployeeId]);
    } else {
        $allStmt = $db->query(
            "SELECT p.id, p.project_name, p.client_name, u.full_name AS employee_name
             FROM projects p JOIN users u ON u.id = p.employee_id
             ORDER BY p.project_name ASC, p.id DESC"
        );
    }
    $allProjects = $allStmt->fetchAll();
}

$selectedProject    = null;
$selectedEmployeeId = 0;
if ($selectedProjectId && $projectsTableReady) {
    $pStmt = $db->prepare(
        "SELECT p.*, u.full_name AS employee_name
         FROM projects p JOIN users u ON u.id = p.employee_id
         WHERE p.id = ? LIMIT 1"
    );
    $pStmt->execute([$selectedProjectId]);
    $selectedProject = $pStmt->fetch() ?: null;
    if ($selectedProject) {
        $selectedEmployeeId = (int)$selectedProject['employee_id'];
    }
}

/* Documents grouped by type, newest version first.
   Try project_id (precise) first; fall back to employee_id for legacy rows. */
$docsByType = [];
if ($selectedProjectId && $selectedEmployeeId) {
    $docs = [];

    if ($hasProjectIdCol) {
        try {
            $ds = $db->prepare(
                "SELECT d.*, u.full_name AS uploaded_by_name
                 FROM employee_documents d JOIN users u ON u.id = d.uploaded_by
                 WHERE d.project_id = ? AND d.document_type IN ('MSA','PO')
                 ORDER BY d.document_type ASC, d.version_no DESC, d.uploaded_at DESC"
            );
            $ds->execute([$selectedProjectId]);
            $docs = $ds->fetchAll();
        } catch (\Throwable $e) {
            error_log('project_details doc query (project_id): ' . $e->getMessage());
        }
    }

    if (empty($docs)) {   /* fallback: legacy rows that predate project_id column */
        try {
            $ds = $db->prepare(
                "SELECT d.*, u.full_name AS uploaded_by_name
                 FROM employee_documents d JOIN users u ON u.id = d.uploaded_by
                 WHERE d.employee_id = ? AND d.document_type IN ('MSA','PO')
                   AND (d.project_id IS NULL OR d.project_id = ?)
                 ORDER BY d.document_type ASC, d.version_no DESC, d.uploaded_at DESC"
            );
            $ds->execute([$selectedEmployeeId, $selectedProjectId]);
            $docs = $ds->fetchAll();
        } catch (\Throwable $e) {
            /* project_id column may not exist on very old installs — try without */
            try {
                $ds = $db->prepare(
                    "SELECT d.*, u.full_name AS uploaded_by_name
                     FROM employee_documents d JOIN users u ON u.id = d.uploaded_by
                     WHERE d.employee_id = ? AND d.document_type IN ('MSA','PO')
                     ORDER BY d.document_type ASC, d.version_no DESC, d.uploaded_at DESC"
                );
                $ds->execute([$selectedEmployeeId]);
                $docs = $ds->fetchAll();
            } catch (\Throwable $e2) {
                error_log('project_details doc query (employee_id): ' . $e2->getMessage());
            }
        }
    }

    foreach ($docs as $doc) {
        $docsByType[(string)$doc['document_type']][] = $doc;
    }
}

/* ═══════════════════════════════════════════════════════════ *
 *  RENDER
 * ═══════════════════════════════════════════════════════════ */
pageHead('Project Details');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id'=>$user['id'],'name'=>$user['name'],'role'=>$user['role']],'project_details'); ?>
  <div class="main-content">
    <?php renderTopbar('Project Details', $user); ?>
    <div class="page-body">

      <?php if (!$canAccess): ?>
        <div class="alert alert-warn"><?= e($restrictionMsg) ?></div>
      <?php elseif (!$projectsTableReady): ?>
        <div class="alert alert-error"><?= e($projectSetupMsg) ?></div>
      <?php else: ?>

      <!-- ════ TOP BAR: search + new ════════════════════════════════════ -->
      <div class="pd-topbar">
        <div class="pd-topbar-left">
          <div class="pd-search-box">
            <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor" class="pd-search-icon"><path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/></svg>
            <input type="text" id="pdSearch" placeholder="Search projects, clients, employees…" autocomplete="off">
          </div>
          <form method="GET" id="pdEmpFilterForm" style="display:flex;align-items:center;gap:0;">
            <?php if ($selectedProjectId): ?><input type="hidden" name="project_id" value="<?= (int)$selectedProjectId ?>"><?php endif; ?>
            <?php if ($activeTab !== 'details'): ?><input type="hidden" name="tab" value="<?= e($activeTab) ?>"><?php endif; ?>
            <div class="pd-select-wrap">
              <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor" class="pd-sel-icon"><path d="M10 10a4 4 0 100-8 4 4 0 000 8zm0 2c-5 0-8 2.24-8 4v1h16v-1c0-1.76-3-4-8-4z"/></svg>
              <select name="filter_emp" class="pd-select" onchange="document.getElementById('pdEmpFilterForm').submit()">
                <option value="">All Employees</option>
                <?php foreach ($employees as $emp): ?>
                  <option value="<?= (int)$emp['id'] ?>" <?= $filterEmployeeId===(int)$emp['id']?'selected':'' ?>>
                    <?= e($emp['full_name']) ?><?= $emp['role']==='hr_admin'?' (HR)':'' ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </div>
            <?php if ($filterEmployeeId): ?>
              <a href="?" class="pd-clear-filter" title="Clear filter">✕</a>
            <?php endif; ?>
          </form>
        </div>
        <a href="?new=1<?= $filterEmployeeId?'&filter_emp='.(int)$filterEmployeeId:'' ?>" class="btn btn-primary btn-sm">
          <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor" style="margin-right:5px;"><path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/></svg>
          New Project
        </a>
      </div>

      <!-- ════ MAIN LAYOUT ═══════════════════════════════════════════════ -->
      <div class="pd-layout">

        <!-- LEFT: project list -->
        <aside class="pd-sidebar">
          <?php if (empty($allProjects)): ?>
            <div class="pd-list-empty">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"/></svg>
              <span><?= $filterEmployeeId ? 'No projects for this employee.' : 'No projects yet.' ?></span>
            </div>
          <?php else: ?>
            <?php if ($filterEmployeeId): ?>
              <div class="pd-filter-chip">
                <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path d="M10 10a4 4 0 100-8 4 4 0 000 8zm0 2c-5 0-8 2.24-8 4v1h16v-1c0-1.76-3-4-8-4z"/></svg>
                <?= count($allProjects) ?> project<?= count($allProjects)!==1?'s':'' ?>
              </div>
            <?php endif; ?>
            <?php foreach ($allProjects as $proj): ?>
              <a href="<?= e(buildProjectUrl((int)$proj['id'], 'details', (int)$filterEmployeeId)) ?>"
                 class="pd-list-item<?= $selectedProjectId===(int)$proj['id']?' is-active':'' ?>"
                 data-name="<?= strtolower(e($proj['project_name'])) ?>"
                 data-client="<?= strtolower(e($proj['client_name'])) ?>"
                 data-emp="<?= strtolower(e($proj['employee_name'])) ?>">
                <div class="pd-list-avatar"><?= e(strtoupper(substr((string)$proj['project_name'],0,2))) ?></div>
                <div class="pd-list-copy">
                  <div class="pd-list-name"><?= e($proj['project_name']) ?></div>
                  <div class="pd-list-meta"><?= e($proj['client_name']) ?></div>
                  <div class="pd-list-emp">
                    <svg width="9" height="9" viewBox="0 0 20 20" fill="currentColor"><path d="M10 10a4 4 0 100-8 4 4 0 000 8zm0 2c-5 0-8 2.24-8 4v1h16v-1c0-1.76-3-4-8-4z"/></svg>
                    <?= e($proj['employee_name']) ?>
                  </div>
                </div>
                <svg class="pd-list-chevron" width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path d="M7.293 4.707L12.586 10l-5.293 5.293 1.414 1.414L15.414 10 8.707 3.293z"/></svg>
              </a>
            <?php endforeach; ?>
          <?php endif; ?>
        </aside>

        <!-- RIGHT: main panel -->
        <div class="pd-main">

          <?php if ($msg): ?>
            <div class="alert alert-<?= $msgType==='error'?'error':'success' ?>" style="margin-bottom:20px;"><?= e($msg) ?></div>
          <?php endif; ?>

          <?php if ($isNewProject): ?>
          <!-- ════ NEW PROJECT FORM ════════════════════════════════════ -->
            <div class="pd-panel-header">
              <div class="pd-panel-avatar pd-avatar-new">+</div>
              <div>
                <h2 class="pd-panel-title">New Project</h2>
                <p class="pd-panel-sub">Fill in the project details below.</p>
              </div>
            </div>
            <div class="card">
              <div class="card-body">
                <form method="POST" class="pd-form">
                  <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
                  <input type="hidden" name="action" value="save_project">
                  <input type="hidden" name="tab" value="details">
                  <input type="hidden" name="project_id" value="0">
                  <div class="pd-form-grid">
                    <div class="form-group">
                      <label>Employee <span class="required">*</span></label>
                      <select name="employee_id" class="form-control" required>
                        <option value="">Select employee</option>
                        <?php foreach ($employees as $emp): ?>
                          <option value="<?= (int)$emp['id'] ?>">
                            <?= e($emp['full_name']) ?><?= $emp['role']==='hr_admin'?' (HR)':'' ?>
                          </option>
                        <?php endforeach; ?>
                      </select>
                    </div>
                    <div class="form-group">
                      <label>Client Name <span class="required">*</span></label>
                      <input type="text" name="client_name" class="form-control" maxlength="120" required>
                    </div>
                    <div class="form-group">
                      <label>Project Name <span class="required">*</span></label>
                      <input type="text" name="project_name" class="form-control" maxlength="120" required>
                    </div>
                    <div class="form-group">
                      <label>Invoicing Email</label>
                      <input type="email" name="invoicing_email" class="form-control" maxlength="180">
                    </div>
                    <div class="form-group">
                      <label>Phone Number</label>
                      <input type="text" name="phone_number" class="form-control" maxlength="30">
                    </div>
                    <div class="form-group">
                      <label>Point of Contact</label>
                      <input type="text" name="point_of_contact" class="form-control" maxlength="120">
                    </div>
                    <div class="form-group">
                      <label>Billing Rate ($/hr)</label>
                      <input type="number" name="billing_rate" class="form-control" min="0" step="0.01">
                    </div>
                    <div class="form-group">
                      <label>Net Days</label>
                      <input type="number" name="net_days" class="form-control" min="0" step="1">
                    </div>
                  </div>
                  <div class="pd-form-actions">
                    <button type="submit" class="btn btn-primary">Create Project</button>
                    <a href="?" class="btn btn-outline">Cancel</a>
                  </div>
                </form>
              </div>
            </div>

          <?php elseif ($selectedProject): ?>
          <!-- ════ EXISTING PROJECT ════════════════════════════════════ -->

            <!-- Hero -->
            <div class="pd-hero">
              <div class="pd-hero-left">
                <div class="pd-hero-avatar"><?= e(strtoupper(substr((string)$selectedProject['project_name'],0,2))) ?></div>
                <div class="pd-hero-info">
                  <h2 class="pd-hero-title"><?= e($selectedProject['project_name']) ?></h2>
                  <div class="pd-hero-meta">
                    <span class="pd-hero-chip">
                      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path d="M10 10a4 4 0 100-8 4 4 0 000 8zm0 2c-5 0-8 2.24-8 4v1h16v-1c0-1.76-3-4-8-4z"/></svg>
                      <?= e($selectedProject['employee_name']) ?>
                    </span>
                    <span class="pd-hero-chip">
                      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path d="M6 6V4a2 2 0 012-2h4a2 2 0 012 2v2h3a1 1 0 011 1v9a2 2 0 01-2 2H4a2 2 0 01-2-2V7a1 1 0 011-1h3z"/></svg>
                      <?= e($selectedProject['client_name']) ?>
                    </span>
                    <?php if ($selectedProject['billing_rate']): ?>
                    <span class="pd-hero-chip pd-chip-green">
                      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path d="M8.433 7.418c.155-.103.346-.196.567-.267v1.698a2.305 2.305 0 01-.567-.267C8.07 8.34 8 8.114 8 8c0-.114.07-.34.433-.582zM11 12.849v-1.698c.22.071.412.164.567.267.364.243.433.468.433.582 0 .114-.07.34-.433.582a2.305 2.305 0 01-.567.267z"/><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-13a1 1 0 10-2 0v.092a4.535 4.535 0 00-1.676.662C6.602 6.234 6 7.009 6 8c0 .99.602 1.765 1.324 2.246.48.32 1.054.545 1.676.662v1.941c-.391-.127-.68-.317-.843-.504a1 1 0 10-1.51 1.31c.562.649 1.413 1.076 2.353 1.253V15a1 1 0 102 0v-.092a4.535 4.535 0 001.676-.662C13.398 13.766 14 12.991 14 12c0-.99-.602-1.765-1.324-2.246A4.535 4.535 0 0011 9.092V7.151c.391.127.68.317.843.504a1 1 0 101.511-1.31c-.563-.649-1.413-1.076-2.354-1.253V5z" clip-rule="evenodd"/></svg>
                      $<?= e(number_format((float)$selectedProject['billing_rate'],2)) ?>/hr
                    </span>
                    <?php endif; ?>
                    <?php if ($selectedProject['net_days']): ?>
                    <span class="pd-hero-chip">Net <?= (int)$selectedProject['net_days'] ?></span>
                    <?php endif; ?>
                  </div>
                </div>
              </div>
              <div class="pd-hero-actions">
                <!-- Stat pills -->
                <?php $totalDocs = count($docsByType['MSA']??[]) + count($docsByType['PO']??[]); ?>
                <?php $msaLatest = ($docsByType['MSA']??[])[0] ?? null; ?>
                <?php $poLatest  = ($docsByType['PO']??[])[0]  ?? null; ?>
                <div class="pd-stat-pill <?= $msaLatest && $msaLatest['status']==='approved' ? 'pd-pill-ok' : ($msaLatest ? 'pd-pill-warn' : 'pd-pill-missing') ?>">
                  <span class="pd-stat-label">MSA</span>
                  <span class="pd-stat-val"><?= $msaLatest ? ucfirst($msaLatest['status']) : 'Missing' ?></span>
                </div>
                <div class="pd-stat-pill <?= $poLatest && $poLatest['status']==='approved' ? 'pd-pill-ok' : ($poLatest ? 'pd-pill-warn' : 'pd-pill-missing') ?>">
                  <span class="pd-stat-label">PO</span>
                  <span class="pd-stat-val"><?= $poLatest ? ucfirst($poLatest['status']) : 'Missing' ?></span>
                </div>
              </div>
            </div>

            <!-- Tabs -->
            <div class="pd-tabs">
              <a href="<?= e(buildProjectUrl((int)$selectedProjectId, 'details', (int)$filterEmployeeId)) ?>"
                 class="pd-tab<?= $activeTab==='details'?' is-active':'' ?>">
                <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clip-rule="evenodd"/></svg>
                Details
              </a>
              <a href="<?= e(buildProjectUrl((int)$selectedProjectId, 'documents', (int)$filterEmployeeId)) ?>"
                 class="pd-tab<?= $activeTab==='documents'?' is-active':'' ?>">
                <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm3 1h2v2H7V5zm2 4H7v2h2V9zm2-4h2v2h-2V5zm2 4h-2v2h2V9z" clip-rule="evenodd"/></svg>
                Documents
                <?php if ($totalDocs): ?>
                  <span class="pd-tab-badge"><?= $totalDocs ?></span>
                <?php endif; ?>
              </a>
            </div>

            <?php if ($activeTab === 'details'): ?>
            <!-- ════ DETAILS TAB ════════════════════════════════════ -->
            <div class="pd-details-grid">

              <!-- Left: edit form -->
              <div class="card">
                <div class="card-header" style="padding:16px 20px;">
                  <h3 style="font-size:.88rem;font-weight:700;color:var(--text-2);text-transform:uppercase;letter-spacing:.06em;margin:0;">Edit Project</h3>
                </div>
                <div class="card-body">
                  <form method="POST" class="pd-form">
                    <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
                    <input type="hidden" name="action"     value="save_project">
                    <input type="hidden" name="tab"        value="details">
                    <input type="hidden" name="project_id" value="<?= (int)$selectedProject['id'] ?>">

                    <div class="form-group">
                      <label>Employee <span class="req">*</span></label>
                      <select name="employee_id" class="form-control" required>
                        <option value="">Select employee</option>
                        <?php foreach ($employees as $emp): ?>
                          <option value="<?= (int)$emp['id'] ?>" <?= $selectedEmployeeId===(int)$emp['id']?'selected':'' ?>>
                            <?= e($emp['full_name']) ?><?= $emp['role']==='hr_admin'?' (HR)':'' ?>
                          </option>
                        <?php endforeach; ?>
                      </select>
                    </div>
                    <div class="pd-form-row">
                      <div class="form-group">
                        <label>Client Name <span class="req">*</span></label>
                        <input type="text" name="client_name" class="form-control" maxlength="120" required
                               value="<?= e((string)($selectedProject['client_name']??'')) ?>">
                      </div>
                      <div class="form-group">
                        <label>Project Name <span class="req">*</span></label>
                        <input type="text" name="project_name" class="form-control" maxlength="120" required
                               value="<?= e((string)($selectedProject['project_name']??'')) ?>">
                      </div>
                    </div>
                    <div class="pd-form-row">
                      <div class="form-group">
                        <label>Invoicing Email</label>
                        <input type="email" name="invoicing_email" class="form-control" maxlength="180"
                               value="<?= e((string)($selectedProject['invoicing_email']??'')) ?>">
                      </div>
                      <div class="form-group">
                        <label>Phone Number</label>
                        <input type="text" name="phone_number" class="form-control" maxlength="30"
                               value="<?= e((string)($selectedProject['phone_number']??'')) ?>">
                      </div>
                    </div>
                    <div class="form-group">
                      <label>Point of Contact</label>
                      <input type="text" name="point_of_contact" class="form-control" maxlength="120"
                             value="<?= e((string)($selectedProject['point_of_contact']??'')) ?>">
                    </div>
                    <div class="pd-form-row">
                      <div class="form-group">
                        <label>Billing Rate ($/hr)</label>
                        <input type="number" name="billing_rate" class="form-control" min="0" step="0.01"
                               value="<?= e((string)($selectedProject['billing_rate']??'')) ?>">
                      </div>
                      <div class="form-group">
                        <label>Net Days</label>
                        <input type="number" name="net_days" class="form-control" min="0" step="1"
                               value="<?= e((string)($selectedProject['net_days']??'')) ?>">
                      </div>
                    </div>
                    <div class="pd-form-actions">
                      <button type="submit" class="btn btn-primary">Save Changes</button>
                      <?php if (!empty($selectedProject['created_at'])): ?>
                        <span style="font-size:.76rem;color:var(--text-3);">
                          Created <?= e(date('M j, Y', strtotime((string)$selectedProject['created_at']))) ?>
                        </span>
                      <?php endif; ?>
                    </div>
                  </form>
                </div>
              </div>

              <!-- Right: info summary -->
              <div style="display:flex;flex-direction:column;gap:16px;">

                <!-- Key info card -->
                <div class="card">
                  <div class="card-header" style="padding:14px 20px;">
                    <h3 style="font-size:.88rem;font-weight:700;color:var(--text-2);text-transform:uppercase;letter-spacing:.06em;margin:0;">Project Summary</h3>
                  </div>
                  <div style="padding:0;">
                    <table class="pd-summary-table">
                      <tr>
                        <td>Assigned To</td>
                        <td><strong><?= e($selectedProject['employee_name']) ?></strong></td>
                      </tr>
                      <tr>
                        <td>Client</td>
                        <td><?= e($selectedProject['client_name']) ?></td>
                      </tr>
                      <?php if ($selectedProject['point_of_contact']): ?>
                      <tr>
                        <td>POC</td>
                        <td><?= e($selectedProject['point_of_contact']) ?></td>
                      </tr>
                      <?php endif; ?>
                      <?php if ($selectedProject['invoicing_email']): ?>
                      <tr>
                        <td>Invoice Email</td>
                        <td><a href="mailto:<?= e($selectedProject['invoicing_email']) ?>" style="color:var(--cyan);"><?= e($selectedProject['invoicing_email']) ?></a></td>
                      </tr>
                      <?php endif; ?>
                      <?php if ($selectedProject['phone_number']): ?>
                      <tr>
                        <td>Phone</td>
                        <td><?= e($selectedProject['phone_number']) ?></td>
                      </tr>
                      <?php endif; ?>
                      <?php if ($selectedProject['billing_rate']): ?>
                      <tr>
                        <td>Billing Rate</td>
                        <td style="color:var(--green);font-weight:700;">$<?= e(number_format((float)$selectedProject['billing_rate'],2)) ?>/hr</td>
                      </tr>
                      <?php endif; ?>
                      <?php if ($selectedProject['net_days']): ?>
                      <tr>
                        <td>Payment Terms</td>
                        <td>Net <?= (int)$selectedProject['net_days'] ?></td>
                      </tr>
                      <?php endif; ?>
                    </table>
                  </div>
                </div>

                <!-- Documents status card -->
                <div class="card">
                  <div class="card-header" style="padding:14px 20px;justify-content:space-between;">
                    <h3 style="font-size:.88rem;font-weight:700;color:var(--text-2);text-transform:uppercase;letter-spacing:.06em;margin:0;">Compliance Docs</h3>
                    <a href="<?= e(buildProjectUrl((int)$selectedProjectId, 'documents', (int)$filterEmployeeId)) ?>" style="font-size:.78rem;color:var(--cyan);font-weight:600;text-decoration:none;">Manage →</a>
                  </div>
                  <div style="padding:12px 20px;display:flex;flex-direction:column;gap:10px;">
                    <?php foreach ($docLabels as $dtype => $dlabel):
                      $latest = ($docsByType[$dtype]??[])[0] ?? null;
                      $ds = $latest ? $latest['status'] : null;
                      $statusClass = match($ds) { 'approved'=>'doc-status-ok','pending'=>'doc-status-pending','rejected'=>'doc-status-reject', default=>'doc-status-missing' };
                      $statusText  = match($ds) { 'approved'=>'Approved','pending'=>'In Review','rejected'=>'Rejected', default=>'Not Uploaded' };
                    ?>
                    <div class="pd-compliance-row">
                      <div class="pd-compliance-icon"><?= $dtype ?></div>
                      <div class="pd-compliance-info">
                        <div class="pd-compliance-label"><?= e($dlabel) ?> Document</div>
                        <?php if ($latest): ?>
                          <div class="pd-compliance-meta">v<?= (int)$latest['version_no'] ?> · <?= e(date('M j, Y', strtotime((string)$latest['uploaded_at']))) ?></div>
                        <?php endif; ?>
                      </div>
                      <span class="pd-doc-status <?= $statusClass ?>"><?= $statusText ?></span>
                    </div>
                    <?php endforeach; ?>
                  </div>
                </div>

              </div><!-- /right col -->
            </div><!-- /pd-details-grid -->

            <?php else: ?>
            <!-- ════ DOCUMENTS TAB ══════════════════════════════════ -->
            <div class="pd-doc-page">
              <?php foreach ($docLabels as $dtype => $dlabel):
                $typeDocs = $docsByType[$dtype] ?? [];
                $docCount = count($typeDocs);
                $latestDoc = $typeDocs[0] ?? null;
                $latestStatus = $latestDoc ? $latestDoc['status'] : null;
              ?>
              <div class="pd-doc-section">
                <!-- Section header -->
                <div class="pd-doc-section-head">
                  <div class="pd-doc-section-left">
                    <div class="pd-dtype-badge"><?= e($dtype) ?></div>
                    <div>
                      <div class="pd-doc-section-title"><?= e($dlabel) ?> Document</div>
                      <div class="pd-doc-section-sub">
                        <?php if ($docCount): ?>
                          <?= $docCount ?> version<?= $docCount!==1?'s':'' ?> &nbsp;·&nbsp;
                          <?php
                            $cntApproved = count(array_filter($typeDocs, fn($d)=>$d['status']==='approved'));
                            $cntPending  = count(array_filter($typeDocs, fn($d)=>$d['status']==='pending'));
                            $cntRejected = count(array_filter($typeDocs, fn($d)=>$d['status']==='rejected'));
                          ?>
                          <?php if ($cntApproved): ?><span style="color:var(--green);">✓ <?= $cntApproved ?> approved</span><?php endif; ?>
                          <?php if ($cntPending):  ?>&nbsp;<span style="color:var(--amber);">⏳ <?= $cntPending ?> pending</span><?php endif; ?>
                          <?php if ($cntRejected): ?>&nbsp;<span style="color:var(--rose);">✗ <?= $cntRejected ?> rejected</span><?php endif; ?>
                        <?php else: ?>
                          <span style="color:var(--rose);">No document uploaded</span>
                        <?php endif; ?>
                      </div>
                    </div>
                  </div>
                  <button type="button" class="btn btn-outline btn-sm pd-upload-toggle"
                          data-target="pd-upload-<?= strtolower($dtype) ?>">
                    <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor" style="margin-right:4px;"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z" clip-rule="evenodd"/></svg>
                    Upload New Version
                  </button>
                </div>

                <!-- Upload form -->
                <div class="pd-upload-panel" id="pd-upload-<?= strtolower($dtype) ?>" hidden>
                  <form method="POST" enctype="multipart/form-data" class="pd-upload-inner">
                    <input type="hidden" name="csrf_token"    value="<?= e(generateCsrfToken()) ?>">
                    <input type="hidden" name="action"        value="upload_document">
                    <input type="hidden" name="tab"           value="documents">
                    <input type="hidden" name="employee_id"   value="<?= (int)$selectedEmployeeId ?>">
                    <input type="hidden" name="project_id"    value="<?= (int)$selectedProjectId ?>">
                    <input type="hidden" name="document_type" value="<?= e($dtype) ?>">
                    <input type="hidden" name="description"   value="<?= e($dlabel) ?> document">
                    <div class="pd-drop-zone">
                      <input type="file" name="document_file" class="pd-drop-input" accept=".pdf,.docx" required>
                      <div class="pd-drop-content">
                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                        <span class="pd-drop-label">Drop file or <strong>browse</strong></span>
                        <span class="pd-drop-hint">PDF or DOCX — saved as a new version</span>
                      </div>
                      <div class="pd-drop-selected" hidden></div>
                    </div>
                    <div class="pd-upload-actions">
                      <button type="submit" class="btn btn-primary">Save Document</button>
                      <button type="button" class="btn btn-outline pd-upload-cancel" data-target="pd-upload-<?= strtolower($dtype) ?>">Cancel</button>
                    </div>
                  </form>
                </div>

                <!-- Version list -->
                <?php if ($docCount): ?>
                  <div class="pd-version-list" id="nav-<?= strtolower($dtype) ?>">
                    <?php foreach ($typeDocs as $i => $doc):
                      $dStatus  = (string)($doc['status']??'pending');
                      $isCurrent= (int)($doc['is_current']??0) === 1;
                      $ext      = strtoupper(pathinfo((string)($doc['file_name']??''), PATHINFO_EXTENSION) ?: 'DOC');
                    ?>
                    <div class="pd-version-card<?= $i===0?' is-active':'' ?> <?= $dStatus==='approved'?'vc-approved':($dStatus==='rejected'?'vc-rejected':'') ?>">
                      <div class="pd-vc-left">
                        <div class="pd-vc-ext <?= $ext==='PDF'?'vc-pdf':($ext==='DOCX'?'vc-docx':'') ?>"><?= $ext ?></div>
                        <div class="pd-vc-info">
                          <div class="pd-vc-name">
                            <?= e((string)($doc['file_name']??'Unnamed file')) ?>
                            <?php if ($isCurrent): ?><span class="pd-current-chip">Current</span><?php endif; ?>
                          </div>
                          <div class="pd-vc-meta">
                            Version <?= (int)$doc['version_no'] ?>
                            &nbsp;·&nbsp; <?= e(date('M j, Y', strtotime((string)$doc['uploaded_at']))) ?>
                            &nbsp;·&nbsp; <?= e((string)($doc['uploaded_by_name']??'HR/Admin')) ?>
                          </div>
                          <?php if (!empty($doc['description'])): ?>
                            <div class="pd-vc-desc"><?= e((string)$doc['description']) ?></div>
                          <?php endif; ?>
                        </div>
                      </div>
                      <div class="pd-vc-right">
                        <span class="badge badge-<?= $dStatus==='approved'?'approved':($dStatus==='rejected'?'rejected':'pending') ?>"><?= e(ucfirst($dStatus)) ?></span>
                        <div class="pd-vc-btns">
                          <a href="<?= e(getEmployeeProjectDocumentServeUrl((int)$doc['id'],(int)$user['id'],false)) ?>" target="_blank" class="btn btn-outline btn-sm">View</a>
                          <a href="<?= e(getEmployeeProjectDocumentServeUrl((int)$doc['id'],(int)$user['id'],true)) ?>" class="btn btn-outline btn-sm">↓</a>
                          <?php if ($dStatus === 'pending'): ?>
                          <form method="POST" style="display:inline;">
                            <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
                            <input type="hidden" name="action" value="review_document">
                            <input type="hidden" name="tab" value="documents">
                            <input type="hidden" name="project_id" value="<?= (int)$selectedProjectId ?>">
                            <input type="hidden" name="doc_id" value="<?= (int)$doc['id'] ?>">
                            <input type="hidden" name="review_action" value="approve">
                            <button type="submit" class="btn btn-sm" style="background:rgba(52,211,153,.12);color:var(--green);border:1px solid rgba(52,211,153,.2);">Approve</button>
                          </form>
                          <form method="POST" style="display:inline;">
                            <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
                            <input type="hidden" name="action" value="review_document">
                            <input type="hidden" name="tab" value="documents">
                            <input type="hidden" name="project_id" value="<?= (int)$selectedProjectId ?>">
                            <input type="hidden" name="doc_id" value="<?= (int)$doc['id'] ?>">
                            <input type="hidden" name="review_action" value="reject">
                            <button type="submit" class="btn btn-sm" style="background:rgba(239,68,68,.1);color:var(--rose);border:1px solid rgba(239,68,68,.18);">Reject</button>
                          </form>
                          <?php endif; ?>
                        </div>
                      </div>
                    </div>
                    <?php endforeach; ?>

                    <?php if ($docCount > 1): ?>
                    <div class="pd-nav-bar">
                      <button type="button" class="pd-nav-btn pd-nav-prev" data-nav="<?= strtolower($dtype) ?>" disabled>
                        <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path d="M13.293 4.293L7.586 10l5.707 5.707 1.414-1.414L10.414 10l4.293-4.293z"/></svg>
                      </button>
                      <span class="pd-nav-count" id="nav-counter-<?= strtolower($dtype) ?>">1 / <?= $docCount ?></span>
                      <button type="button" class="pd-nav-btn pd-nav-next" data-nav="<?= strtolower($dtype) ?>">
                        <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path d="M6.707 4.293L12.414 10l-5.707 5.707 1.414 1.414L14.828 10 8.121 2.879z"/></svg>
                      </button>
                    </div>
                    <?php endif; ?>
                  </div>
                <?php else: ?>
                  <div class="pd-no-doc">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
                    No <?= e($dlabel) ?> document uploaded yet. Click <strong>Upload New Version</strong> to add one.
                  </div>
                <?php endif; ?>
              </div>
              <?php endforeach; ?>
            </div>
            <?php endif; /* tab */ ?>

          <?php else: ?>
          <!-- ════ EMPTY STATE ═══════════════════════════════════════ -->
            <div class="pd-empty">
              <div class="pd-empty-icon">
                <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"/><line x1="12" y1="12" x2="12" y2="16"/><line x1="10" y1="14" x2="14" y2="14"/></svg>
              </div>
              <h3>No project selected</h3>
              <p>Pick a project from the list on the left, or create a new one.</p>
              <a href="?new=1" class="btn btn-primary">+ New Project</a>
            </div>
          <?php endif; ?>

        </div><!-- /pd-main -->
      </div><!-- /pd-layout -->

      <?php endif; /* canAccess */ ?>
    </div><!-- /page-body -->
  </div>
</div>
<?php pageFooter(); ?>

<script>
/* ── Sidebar live search ─────────────────────────────────── */
(function(){
  var inp = document.getElementById('pdSearch');
  if (!inp) return;
  inp.addEventListener('input', function(){
    var q = inp.value.trim().toLowerCase();
    document.querySelectorAll('.pd-list-item').forEach(function(el){
      var hit = !q||(el.dataset.name||'').includes(q)||(el.dataset.client||'').includes(q)||(el.dataset.emp||'').includes(q);
      el.style.display = hit ? '' : 'none';
    });
  });
}());

/* ── Upload panel open/close ─────────────────────────────── */
document.querySelectorAll('.pd-upload-toggle').forEach(function(btn){
  btn.addEventListener('click', function(){
    var p = document.getElementById(btn.dataset.target);
    if (p) p.hidden = !p.hidden;
  });
});
document.querySelectorAll('.pd-upload-cancel').forEach(function(btn){
  btn.addEventListener('click', function(){
    var p = document.getElementById(btn.dataset.target);
    if (p) p.hidden = true;
  });
});

/* ── Drop-zone / file picker ─────────────────────────────── */
document.querySelectorAll('.pd-drop-zone').forEach(function(dz){
  var input   = dz.querySelector('.pd-drop-input');
  var content = dz.querySelector('.pd-drop-content');
  var sel     = dz.querySelector('.pd-drop-selected');
  if (!input||!content||!sel) return;

  function showFile(f){
    var kb = f.size/1024;
    var sz = kb<1000 ? Math.round(kb)+'KB' : (f.size/1048576).toFixed(1)+'MB';
    content.hidden = true; sel.hidden = false;
    sel.innerHTML =
      '<svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" style="color:var(--cyan);flex-shrink:0"><path d="M16.707 5.293a1 1 0 00-1.414 0L8 12.586 4.707 9.293a1 1 0 00-1.414 1.414l4 4a1 1 0 001.414 0l8-8a1 1 0 000-1.414z"/></svg>'+
      '<span style="font-weight:600;color:var(--text-1)">'+f.name+'</span>'+
      '<span style="font-size:.78rem;color:var(--text-3)">'+sz+'</span>';
  }
  dz.addEventListener('dragover',  function(e){ e.preventDefault(); dz.classList.add('is-over'); });
  dz.addEventListener('dragleave', function(){ dz.classList.remove('is-over'); });
  dz.addEventListener('drop', function(e){
    e.preventDefault(); dz.classList.remove('is-over');
    if (!e.dataTransfer.files.length) return;
    try{ var dt=new DataTransfer(); dt.items.add(e.dataTransfer.files[0]); input.files=dt.files; }catch(x){}
    showFile(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', function(){ if(input.files&&input.files.length) showFile(input.files[0]); });
  dz.addEventListener('click', function(e){ if(e.target!==input&&!e.target.closest('button')) input.click(); });
});

/* ── Version navigator ───────────────────────────────────── */
(function(){
  var state = {};
  document.querySelectorAll('.pd-version-list').forEach(function(navEl){
    var id    = navEl.id.replace('nav-','');
    var cards = navEl.querySelectorAll('.pd-version-card');
    if (cards.length < 2) return;
    state[id] = { idx:0, total:cards.length, cards:cards };
  });
  function goTo(id, n2){
    var n = state[id]; if (!n) return;
    n.cards[n.idx].classList.remove('is-active');
    n.idx = n2;
    n.cards[n.idx].classList.add('is-active');
    var ctr = document.getElementById('nav-counter-'+id);
    if (ctr) ctr.textContent = (n.idx+1)+' / '+n.total;
    document.querySelectorAll('.pd-nav-prev[data-nav="'+id+'"]').forEach(function(b){ b.disabled=(n.idx===0); });
    document.querySelectorAll('.pd-nav-next[data-nav="'+id+'"]').forEach(function(b){ b.disabled=(n.idx===n.total-1); });
  }
  document.querySelectorAll('.pd-nav-prev').forEach(function(b){
    b.addEventListener('click',function(){ var n=state[b.dataset.nav]; if(n&&n.idx>0) goTo(b.dataset.nav,n.idx-1); });
  });
  document.querySelectorAll('.pd-nav-next').forEach(function(b){
    b.addEventListener('click',function(){ var n=state[b.dataset.nav]; if(n&&n.idx<n.total-1) goTo(b.dataset.nav,n.idx+1); });
  });
}());
</script>

<style>
/* ── Top bar ─────────────────────────────────────────────── */
.pd-topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:20px;flex-wrap:wrap}
.pd-topbar-left{display:flex;align-items:center;gap:10px;flex:1;min-width:0;flex-wrap:wrap}
.pd-search-box{display:flex;align-items:center;gap:8px;background:var(--surface-1);border:1px solid var(--surface-3);border-radius:10px;padding:0 12px;flex:1;min-width:180px;max-width:360px;transition:border-color .12s,box-shadow .12s}
.pd-search-box:focus-within{border-color:var(--cyan);box-shadow:0 0 0 3px var(--cyan-glow)}
.pd-search-icon{color:var(--text-3);flex-shrink:0}
.pd-search-box input{flex:1;background:none;border:none;outline:none;color:var(--text-1);font-size:.86rem;padding:9px 0;min-width:0}
.pd-search-box input::placeholder{color:var(--text-3)}
.pd-select-wrap{position:relative;display:flex;align-items:center}
.pd-sel-icon{position:absolute;left:10px;color:var(--text-3);pointer-events:none}
.pd-select{background:var(--surface-1);border:1px solid var(--surface-3);border-radius:10px;color:var(--text-1);font-size:.84rem;padding:8px 14px 8px 28px;outline:none;appearance:none;cursor:pointer;transition:border-color .12s}
.pd-select:focus{border-color:var(--cyan);box-shadow:0 0 0 3px var(--cyan-glow)}
.pd-clear-filter{margin-left:6px;display:flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:50%;background:var(--surface-3);color:var(--text-3);text-decoration:none;font-size:.78rem;transition:background .12s,color .12s}
.pd-clear-filter:hover{background:var(--rose-dim);color:var(--rose)}

/* ── Layout ──────────────────────────────────────────────── */
.pd-layout{display:grid;grid-template-columns:260px 1fr;gap:20px;align-items:start}

/* ── Sidebar ─────────────────────────────────────────────── */
.pd-sidebar{background:var(--surface-1);border:1px solid var(--surface-3);border-radius:14px;overflow:hidden;position:sticky;top:20px;max-height:calc(100vh - 140px);overflow-y:auto;scrollbar-width:thin}
.pd-list-empty{padding:32px 16px;text-align:center;color:var(--text-3);font-size:.84rem;display:flex;flex-direction:column;align-items:center;gap:10px;line-height:1.6}
.pd-filter-chip{display:flex;align-items:center;gap:5px;padding:6px 14px;font-size:.72rem;font-weight:600;color:var(--cyan);background:var(--cyan-glow);border-bottom:1px solid var(--surface-3)}
.pd-list-item{display:flex;align-items:center;gap:10px;padding:10px 14px;text-decoration:none;border-left:3px solid transparent;transition:background .12s,border-color .12s;cursor:pointer}
.pd-list-item:hover{background:var(--surface-2);border-left-color:var(--surface-3)}
.pd-list-item.is-active{background:rgba(34,211,238,.06);border-left-color:var(--cyan)}
.pd-list-avatar{width:34px;height:34px;flex-shrink:0;border-radius:8px;background:var(--surface-3);color:var(--cyan);display:flex;align-items:center;justify-content:center;font-size:.66rem;font-weight:800;letter-spacing:.03em;transition:background .12s,color .12s}
.pd-list-item.is-active .pd-list-avatar{background:var(--cyan);color:#000}
.pd-list-copy{flex:1;min-width:0}
.pd-list-name{font-size:.84rem;font-weight:600;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pd-list-meta{font-size:.72rem;color:var(--text-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
.pd-list-emp{display:inline-flex;align-items:center;gap:4px;margin-top:4px;font-size:.71rem;font-weight:600;color:var(--cyan);background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.18);border-radius:20px;padding:2px 7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.pd-list-item.is-active .pd-list-emp{background:rgba(34,211,238,.15);border-color:rgba(34,211,238,.35)}
.pd-list-chevron{color:var(--text-3);flex-shrink:0;opacity:0;transition:opacity .12s}
.pd-list-item.is-active .pd-list-chevron,.pd-list-item:hover .pd-list-chevron{opacity:1;color:var(--cyan)}

/* ── Main panel ──────────────────────────────────────────── */
.pd-main{min-width:0}

/* ── Project hero ────────────────────────────────────────── */
.pd-hero{display:flex;align-items:center;justify-content:space-between;gap:16px;background:var(--surface-1);border:1px solid var(--surface-3);border-radius:14px;padding:20px 24px;margin-bottom:16px;flex-wrap:wrap}
.pd-hero-left{display:flex;align-items:center;gap:14px;flex:1;min-width:0}
.pd-hero-avatar{width:52px;height:52px;flex-shrink:0;border-radius:13px;background:linear-gradient(135deg,var(--cyan),#0891b2);color:#000;display:flex;align-items:center;justify-content:center;font-size:.9rem;font-weight:900;font-family:var(--font-display);letter-spacing:-.5px}
.pd-hero-info{flex:1;min-width:0}
.pd-hero-title{font-size:1.2rem;font-weight:800;color:var(--text-1);margin:0 0 6px;font-family:var(--font-display);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pd-hero-meta{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.pd-hero-chip{display:inline-flex;align-items:center;gap:4px;font-size:.76rem;color:var(--text-3);background:var(--surface-2);border:1px solid var(--surface-3);border-radius:20px;padding:3px 9px;white-space:nowrap}
.pd-chip-green{color:var(--green) !important;background:var(--green-dim) !important;border-color:rgba(52,211,153,.2) !important}
.pd-hero-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.pd-stat-pill{display:flex;flex-direction:column;align-items:center;background:var(--surface-2);border:1px solid var(--surface-3);border-radius:10px;padding:8px 14px;min-width:60px;text-align:center}
.pd-stat-label{font-size:.66rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-3)}
.pd-stat-val{font-size:.8rem;font-weight:700;color:var(--text-1);margin-top:2px}
.pd-pill-ok{border-color:rgba(52,211,153,.25);background:rgba(52,211,153,.06)}.pd-pill-ok .pd-stat-val{color:var(--green)}
.pd-pill-warn{border-color:rgba(245,158,11,.25);background:rgba(245,158,11,.06)}.pd-pill-warn .pd-stat-val{color:var(--amber)}
.pd-pill-missing{border-color:rgba(239,68,68,.2);background:rgba(239,68,68,.05)}.pd-pill-missing .pd-stat-val{color:var(--rose)}
.pd-panel-header{display:flex;align-items:center;gap:14px;margin-bottom:20px}
.pd-panel-avatar{width:48px;height:48px;flex-shrink:0;border-radius:12px;background:var(--surface-3);color:var(--cyan);display:flex;align-items:center;justify-content:center;font-size:1.4rem;font-weight:300}
.pd-avatar-new{background:var(--cyan-glow);border:1px dashed var(--cyan);color:var(--cyan)}
.pd-panel-title{font-size:1.15rem;font-weight:800;color:var(--text-1);margin:0 0 2px}
.pd-panel-sub{font-size:.83rem;color:var(--text-3);margin:0}

/* ── Tabs ────────────────────────────────────────────────── */
.pd-tabs{display:flex;gap:2px;border-bottom:1px solid var(--surface-3);margin-bottom:18px}
.pd-tab{display:inline-flex;align-items:center;gap:6px;padding:9px 16px;font-size:.86rem;font-weight:600;color:var(--text-3);text-decoration:none;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .12s,border-color .12s;border-radius:8px 8px 0 0}
.pd-tab:hover{color:var(--text-1);background:var(--surface-2)}
.pd-tab.is-active{color:var(--cyan);border-bottom-color:var(--cyan);background:var(--surface-2)}
.pd-tab-badge{background:var(--cyan);color:#000;font-size:.64rem;font-weight:800;border-radius:20px;padding:1px 6px;line-height:1.7}

/* ── Details grid ────────────────────────────────────────── */
.pd-details-grid{display:grid;grid-template-columns:1fr 320px;gap:20px;align-items:start}
.pd-form-row{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}
.pd-form-actions{display:flex;align-items:center;gap:14px;padding-top:8px;flex-wrap:wrap}
.req{color:var(--rose)}

/* ── Summary table ───────────────────────────────────────── */
.pd-summary-table{width:100%;border-collapse:collapse;font-size:.86rem}
.pd-summary-table td{padding:10px 20px;border-bottom:1px solid var(--surface-3);vertical-align:middle}
.pd-summary-table tr:last-child td{border-bottom:none}
.pd-summary-table td:first-child{color:var(--text-3);font-size:.79rem;text-transform:uppercase;letter-spacing:.04em;width:120px;font-weight:600}

/* ── Compliance rows ─────────────────────────────────────── */
.pd-compliance-row{display:flex;align-items:center;gap:10px}
.pd-compliance-icon{width:36px;height:36px;flex-shrink:0;border-radius:8px;background:var(--cyan-glow);border:1px solid var(--cyan);color:var(--cyan);display:flex;align-items:center;justify-content:center;font-size:.66rem;font-weight:800;letter-spacing:.04em}
.pd-compliance-info{flex:1;min-width:0}
.pd-compliance-label{font-size:.84rem;font-weight:600;color:var(--text-1)}
.pd-compliance-meta{font-size:.72rem;color:var(--text-3);margin-top:1px}
.pd-doc-status{font-size:.72rem;font-weight:700;border-radius:20px;padding:3px 10px;white-space:nowrap}
.doc-status-ok{background:rgba(52,211,153,.12);color:var(--green);border:1px solid rgba(52,211,153,.2)}
.doc-status-pending{background:rgba(251,191,36,.1);color:var(--amber);border:1px solid rgba(251,191,36,.2)}
.doc-status-reject{background:rgba(239,68,68,.1);color:var(--rose);border:1px solid rgba(239,68,68,.18)}
.doc-status-missing{background:var(--surface-3);color:var(--text-3);border:1px solid var(--surface-3)}

/* ── Documents tab ───────────────────────────────────────── */
.pd-doc-page{display:flex;flex-direction:column;gap:16px}
.pd-doc-section{border:1px solid var(--surface-3);border-radius:14px;background:var(--surface-1);overflow:hidden}
.pd-doc-section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 20px;border-bottom:1px solid var(--surface-3);flex-wrap:wrap}
.pd-doc-section-left{display:flex;align-items:center;gap:12px;flex:1;min-width:0}
.pd-dtype-badge{width:40px;height:40px;flex-shrink:0;border-radius:10px;background:var(--cyan-glow);border:1px solid var(--cyan);color:var(--cyan);display:flex;align-items:center;justify-content:center;font-size:.68rem;font-weight:800;letter-spacing:.04em}
.pd-doc-section-title{font-weight:700;color:var(--text-1);margin-bottom:2px;font-size:.9rem}
.pd-doc-section-sub{font-size:.77rem;color:var(--text-3)}
.pd-upload-panel{padding:16px 20px;border-bottom:1px solid var(--surface-3);background:var(--surface-2)}
.pd-drop-zone{border:2px dashed var(--surface-3);border-radius:10px;padding:22px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:border-color .12s,background .12s;position:relative;min-height:90px}
.pd-drop-zone:hover,.pd-drop-zone.is-over{border-color:var(--cyan);background:var(--cyan-glow)}
.pd-drop-input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%;font-size:0}
.pd-drop-content{display:flex;flex-direction:column;align-items:center;gap:5px;pointer-events:none;color:var(--text-3)}
.pd-drop-label{font-size:.88rem;color:var(--text-2)}.pd-drop-label strong{color:var(--cyan)}
.pd-drop-hint{font-size:.74rem}
.pd-drop-selected{display:flex;align-items:center;gap:8px;pointer-events:none;flex-wrap:wrap}
.pd-upload-actions{display:flex;gap:10px;margin-top:12px}
.pd-no-doc{padding:22px 20px;display:flex;align-items:center;gap:12px;color:var(--text-3);font-size:.84rem}

/* ── Version cards ───────────────────────────────────────── */
.pd-version-list{padding:16px 20px;display:flex;flex-direction:column;gap:0}
.pd-version-card{display:none;align-items:center;justify-content:space-between;gap:14px;padding:14px;background:var(--surface-2);border:1px solid var(--surface-3);border-radius:10px;flex-wrap:wrap}
.pd-version-card.is-active{display:flex;animation:vcFadeIn .18s ease}
.pd-version-card.vc-approved{border-color:rgba(52,211,153,.22);background:rgba(52,211,153,.04)}
.pd-version-card.vc-rejected{border-color:rgba(239,68,68,.18);background:rgba(239,68,68,.03)}
@keyframes vcFadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.pd-vc-left{display:flex;align-items:center;gap:12px;flex:1;min-width:0}
.pd-vc-ext{width:42px;height:42px;flex-shrink:0;border-radius:9px;background:var(--surface-3);border:1px solid var(--surface-3);display:flex;align-items:center;justify-content:center;font-size:.62rem;font-weight:800;color:var(--text-2);letter-spacing:.03em}
.vc-pdf{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.2);color:#ef4444}
.vc-docx{background:rgba(59,130,246,.1);border-color:rgba(59,130,246,.2);color:#3b82f6}
.pd-vc-name{font-size:.87rem;font-weight:600;color:var(--text-1);display:flex;align-items:center;gap:7px;flex-wrap:wrap;word-break:break-word}
.pd-current-chip{background:var(--cyan);color:#000;font-size:.62rem;font-weight:700;border-radius:20px;padding:2px 7px;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
.pd-vc-meta{font-size:.74rem;color:var(--text-3);margin-top:3px}
.pd-vc-desc{font-size:.78rem;color:var(--text-2);margin-top:5px;padding:5px 9px;background:var(--surface-1);border-radius:6px;border-left:2px solid var(--cyan)}
.pd-vc-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.pd-vc-btns{display:flex;align-items:center;gap:6px}
.pd-nav-bar{display:flex;align-items:center;justify-content:center;gap:12px;padding-top:12px;margin-top:12px;border-top:1px solid var(--surface-3)}
.pd-nav-btn{width:30px;height:30px;border-radius:8px;border:1px solid var(--surface-3);background:var(--surface-1);color:var(--text-2);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .12s,border-color .12s,color .12s}
.pd-nav-btn:hover:not(:disabled){background:var(--cyan-glow);border-color:var(--cyan);color:var(--cyan)}
.pd-nav-btn:disabled{opacity:.3;cursor:not-allowed}
.pd-nav-count{font-size:.8rem;color:var(--text-3);min-width:44px;text-align:center;font-variant-numeric:tabular-nums}

/* ── Empty state ─────────────────────────────────────────── */
.pd-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:380px;gap:12px;text-align:center;color:var(--text-3);padding:40px 20px}
.pd-empty-icon{width:80px;height:80px;border-radius:20px;background:var(--surface-2);border:1px solid var(--surface-3);display:flex;align-items:center;justify-content:center;margin-bottom:4px}
.pd-empty h3{font-size:1.1rem;font-weight:700;color:var(--text-1);margin:0}
.pd-empty p{font-size:.86rem;margin:0;line-height:1.7}

/* ── Responsive ──────────────────────────────────────────── */
@media(max-width:1100px){.pd-details-grid{grid-template-columns:1fr}}
@media(max-width:900px){
  .pd-layout{grid-template-columns:1fr}
  .pd-sidebar{position:static;max-height:220px;border-radius:14px}
  .pd-form-row{grid-template-columns:1fr}
  .pd-hero{padding:14px 16px}
}
@media(max-width:600px){
  .pd-topbar{flex-direction:column;align-items:stretch}
  .pd-topbar-left{flex-direction:column;align-items:stretch}
  .pd-search-box{max-width:100%}
  .pd-hero-actions{display:none}
}
</style>
</body>
</html>