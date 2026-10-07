<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

$ALLOWED_DOC_TYPES = ['MSA', 'PROJECT'];
$docLabels = [
    'MSA'     => 'MSA',
    'PROJECT' => 'Project Document',
];

$msg = '';
$msgType = '';

$employeeListStmt = $db->query(
    "SELECT id, full_name
     FROM users
     WHERE role = 'employee' AND status = 'active'
     ORDER BY full_name ASC"
);
$employeeList = $employeeListStmt->fetchAll();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true);

    $action            = validateEnum($_POST['action'] ?? '', ['upload_document']);
    $employeeId        = sanitizeInt($_POST['employee_id'] ?? 0, 1);
    $documentType      = validateEnum($_POST['document_type'] ?? '', $ALLOWED_DOC_TYPES);
    $description       = sanitizeString($_POST['description'] ?? '', 1000);
    $replaceDocumentId = sanitizeInt($_POST['replace_document_id'] ?? 0, 1);

    if ($action !== 'upload_document') {
        $msg = 'Invalid request.';
        $msgType = 'error';
    } elseif (!$employeeId || !$documentType) {
        $msg = 'Please select an employee and document type.';
        $msgType = 'error';
    } elseif (empty($_FILES['document_file']) || ($_FILES['document_file']['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        $msg = 'Please choose a file to upload.';
        $msgType = 'error';
    } else {
        $result = handleEmployeeProjectDocumentUpload(
            $_FILES['document_file'],
            $employeeId,
            $documentType,
            (int)$user['id'],
            $description !== '' ? $description : null,
            $replaceDocumentId ?: null,
            'pending'
        );

        if ($result['success']) {
            auditLog($replaceDocumentId ? 'employee_project_document_replaced' : 'employee_project_document_uploaded', 'employee_documents', $result['id'] ?? null, [
                'employee_id' => $employeeId,
                'document_type' => $documentType,
                'version_no' => $result['version_no'] ?? 1,
                'replaced_document_id' => $replaceDocumentId ?: null,
            ]);
            $msg = $result['message'] . ' Employee: ' . (string)($result['employee_name'] ?? '');
            $msgType = 'success';
        } else {
            $msg = $result['message'];
            $msgType = 'error';
        }
    }
}

$filterEmployeeId = sanitizeInt($_GET['employee_id'] ?? 0, 1);
$filterDocType    = validateEnum($_GET['document_type'] ?? '', array_merge($ALLOWED_DOC_TYPES, [''])) ?? '';
$search           = sanitizeString($_GET['search'] ?? '', 100);
$showHistory      = (($_GET['history'] ?? '') === '1');
$replaceFocusId   = sanitizeInt($_GET['replace_id'] ?? 0, 1);

$replaceFocus = null;
if ($replaceFocusId) {
    $replaceStmt = $db->prepare(
        "SELECT d.id, d.employee_id, d.document_type, d.file_name, d.version_no, u.full_name
         FROM employee_documents d
         JOIN users u ON u.id = d.employee_id
         WHERE d.id = ? AND d.is_current = 1
         LIMIT 1"
    );
    $replaceStmt->execute([$replaceFocusId]);
    $replaceFocus = $replaceStmt->fetch();
}

$where = [];
$params = [];

if (!$showHistory) {
    $where[] = 'd.is_current = 1';
}
if ($filterEmployeeId) {
    $where[] = 'd.employee_id = ?';
    $params[] = $filterEmployeeId;
}
if ($filterDocType) {
    $where[] = 'd.document_type = ?';
    $params[] = $filterDocType;
}
if ($search !== '') {
    $where[] = "(u.full_name LIKE ? OR d.file_name LIKE ? OR COALESCE(d.description, '') LIKE ?)";
    $params[] = '%' . $search . '%';
    $params[] = '%' . $search . '%';
    $params[] = '%' . $search . '%';
}

$sql = "
    SELECT d.*, u.full_name AS employee_name, up.full_name AS uploaded_by_name
    FROM employee_documents d
    JOIN users u ON u.id = d.employee_id
    JOIN users up ON up.id = d.uploaded_by
";
if ($where) {
    $sql .= ' WHERE ' . implode(' AND ', $where);
}
$sql .= ' ORDER BY u.full_name ASC, d.document_type ASC, d.version_no DESC, d.uploaded_at DESC LIMIT 200';

$docsStmt = $db->prepare($sql);
$docsStmt->execute($params);
$documents = $docsStmt->fetchAll();

pageHead('Employee Project Documents');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'project_documents'); ?>
  <div class="main-content">
    <?php renderTopbar('Employee Project Documents', $user); ?>
    <div class="page-body">
      <div class="page-header">
        <div>
          <h1>Employee Project Documents</h1>
          <p>HR Admin and Super Admin only. Employees cannot view, download, or access these files.</p>
        </div>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <div class="card" style="margin-bottom:24px;border:1px solid rgba(31,160,192,.25);">
        <div class="card-header">
          <h3><?= $replaceFocus ? 'Replace Document' : 'Upload Employee Document' ?></h3>
        </div>
        <div class="card-body">
          <?php if ($replaceFocus): ?>
            <div class="alert alert-info" style="margin-bottom:16px;">
              Replacing <?= e($replaceFocus['file_name']) ?> for <?= e($replaceFocus['full_name']) ?>.
              New upload will become version <?= (int)$replaceFocus['version_no'] + 1 ?>.
            </div>
          <?php endif; ?>

          <form method="POST" enctype="multipart/form-data" id="employee-project-doc-form">
            <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
            <input type="hidden" name="action" value="upload_document">
            <input type="hidden" name="replace_document_id" value="<?= (int)($replaceFocus['id'] ?? 0) ?>">

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;">
              <div class="form-group">
                <label>Employee <span style="color:#e05c5c;">*</span></label>
                <select name="employee_id" class="form-control" required>
                  <option value="">Select employee</option>
                  <?php foreach ($employeeList as $employee): ?>
                    <?php $selectedEmployee = (int)($replaceFocus['employee_id'] ?? ($_POST['employee_id'] ?? 0)) === (int)$employee['id']; ?>
                    <option value="<?= (int)$employee['id'] ?>" <?= $selectedEmployee ? 'selected' : '' ?>>
                      <?= e($employee['full_name']) ?>
                    </option>
                  <?php endforeach; ?>
                </select>
              </div>

              <div class="form-group">
                <label>Document Type <span style="color:#e05c5c;">*</span></label>
                <select name="document_type" class="form-control" required>
                  <option value="">Select type</option>
                  <?php foreach ($docLabels as $type => $label): ?>
                    <?php $selectedType = (($replaceFocus['document_type'] ?? ($_POST['document_type'] ?? '')) === $type); ?>
                    <option value="<?= e($type) ?>" <?= $selectedType ? 'selected' : '' ?>><?= e($label) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>

              <div class="form-group" style="grid-column:1/-1;">
                <label>File <span style="color:#e05c5c;">*</span></label>
                <input type="file" name="document_file" class="form-control" required accept=".pdf,.docx,.xlsx,.jpg,.jpeg,.png,.gif,.webp">
                <div style="font-size:.78rem;color:var(--gray-400);margin-top:6px;">Allowed: PDF, DOCX, XLSX, JPG, PNG, GIF, WEBP. Max 10MB.</div>
              </div>

              <div class="form-group" style="grid-column:1/-1;">
                <label>Description / Notes</label>
                <textarea name="description" class="form-control" rows="3" maxlength="1000" placeholder="Optional notes for HR/Admin only"><?= e($_POST['description'] ?? '') ?></textarea>
              </div>
            </div>

            <div style="display:flex;gap:10px;flex-wrap:wrap;">
              <button type="submit" class="btn btn-primary"><?= $replaceFocus ? 'Replace Document' : 'Upload Document' ?></button>
              <?php if ($replaceFocus): ?>
                <a href="/admin/employee_project_documents.php" class="btn btn-outline">Cancel Replace</a>
              <?php endif; ?>
            </div>
          </form>
        </div>
      </div>

      <div class="card" style="margin-bottom:20px;">
        <div class="card-body" style="padding:16px 24px;">
          <form method="GET" style="display:flex;gap:12px;flex-wrap:wrap;align-items:end;">
            <div class="form-group" style="margin:0;min-width:220px;">
              <label>Search</label>
              <input type="text" name="search" class="form-control" maxlength="100" value="<?= e($search) ?>" placeholder="Employee, file name, notes">
            </div>
            <div class="form-group" style="margin:0;min-width:220px;">
              <label>Employee</label>
              <select name="employee_id" class="form-control">
                <option value="">All employees</option>
                <?php foreach ($employeeList as $employee): ?>
                  <option value="<?= (int)$employee['id'] ?>" <?= $filterEmployeeId === (int)$employee['id'] ? 'selected' : '' ?>>
                    <?= e($employee['full_name']) ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="form-group" style="margin:0;min-width:180px;">
              <label>Document Type</label>
              <select name="document_type" class="form-control">
                <option value="">All types</option>
                <?php foreach ($docLabels as $type => $label): ?>
                  <option value="<?= e($type) ?>" <?= $filterDocType === $type ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="form-group" style="margin:0;min-width:160px;">
              <label>History</label>
              <select name="history" class="form-control">
                <option value="0" <?= !$showHistory ? 'selected' : '' ?>>Current only</option>
                <option value="1" <?= $showHistory ? 'selected' : '' ?>>All versions</option>
              </select>
            </div>
            <button type="submit" class="btn btn-primary">Filter</button>
            <a href="/admin/employee_project_documents.php" class="btn btn-outline">Reset</a>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3>Document Library</h3>
          <span style="font-size:.82rem;color:var(--gray-400);"><?= count($documents) ?> document(s)</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Employee Name</th>
                <th>Document Type</th>
                <th>File Name</th>
                <th>Uploaded Date</th>
                <th>Version</th>
                <th>Notes</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php if (!$documents): ?>
                <tr>
                  <td colspan="7" style="text-align:center;padding:32px;color:var(--gray-400);">No employee project documents found.</td>
                </tr>
              <?php endif; ?>
              <?php foreach ($documents as $doc): ?>
                <?php
                $viewUrl = getEmployeeProjectDocumentServeUrl((int)$doc['id'], (int)$user['id'], false);
                $downloadUrl = getEmployeeProjectDocumentServeUrl((int)$doc['id'], (int)$user['id'], true);
                ?>
                <tr>
                  <td style="font-weight:600;"><?= e($doc['employee_name']) ?></td>
                  <td>
                    <span class="badge badge-info"><?= e($docLabels[$doc['document_type']] ?? $doc['document_type']) ?></span>
                    <?php if (!(int)$doc['is_current']): ?>
                      <div style="font-size:.72rem;color:var(--amber);margin-top:4px;">Archived version</div>
                    <?php endif; ?>
                  </td>
                  <td>
                    <div style="font-weight:600;"><?= e($doc['file_name']) ?></div>
                    <div style="font-size:.78rem;color:var(--gray-400);"><?= e((string)round(((int)$doc['file_size']) / 1024)) ?> KB</div>
                  </td>
                  <td>
                    <div><?= e(date('M j, Y', strtotime($doc['uploaded_at']))) ?></div>
                    <div style="font-size:.78rem;color:var(--gray-400);"><?= e(date('g:i a', strtotime($doc['uploaded_at']))) ?></div>
                  </td>
                  <td>v<?= (int)$doc['version_no'] ?></td>
                  <td style="max-width:240px;color:var(--gray-500);"><?= e($doc['description'] ?? '—') ?></td>
                  <td>
                    <div style="display:flex;gap:8px;flex-wrap:wrap;">
                      <a href="<?= e($viewUrl) ?>" target="_blank" class="btn btn-outline btn-sm" data-project-doc-action="view">View</a>
                      <a href="<?= e($downloadUrl) ?>" class="btn btn-outline btn-sm" data-project-doc-action="download">Download</a>
                      <?php if ((int)$doc['is_current']): ?>
                        <a href="/admin/employee_project_documents.php?replace_id=<?= (int)$doc['id'] ?>" class="btn btn-primary btn-sm">Replace</a>
                      <?php endif; ?>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
document.querySelectorAll('[data-project-doc-action]').forEach(function(link) {
  link.addEventListener('click', function() {
    var label = link.dataset.projectDocAction === 'download' ? 'Preparing secure download...' : 'Opening secure document...';
    link.dataset.originalText = link.textContent;
    link.textContent = label;
    window.setTimeout(function() {
      link.textContent = link.dataset.originalText || 'View';
    }, 3000);
  });
});

var uploadForm = document.getElementById('employee-project-doc-form');
if (uploadForm) {
  uploadForm.addEventListener('submit', function() {
    var button = uploadForm.querySelector('button[type="submit"]');
    if (button) {
      button.disabled = true;
      button.textContent = 'Uploading...';
    }
  });
}
</script>
<?php pageFooter(); ?>
</body>
</html>
