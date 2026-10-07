<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
guardRequestSize(defined('MAX_POST_BYTES') ? MAX_POST_BYTES : 5242880);
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
startSecureSession();
$user   = requireAnyRole();
$userId = (int)$user['id'];
$db     = getDB();

// Category management + upload is HR & Super Admin only. Re-checked
// server-side below — never trust the frontend hiding the forms.
$canManage = in_array($user['role'], ['hr_admin', 'super_admin'], true);

$msg = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken(true);
    $action = sanitizeString($_POST['action'] ?? 'upload', 30);

    if (!$canManage) {
        auditLog('h1b_document_action_denied', 'h1b_documents', null, ['role' => $user['role'], 'action' => $action]);
        http_response_code(403);
        $msg = 'You do not have permission to do that.';
        $msgType = 'error';
    } elseif ($action === 'create_category') {
        $result = createDocumentCategory($_POST['category_name'] ?? '', $userId);
        $msg = $result['message'];
        $msgType = $result['success'] ? 'success' : 'error';
        if ($result['success']) {
            auditLog('document_category_created', 'document_categories', $result['id'] ?? null, ['name' => $_POST['category_name'] ?? '']);
        }
    } elseif ($action === 'rename_category') {
        $categoryId = sanitizeInt($_POST['category_id'] ?? null, 1);
        if (!$categoryId) {
            $msg = 'Invalid category.';
            $msgType = 'error';
        } else {
            $result = renameDocumentCategory($categoryId, $_POST['category_name'] ?? '');
            $msg = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
            if ($result['success']) {
                auditLog('document_category_renamed', 'document_categories', $categoryId, ['name' => $_POST['category_name'] ?? '']);
            }
        }
    } elseif ($action === 'delete_category') {
        $categoryId = sanitizeInt($_POST['category_id'] ?? null, 1);
        if (!$categoryId) {
            $msg = 'Invalid category.';
            $msgType = 'error';
        } else {
            $result = deleteDocumentCategoryIfEmpty($categoryId);
            $msg = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
            if ($result['success']) {
                auditLog('document_category_deleted', 'document_categories', $categoryId, []);
            }
        }
    } else {
        $documentName = sanitizeString($_POST['document_name'] ?? '', 180);
        $categoryId   = sanitizeInt($_POST['category_id'] ?? null, 1);

        if ($documentName === '') {
            $msg = 'Please provide a document name.';
            $msgType = 'error';
        } elseif (!$categoryId) {
            $msg = 'Please select a category.';
            $msgType = 'error';
        } elseif (empty($_FILES['document_file']) || ($_FILES['document_file']['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
            $msg = 'Please choose a file to upload.';
            $msgType = 'error';
        } else {
            $result = handleH1bDocumentUpload($_FILES['document_file'], $documentName, $userId, $categoryId);

            if ($result['success']) {
                auditLog('h1b_document_uploaded', 'h1b_documents', $result['id'] ?? null, [
                    'document_name' => $documentName,
                    'category_id'   => $categoryId,
                ]);
                $msg = $result['message'];
                $msgType = 'success';
            } else {
                $msg = $result['message'];
                $msgType = 'error';
            }
        }
    }
}

$categories = getDocumentCategoriesWithCounts();

$docsStmt = $db->query(
    "SELECT d.*, u.full_name AS uploaded_by_name, u.role AS uploaded_by_role
     FROM h1b_documents d
     JOIN users u ON u.id = d.uploaded_by
     ORDER BY d.uploaded_at DESC"
);
$documentsByCategory = [];
foreach ($docsStmt->fetchAll() as $doc) {
    $documentsByCategory[(int)$doc['category_id']][] = $doc;
}

pageHead('Document Library');
?>
<body>
<div class="app-shell">
  <?php renderSidebar(['id' => $user['id'], 'name' => $user['name'], 'role' => $user['role']], 'h1b_documents'); ?>
  <div class="main-content">
    <?php renderTopbar('Document Library', $user); ?>
    <div class="page-body">
      <div class="page-header">
        <div>
          <h1>Document Library</h1>
          <p><?= $canManage ? 'Create categories and upload shared documents (DOCX, PDF, images) for all employees.' : 'View and download documents shared by HR/Admin.' ?></p>
        </div>
      </div>

      <?php if ($msg): ?>
        <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>"><?= e($msg) ?></div>
      <?php endif; ?>

      <?php if ($canManage): ?>
      <div class="card" style="margin-bottom:24px;border:1px solid rgba(31,160,192,.25);">
        <div class="card-header">
          <h3>New Category</h3>
        </div>
        <div class="card-body">
          <form method="POST" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">
            <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
            <input type="hidden" name="action" value="create_category">
            <div class="form-group" style="flex:1;min-width:220px;margin-bottom:0;">
              <label>Category Name</label>
              <input type="text" name="category_name" class="form-control" maxlength="100" required placeholder="e.g. Passport, PERM, Tax Documents">
            </div>
            <button type="submit" class="btn btn-primary">Add Category</button>
          </form>
        </div>
      </div>

      <div class="card" style="margin-bottom:24px;border:1px solid rgba(31,160,192,.25);">
        <div class="card-header">
          <h3>Upload Document</h3>
        </div>
        <div class="card-body">
          <?php if (!$categories): ?>
            <p style="color:var(--gray-400);">Create a category above before uploading a document.</p>
          <?php else: ?>
          <form method="POST" enctype="multipart/form-data" id="h1b-doc-form">
            <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
            <input type="hidden" name="action" value="upload">

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;">
              <div class="form-group">
                <label>Category <span style="color:#e05c5c;">*</span></label>
                <select name="category_id" class="form-control" required>
                  <option value="">Select a category</option>
                  <?php foreach ($categories as $cat): ?>
                    <option value="<?= (int)$cat['id'] ?>"><?= e($cat['name']) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>

              <div class="form-group">
                <label>Document Name <span style="color:#e05c5c;">*</span></label>
                <input type="text" name="document_name" class="form-control" maxlength="180" required value="<?= e($_POST['document_name'] ?? '') ?>" placeholder="e.g. H1B Cap Filing Instructions">
              </div>

              <div class="form-group">
                <label>File (DOCX, PDF, JPG, PNG, WEBP) <span style="color:#e05c5c;">*</span></label>
                <input type="file" name="document_file" class="form-control" required accept=".docx,.pdf,.jpg,.jpeg,.png,.webp">
                <div style="font-size:.78rem;color:var(--gray-400);margin-top:6px;">Allowed: DOCX, PDF, JPG, PNG, WEBP.</div>
              </div>
            </div>

            <div style="display:flex;gap:10px;flex-wrap:wrap;">
              <button type="submit" class="btn btn-primary">Upload Document</button>
            </div>
          </form>
          <?php endif; ?>
        </div>
      </div>
      <?php endif; ?>

      <?php if (!$categories): ?>
        <div class="card">
          <div class="card-body">
            <p style="text-align:center;padding:32px;color:var(--gray-400);">No document categories yet.</p>
          </div>
        </div>
      <?php endif; ?>

      <?php foreach ($categories as $cat):
        $catId   = (int)$cat['id'];
        $catDocs = $documentsByCategory[$catId] ?? [];
        $count   = (int)$cat['document_count'];
      ?>
      <div class="card" style="margin-bottom:18px;">
        <div class="card-header" style="cursor:pointer;user-select:none;" data-cat-toggle="cat-<?= $catId ?>">
          <h3><span class="cat-arrow" id="arrow-cat-<?= $catId ?>" style="display:inline-block;margin-right:8px;transition:transform .2s;">&#9654;</span><?= e($cat['name']) ?> (<?= $count ?> Document<?= $count === 1 ? '' : 's' ?>)</h3>
          <?php if ($canManage): ?>
          <div style="display:flex;gap:8px;flex-wrap:wrap;" onclick="event.stopPropagation();">
            <button type="button" class="btn btn-outline btn-sm" data-rename-toggle="cat-<?= $catId ?>">Rename</button>
            <?php if ($count === 0): ?>
            <form method="POST" onsubmit="return confirm('Delete the empty category &quot;<?= e(addslashes($cat['name'])) ?>&quot;?');" style="display:inline;">
              <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
              <input type="hidden" name="action" value="delete_category">
              <input type="hidden" name="category_id" value="<?= $catId ?>">
              <button type="submit" class="btn btn-outline btn-sm" style="color:#e05c5c;border-color:#e05c5c;">Delete</button>
            </form>
            <?php endif; ?>
          </div>
          <?php endif; ?>
        </div>

        <?php if ($canManage): ?>
        <div class="card-body" id="rename-cat-<?= $catId ?>" style="display:none;border-bottom:1px solid rgba(255,255,255,.08);">
          <form method="POST" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">
            <input type="hidden" name="csrf_token" value="<?= e(generateCsrfToken()) ?>">
            <input type="hidden" name="action" value="rename_category">
            <input type="hidden" name="category_id" value="<?= $catId ?>">
            <div class="form-group" style="flex:1;min-width:220px;margin-bottom:0;">
              <label>New Name</label>
              <input type="text" name="category_name" class="form-control" maxlength="100" required value="<?= e($cat['name']) ?>">
            </div>
            <button type="submit" class="btn btn-primary btn-sm">Save</button>
          </form>
        </div>
        <?php endif; ?>

        <div class="table-wrap" id="cat-<?= $catId ?>" style="display:none;">
          <table>
            <thead>
              <tr>
                <th>Document Name</th>
                <th>Uploaded Date</th>
                <th>Uploaded By</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php if (!$catDocs): ?>
                <tr>
                  <td colspan="4" style="text-align:center;padding:32px;color:var(--gray-400);">No documents in this category yet.</td>
                </tr>
              <?php endif; ?>
              <?php foreach ($catDocs as $doc): ?>
                <?php
                $viewUrl = getH1bDocumentServeUrl((int)$doc['id'], $userId, false);
                $downloadUrl = getH1bDocumentServeUrl((int)$doc['id'], $userId, true);
                ?>
                <tr>
                  <td style="font-weight:600;"><?= e($doc['document_name']) ?></td>
                  <td>
                    <div><?= e(date('M j, Y', strtotime($doc['uploaded_at']))) ?></div>
                    <div style="font-size:.78rem;color:var(--gray-400);"><?= e(date('g:i a', strtotime($doc['uploaded_at']))) ?></div>
                  </td>
                  <td><?= in_array($doc['uploaded_by_role'], ['hr_admin', 'super_admin'], true) ? 'HR' : e($doc['uploaded_by_name']) ?></td>
                  <td>
                    <div style="display:flex;gap:8px;flex-wrap:wrap;">
                      <a href="<?= e($viewUrl) ?>" target="_blank" class="btn btn-outline btn-sm" data-h1b-doc-action="view" data-mime="<?= e($doc['mime_type']) ?>">View</a>
                      <a href="<?= e($downloadUrl) ?>" class="btn btn-outline btn-sm" data-h1b-doc-action="download">Download</a>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
</div>

<div class="modal-overlay hidden" id="doc-view-overlay">
  <div class="modal" style="max-width:920px;width:95vw;">
    <div class="modal-header">
      <h3 id="doc-view-title">Document</h3>
      <button type="button" class="btn btn-outline btn-sm" id="doc-view-close">Close</button>
    </div>
    <div id="doc-view-viewport">
      <div id="doc-view-body">
        <p>Loading document...</p>
      </div>
    </div>
    <div class="modal-footer">
      <a href="#" id="doc-view-download" class="btn btn-primary btn-sm">Download</a>
    </div>
  </div>
</div>

<style>
#doc-view-viewport { max-height: 72vh; overflow-y: auto; padding: 28px; background: #525659; }
#doc-view-body { background: #fff; color: #1a1a1a; max-width: 800px; margin: 0 auto; padding: 56px 64px; min-height: 400px; box-shadow: 0 2px 12px rgba(0,0,0,.4); font-family: Georgia, 'Times New Roman', serif; line-height: 1.55; }
#doc-view-body table { border-collapse: collapse; width: 100%; margin-bottom: 12px; }
#doc-view-body table td, #doc-view-body table th { border: 1px solid #c9c9c9; padding: 6px 10px; }
#doc-view-body tbody tr:hover, #doc-view-body tbody tr:hover td { background: transparent; color: inherit; }
#doc-view-body p { margin-bottom: 10px; }
#doc-view-body h1, #doc-view-body h2, #doc-view-body h3 { font-family: Georgia, 'Times New Roman', serif; margin: 18px 0 10px; }
#doc-view-body img { max-width: 100%; }
@media (max-width: 640px) {
  #doc-view-viewport { padding: 12px; }
  #doc-view-body { padding: 24px; }
}
</style>
<script src="/assets/js/vendor/mammoth.browser.min.js"></script>
<script>
document.querySelectorAll('[data-cat-toggle]').forEach(function(header) {
  header.addEventListener('click', function() {
    var id = header.getAttribute('data-cat-toggle');
    var body = document.getElementById(id);
    var arrow = document.getElementById('arrow-' + id);
    var open = body.style.display === 'block';
    body.style.display = open ? 'none' : 'block';
    if (arrow) arrow.style.transform = open ? 'rotate(0deg)' : 'rotate(90deg)';
  });
});

document.querySelectorAll('[data-rename-toggle]').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var id = btn.getAttribute('data-rename-toggle');
    var box = document.getElementById('rename-' + id);
    if (box) box.style.display = box.style.display === 'block' ? 'none' : 'block';
  });
});

var docViewOverlay  = document.getElementById('doc-view-overlay');
var docViewTitle    = document.getElementById('doc-view-title');
var docViewBody     = document.getElementById('doc-view-body');
var docViewDownload = document.getElementById('doc-view-download');

function closeDocView() {
  docViewOverlay.classList.add('hidden');
  docViewBody.innerHTML = '<p>Loading document...</p>';
}
document.getElementById('doc-view-close').addEventListener('click', closeDocView);
docViewOverlay.addEventListener('click', function(e) {
  if (e.target === docViewOverlay) closeDocView();
});
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape' && !docViewOverlay.classList.contains('hidden')) closeDocView();
});

document.querySelectorAll('[data-h1b-doc-action="download"]').forEach(function(link) {
  link.addEventListener('click', function() {
    link.dataset.originalText = link.textContent;
    link.textContent = 'Preparing secure download...';
    window.setTimeout(function() {
      link.textContent = link.dataset.originalText || 'Download';
    }, 3000);
  });
});

var DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

// mammoth.js converts the uploaded .docx straight to HTML, including any
// hyperlinks the document author embedded (e.g. javascript:/data: URLs).
// Only hr_admin/super_admin can upload here, but every employee views this
// library, so a single malicious or compromised admin upload shouldn't be
// able to run script in every viewer's session — strip anything but plain
// markup and safe link/image targets before it ever touches innerHTML.
function sanitizeMammothHtml(html) {
  var doc = new DOMParser().parseFromString(html || '', 'text/html');
  ['script', 'style', 'iframe', 'object', 'embed', 'link', 'meta', 'form', 'base'].forEach(function(tag) {
    doc.querySelectorAll(tag).forEach(function(el) { el.remove(); });
  });
  doc.querySelectorAll('*').forEach(function(el) {
    Array.prototype.slice.call(el.attributes).forEach(function(attr) {
      var name = attr.name.toLowerCase();
      if (name.indexOf('on') === 0) { el.removeAttribute(attr.name); return; }
      if (name === 'href' || name === 'src') {
        var val = (attr.value || '').trim().toLowerCase();
        var isSafe = val === '' || /^(https?:|mailto:|#|\/|data:image\/)/.test(val);
        if (!isSafe) el.removeAttribute(attr.name);
      }
    });
  });
  return doc.body.innerHTML;
}

document.querySelectorAll('[data-h1b-doc-action="view"]').forEach(function(link) {
  if (link.dataset.mime !== DOCX_MIME) {
    // PDF and images: browsers render these natively inline (the server
    // already sends Content-Disposition: inline with the real mime type),
    // so just let the link open normally in a new tab.
    return;
  }
  link.addEventListener('click', function(e) {
    e.preventDefault();
    var url = link.getAttribute('href');
    var docName = link.closest('tr').querySelector('td').textContent.trim();

    docViewTitle.textContent = docName;
    docViewDownload.href = link.closest('td').querySelector('[data-h1b-doc-action="download"]').getAttribute('href');
    docViewBody.innerHTML = '<p>Loading document...</p>';
    docViewOverlay.classList.remove('hidden');

    fetch(url, { credentials: 'same-origin' })
      .then(function(res) {
        if (!res.ok) throw new Error('Failed to load document.');
        return res.arrayBuffer();
      })
      .then(function(buffer) {
        return window.mammoth.convertToHtml({ arrayBuffer: buffer });
      })
      .then(function(result) {
        docViewBody.innerHTML = sanitizeMammothHtml(result.value) || '<p>This document has no readable content.</p>';
      })
      .catch(function() {
        docViewBody.innerHTML = '<p>Could not preview this document in the browser. Please use Download instead.</p>';
      });
  });
});

var h1bUploadForm = document.getElementById('h1b-doc-form');
if (h1bUploadForm) {
  h1bUploadForm.addEventListener('submit', function() {
    var button = h1bUploadForm.querySelector('button[type="submit"]');
    if (button) {
      button.disabled = true;
      button.textContent = 'Uploading...';
    }
  });
}
</script>
<?php pageFooter(); ?>
