<?php
/**
 * CloudFen HR Portal — Job Openings Manager
 * /hrportal/admin/manage_jobs.php
 * Access: hr_admin, super_admin
 */
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

/* ── Ensure table exists ────────────────────────────────────── */
if (!tableExists('job_openings')) {
    $db->exec("
        CREATE TABLE IF NOT EXISTS `job_openings` (
          `id`              INT UNSIGNED     NOT NULL AUTO_INCREMENT,
          `title`           VARCHAR(120)     NOT NULL,
          `employment_type` VARCHAR(60)      NOT NULL DEFAULT 'Full Time',
          `location`        VARCHAR(120)     NOT NULL,
          `description`     TEXT             NOT NULL,
          `posted_date`     DATE             DEFAULT NULL,
          `status`          ENUM('active','inactive') NOT NULL DEFAULT 'active',
          `created_by`      INT UNSIGNED     DEFAULT NULL,
          `updated_by`      INT UNSIGNED     DEFAULT NULL,
          `created_at`      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
          `updated_at`      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          PRIMARY KEY (`id`),
          KEY `idx_status` (`status`),
          KEY `idx_created_at` (`created_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
}

/* ── Load all jobs ──────────────────────────────────────────── */
$jobs = $db->query('SELECT * FROM job_openings ORDER BY created_at DESC')->fetchAll();
$activeCount   = count(array_filter($jobs, fn($j) => $j['status'] === 'active'));
$inactiveCount = count($jobs) - $activeCount;

pageHead('Manage Job Openings');
?>
<body>
<?php renderSidebar($user, 'manage_jobs'); ?>
<div class="main-wrap">
  <?php renderTopbar('Manage Job Openings', $user); ?>
  <div class="page-body">

    <!-- Page Header -->
    <div class="page-header" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:28px;">
      <div>
        <h1 style="font-size:1.4rem;font-weight:800;color:var(--text-1);margin:0;">Job Openings</h1>
        <p style="color:var(--text-2);font-size:.875rem;margin:4px 0 0;">Add, edit, or remove job listings on the public Careers page.</p>
      </div>
      <button class="btn-cf-primary" onclick="showModal()">+ Add Job Opening</button>
    </div>

    <!-- Stats Row -->
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:28px;">
      <div class="stat-card">
        <div class="stat-label">Total Listings</div>
        <div class="stat-value"><?= count($jobs) ?></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Active (Visible)</div>
        <div class="stat-value" style="color:var(--green);"><?= $activeCount ?></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Hidden</div>
        <div class="stat-value" style="color:var(--text-3);"><?= $inactiveCount ?></div>
      </div>
    </div>

    <!-- Flash message -->
    <div id="flash-msg" style="display:none;"></div>

    <!-- Jobs Table -->
    <div class="card-cf">
      <div class="card-cf-header">
        <span style="font-weight:700;color:var(--text-1);">All Job Openings</span>
        <span style="font-size:.8rem;color:var(--text-3);"><?= count($jobs) ?> total</span>
      </div>
      <?php if (empty($jobs)): ?>
        <div style="text-align:center;padding:48px 24px;color:var(--text-3);">
          <div style="font-size:2rem;margin-bottom:12px;">📋</div>
          <p>No job openings yet. Click <strong>+ Add Job Opening</strong> to create the first one.</p>
        </div>
      <?php else: ?>
        <div class="jobs-table-wrap">
          <table class="jobs-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Type</th>
                <th>Location</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="jobs-tbody">
              <?php foreach ($jobs as $job): ?>
              <tr id="row-<?= (int)$job['id'] ?>">
                <td style="font-weight:600;color:var(--text-1);"><?= e($job['title']) ?></td>
                <td style="color:var(--text-2);font-size:.85rem;"><?= e($job['employment_type']) ?></td>
                <td style="color:var(--text-2);font-size:.85rem;"><?= e($job['location']) ?></td>
                <td>
                  <span class="badge-status <?= $job['status'] === 'active' ? 'badge-active' : 'badge-inactive' ?>">
                    <?= $job['status'] === 'active' ? 'Active' : 'Hidden' ?>
                  </span>
                </td>
                <td style="color:var(--text-3);font-size:.82rem;">
                  <?= date('M j, Y', strtotime($job['created_at'])) ?>
                </td>
                <td>
                  <div style="display:flex;gap:8px;">
                    <button class="btn-cf-sm btn-cf-ghost"
                      onclick="editJob(<?= htmlspecialchars(json_encode([
                        'id'              => $job['id'],
                        'title'           => $job['title'],
                        'employment_type' => $job['employment_type'],
                        'location'        => $job['location'],
                        'description'     => strip_tags($job['description']),
                        'status'          => $job['status'],
                      ]), ENT_QUOTES) ?>)">Edit</button>
                    <button class="btn-cf-sm btn-cf-danger"
                      onclick="deleteJob(<?= (int)$job['id'] ?>, this)">Close</button>
                  </div>
                </td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </div>

  </div><!-- .page-body -->
</div><!-- .main-wrap -->

<!-- ── Add/Edit Modal ──────────────────────────────────────── -->
<div id="job-modal" class="cf-modal-overlay" style="display:none;" onclick="if(event.target===this)hideModal()">
  <div class="cf-modal-box">
    <div class="cf-modal-head">
      <h2 id="modal-title" class="cf-modal-heading">Add Job Opening</h2>
      <button class="cf-modal-close" onclick="hideModal()">&times;</button>
    </div>
    <div class="cf-modal-body">
      <input type="hidden" id="edit-id" value="">

      <div class="form-grid-2">
        <div class="form-field">
          <label class="form-label">Job Title <span style="color:var(--rose)">*</span></label>
          <input id="f-title" type="text" class="form-control-cf" placeholder="e.g. Senior Java Developer" maxlength="120">
        </div>
        <div class="form-field">
          <label class="form-label">Employment Type <span style="color:var(--rose)">*</span></label>
          <select id="f-type" class="form-control-cf">
            <option>Full Time</option>
            <option>Contract</option>
            <option>Contract, Full Time</option>
            <option>Full Time, Travel/Relocation</option>
            <option>Part Time</option>
          </select>
        </div>
        <div class="form-field">
          <label class="form-label">Location <span style="color:var(--rose)">*</span></label>
          <input id="f-location" type="text" class="form-control-cf" placeholder="e.g. Alpharetta, GA" maxlength="120">
        </div>
        <div class="form-field">
          <label class="form-label">Visibility</label>
          <select id="f-status" class="form-control-cf">
            <option value="active">Active — visible on careers page</option>
            <option value="inactive">Hidden — not shown publicly</option>
          </select>
        </div>
      </div>

      <div class="form-field" style="margin-top:14px;">
        <label class="form-label">Job Description / Requirements <span style="color:var(--rose)">*</span></label>
        <textarea id="f-description" class="form-control-cf" rows="10"
          placeholder="Enter duties, requirements, location details, salary info, etc.&#10;&#10;This will appear in the modal on the public Careers page."></textarea>
      </div>

      <div id="modal-msg" style="display:none;margin-top:12px;padding:10px 14px;border-radius:6px;font-size:.88em;"></div>
    </div>
    <div class="cf-modal-footer">
      <button class="btn-cf-secondary" onclick="hideModal()">Cancel</button>
      <button id="save-btn" class="btn-cf-primary" onclick="saveJob()">Save Job Opening</button>
    </div>
  </div>
</div>

<style>
/* ── Page specific ─────────────────────────────────────────── */
.stat-card { background:var(--surface-2); border:1px solid var(--surface-4); border-radius:var(--radius); padding:20px 22px; }
.stat-label { color:var(--text-3); font-size:.78rem; font-weight:600; letter-spacing:.5px; text-transform:uppercase; margin-bottom:6px; }
.stat-value { font-size:1.8rem; font-weight:800; color:var(--text-1); }

.card-cf { background:var(--surface-1); border:1px solid var(--surface-3); border-radius:var(--radius-lg); overflow:hidden; }
.card-cf-header { display:flex; justify-content:space-between; align-items:center; padding:16px 22px; border-bottom:1px solid var(--surface-3); }

.jobs-table-wrap { overflow-x:auto; }
.jobs-table { width:100%; border-collapse:collapse; font-size:.88rem; }
.jobs-table thead th { padding:11px 18px; text-align:left; font-size:.75rem; font-weight:700; letter-spacing:.5px; text-transform:uppercase; color:var(--text-3); border-bottom:1px solid var(--surface-3); background:var(--surface-2); }
.jobs-table tbody tr { border-bottom:1px solid var(--surface-2); transition:background .12s; }
.jobs-table tbody tr:hover { background:var(--surface-2); }
.jobs-table tbody tr:last-child { border-bottom:none; }
.jobs-table td { padding:14px 18px; vertical-align:middle; }

.badge-status { padding:3px 10px; border-radius:20px; font-size:.73rem; font-weight:700; }
.badge-active   { background:var(--green-dim); color:var(--green); }
.badge-inactive { background:var(--surface-3); color:var(--text-3); }

.btn-cf-primary   { background:var(--cyan); color:#fff; border:none; padding:9px 20px; border-radius:var(--radius); font-size:.88rem; font-weight:700; cursor:pointer; font-family:var(--font); transition:background .15s; }
.btn-cf-primary:hover   { background:var(--cyan-bright); }
.btn-cf-secondary { background:var(--surface-3); color:var(--text-1); border:none; padding:9px 20px; border-radius:var(--radius); font-size:.88rem; font-weight:600; cursor:pointer; font-family:var(--font); }
.btn-cf-sm        { padding:5px 12px; font-size:.78rem; border-radius:5px; cursor:pointer; font-weight:600; border:none; font-family:var(--font); }
.btn-cf-ghost     { background:transparent; color:var(--cyan); border:1px solid var(--cyan-dim); }
.btn-cf-ghost:hover { background:var(--cyan-glow); }
.btn-cf-danger    { background:var(--rose-dim); color:var(--rose); border:1px solid transparent; }
.btn-cf-danger:hover { background:rgba(239,68,68,.25); }

/* ── Modal ──────────────────────────────────────────────────── */
.cf-modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,.72); z-index:9000; display:flex; align-items:center; justify-content:center; padding:16px; }
.cf-modal-box     { background:var(--surface-1); border:1px solid var(--surface-3); border-radius:var(--radius-lg); width:100%; max-width:700px; max-height:90vh; display:flex; flex-direction:column; box-shadow:var(--shadow-lg); animation:fadeIn .2s ease; }
.cf-modal-head    { display:flex; align-items:center; justify-content:space-between; padding:20px 24px; border-bottom:1px solid var(--surface-3); flex-shrink:0; }
.cf-modal-heading { font-size:1.05rem; font-weight:800; color:var(--text-1); margin:0; }
.cf-modal-close   { background:none; border:none; color:var(--text-3); font-size:1.4rem; cursor:pointer; line-height:1; padding:0 4px; }
.cf-modal-close:hover { color:var(--text-1); }
.cf-modal-body    { padding:24px; overflow-y:auto; flex:1; }
.cf-modal-footer  { padding:16px 24px; border-top:1px solid var(--surface-3); display:flex; justify-content:flex-end; gap:10px; flex-shrink:0; }

/* ── Form ───────────────────────────────────────────────────── */
.form-grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
@media(max-width:540px){ .form-grid-2{ grid-template-columns:1fr; } }
.form-field { display:flex; flex-direction:column; gap:5px; }
.form-label { font-size:.8rem; font-weight:600; color:var(--text-2); letter-spacing:.3px; }
.form-control-cf { background:var(--surface-2); border:1px solid var(--surface-4); border-radius:var(--radius); padding:9px 12px; color:var(--text-1); font-size:.9rem; outline:none; transition:border-color .15s; font-family:var(--font); width:100%; }
.form-control-cf:focus { border-color:var(--cyan); box-shadow:0 0 0 3px var(--cyan-glow); }
textarea.form-control-cf { resize:vertical; min-height:120px; }

#flash-msg { padding:12px 16px; border-radius:var(--radius); margin-bottom:18px; font-size:.88rem; }
.flash-ok  { background:var(--green-dim); color:var(--green); border:1px solid rgba(16,185,129,.3); }
.flash-err { background:var(--rose-dim); color:var(--rose); border:1px solid rgba(239,68,68,.3); }
</style>

<script>
var API = 'job_openings.php';
var CSRF_TOKEN = <?= json_encode(generateCsrfToken()) ?>;

function showModal(){ document.getElementById('job-modal').style.display='flex'; }
function hideModal(){
  document.getElementById('job-modal').style.display='none';
  resetForm();
}
function resetForm(){
  document.getElementById('edit-id').value='';
  document.getElementById('f-title').value='';
  document.getElementById('f-type').value='Full Time';
  document.getElementById('f-location').value='';
  document.getElementById('f-description').value='';
  document.getElementById('f-status').value='active';
  document.getElementById('modal-title').textContent='Add Job Opening';
  document.getElementById('save-btn').textContent='Save Job Opening';
  document.getElementById('modal-msg').style.display='none';
}

function editJob(job){
  document.getElementById('edit-id').value=job.id;
  document.getElementById('f-title').value=job.title||'';
  document.getElementById('f-type').value=job.employment_type||'Full Time';
  document.getElementById('f-location').value=job.location||'';
  document.getElementById('f-description').value=job.description||'';
  document.getElementById('f-status').value=job.status||'active';
  document.getElementById('modal-title').textContent='Edit Job Opening';
  document.getElementById('save-btn').textContent='Update Job Opening';
  document.getElementById('modal-msg').style.display='none';
  showModal();
}

function saveJob(){
  var editId = document.getElementById('edit-id').value;
  var title  = document.getElementById('f-title').value.trim();
  var type   = document.getElementById('f-type').value;
  var loc    = document.getElementById('f-location').value.trim();
  var desc   = document.getElementById('f-description').value.trim();
  var status = document.getElementById('f-status').value;

  if(!title||!loc||!desc){ modalMsg('Please fill in all required fields.','err'); return; }

  var btn=document.getElementById('save-btn');
  btn.disabled=true; btn.textContent='Saving…';

  var payload={title:title,employment_type:type,location:loc,description:desc,status:status};
  var action=editId?'update':'create';
  if(editId) payload.id=editId;

  fetch(API+'?action='+action,{
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},
    body:JSON.stringify(payload)
  })
  .then(r=>r.json())
  .then(d=>{
    btn.disabled=false;
    btn.textContent=editId?'Update Job Opening':'Save Job Opening';
    if(d.success){ showFlash(editId?'Job updated.':'Job opening added.','ok'); hideModal(); setTimeout(()=>location.reload(),800); }
    else { modalMsg(d.message||'An error occurred.','err'); }
  })
  .catch(()=>{ btn.disabled=false; btn.textContent=editId?'Update Job Opening':'Save Job Opening'; modalMsg('Network error. Please try again.','err'); });
}

function deleteJob(jobId, btn){
  if(!confirm('Close this job opening? Existing candidate records will be retained.')) return;
  btn.disabled=true; btn.textContent='…';
  fetch(API+'?action=delete',{
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},
    body:JSON.stringify({id:jobId})
  })
  .then(r=>r.json())
  .then(d=>{
    if(d.success){
      var row=document.getElementById('row-'+jobId);
      if(row) row.style.animation='fadeOut .3s ease forwards';
      setTimeout(()=>{ if(row) row.remove(); }, 350);
      showFlash('Job closed. Candidate history retained.','ok');setTimeout(()=>location.reload(),600);
    } else {
      btn.disabled=false; btn.textContent='Close';
      showFlash(d.message||'Error removing job.','err');
    }
  })
  .catch(()=>{ btn.disabled=false; btn.textContent='Close'; showFlash('Network error.','err'); });
}

function modalMsg(msg,type){
  var el=document.getElementById('modal-msg');
  el.textContent=msg;
  el.style.background=type==='ok'?'rgba(16,185,129,.15)':'rgba(239,68,68,.12)';
  el.style.color=type==='ok'?'#10b981':'#ef4444';
  el.style.border='1px solid '+(type==='ok'?'rgba(16,185,129,.3)':'rgba(239,68,68,.3)');
  el.style.display='block';
}
function showFlash(msg,type){
  var el=document.getElementById('flash-msg');
  el.textContent=msg; el.style.display='block';
  el.className=type==='ok'?'flash-ok':'flash-err';
  setTimeout(()=>{ el.style.display='none'; }, 3500);
}

// Keyboard close
document.addEventListener('keydown',function(e){ if(e.key==='Escape') hideModal(); });
</script>

<?php pageFooter(); ?>
</body>
</html>
