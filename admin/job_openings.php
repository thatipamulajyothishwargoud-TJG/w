<?php
/**
 * CloudFen — Job Openings API
 * Endpoint: /hrportal/admin/job_openings.php
 *
 * Actions (GET):
 *   ?action=whoami  → returns {role} for the current session (used by job.html JS)
 *   ?action=list    → returns all active job openings (public) or all (admin)
 *
 * Actions (POST, hr_admin / super_admin only):
 *   ?action=create  → add a new job opening
 *   ?action=update  → edit an existing job opening
 *   ?action=delete  → remove a job opening
 *
 * CORS: only the same origin (job.html) may call this.
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';

sendSecurityHeaders();

/* ── CORS: same-origin only. This endpoint is called with credentials
   (session cookie), so reflecting an arbitrary Origin back with
   Allow-Credentials:true would let any site read admin job data.
   An Origin header is always scheme+host+port only (no path), so compare
   against just that part of APP_URL — APP_URL itself may include a
   subpath (e.g. https://host/hrportal per cf_config's layout). ── */
$appOriginParts = defined('APP_URL') ? parse_url((string)APP_URL) : false;
$appOrigin = $appOriginParts && !empty($appOriginParts['host'])
    ? ($appOriginParts['scheme'] ?? 'https') . '://' . $appOriginParts['host'] . (isset($appOriginParts['port']) ? ':' . $appOriginParts['port'] : '')
    : '';
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin && $appOrigin && $origin === $appOrigin) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');
}
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

header('Content-Type: application/json; charset=UTF-8');

/* ── Ensure the job_openings table exists ───────────────────── */
ensureJobOpeningsTable();

/* ── Route ───────────────────────────────────────────────────── */
$action = sanitizeString($_GET['action'] ?? '', 30);

match ($action) {
    'whoami' => handleWhoami(),
    'list'   => handleList(),
    'create' => handleCreate(),
    'update' => handleUpdate(),
    'delete' => handleDelete(),
    default  => jsonError('Unknown action', 400),
};

/* ════════════════════════════════════════════════════════════ */
/* HANDLERS                                                     */
/* ════════════════════════════════════════════════════════════ */

function handleWhoami(): void {
    startSecureSession();
    $role = $_SESSION['role'] ?? '';
    $name = $_SESSION['name'] ?? '';
    echo json_encode(['success' => true, 'role' => $role, 'name' => $name]);
}

function handleList(): void {
    startSecureSession();
    $role     = $_SESSION['role'] ?? '';
    $isAdmin  = in_array($role, ['hr_admin', 'super_admin'], true);
    $db       = getDB();

    // Admins see all; public sees only active
    $sql = $isAdmin
        ? 'SELECT * FROM job_openings ORDER BY created_at DESC'
        : "SELECT * FROM job_openings WHERE status = 'active' ORDER BY created_at DESC";

    $jobs = $db->query($sql)->fetchAll();
    echo json_encode(['success' => true, 'jobs' => $jobs]);
}

function handleCreate(): void {
    $admin = requireAdminRole();
    verifyCsrfToken();
    $data  = jsonInput();

    $title  = sanitizeString($data['title']           ?? '', 120);
    $type   = sanitizeString($data['employment_type'] ?? 'Full Time', 60);
    $loc    = sanitizeString($data['location']        ?? '', 120);
    $desc   = sanitizeString($data['description']     ?? '', 5000);
    $status = validateEnum($data['status'] ?? 'active', ['active', 'inactive']) ?? 'active';

    if (!$title || !$loc || !$desc) {
        jsonError('Title, location, and description are required.');
    }

    $db = getDB();
    $stmt = $db->prepare(
        'INSERT INTO job_openings (title, employment_type, location, description, status, created_by)
         VALUES (?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute([$title, $type, $loc, nl2br(e($desc)), $status, (int)$admin['id']]);
    $newId = (int)$db->lastInsertId();

    auditLog('job_create', 'job_openings', $newId, ['by' => $admin['id'], 'title' => $title]);
    echo json_encode(['success' => true, 'id' => $newId, 'message' => 'Job opening created.']);
}

function handleUpdate(): void {
    $admin = requireAdminRole();
    verifyCsrfToken();
    $data  = jsonInput();

    $id     = sanitizeInt($data['id'] ?? null, 1);
    $title  = sanitizeString($data['title']           ?? '', 120);
    $type   = sanitizeString($data['employment_type'] ?? 'Full Time', 60);
    $loc    = sanitizeString($data['location']        ?? '', 120);
    $desc   = sanitizeString($data['description']     ?? '', 5000);
    $status = validateEnum($data['status'] ?? 'active', ['active', 'inactive']) ?? 'active';

    if (!$id || !$title || !$loc || !$desc) {
        jsonError('ID, title, location, and description are required.');
    }

    $db   = getDB();
    $stmt = $db->prepare(
        'UPDATE job_openings
            SET title = ?, employment_type = ?, location = ?, description = ?,
                status = ?, updated_by = ?, updated_at = NOW()
          WHERE id = ?'
    );
    $stmt->execute([$title, $type, $loc, nl2br(e($desc)), $status, (int)$admin['id'], $id]);

    auditLog('job_update', 'job_openings', $id, ['by' => $admin['id'], 'title' => $title]);
    echo json_encode(['success' => true, 'message' => 'Job opening updated.']);
}

function handleDelete(): void {
    $admin = requireAdminRole();
    verifyCsrfToken();
    $data  = jsonInput();
    $id    = sanitizeInt($data['id'] ?? null, 1);

    if (!$id) { jsonError('Invalid job ID.'); }

    $db   = getDB();
    // Keep candidate history when closing an opening.
    $row  = $db->prepare('SELECT title FROM job_openings WHERE id = ?');
    $row->execute([$id]);
    $job  = $row->fetch();
    if (!$job) { jsonError('Job opening not found.'); }

    $db->prepare("UPDATE job_openings SET status='inactive',updated_by=? WHERE id=?")->execute([(int)$admin['id'],$id]);

    auditLog('job_close', 'job_openings', $id, ['by' => $admin['id'], 'title' => $job['title']]);
    echo json_encode(['success' => true, 'message' => 'Job opening closed. Candidate history retained.']);
}

/* ════════════════════════════════════════════════════════════ */
/* UTILITIES                                                    */
/* ════════════════════════════════════════════════════════════ */

function requireAdminRole(): array {
    startSecureSession();
    checkIpBlock();
    if (empty($_SESSION['user_id'])) {
        jsonError('Authentication required.', 401);
    }
    if (!in_array($_SESSION['role'] ?? '', ['hr_admin', 'super_admin'], true)) {
        jsonError('Access denied. HR Admin or Super Admin role required.', 403);
    }
    return [
        'id'   => (int)$_SESSION['user_id'],
        'name' => $_SESSION['name'] ?? 'Admin',
        'role' => $_SESSION['role'],
    ];
}

function jsonInput(): array {
    $raw = file_get_contents('php://input');
    if (!$raw) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function jsonError(string $msg, int $code = 400): never {
    http_response_code($code);
    echo json_encode(['success' => false, 'message' => $msg]);
    exit;
}

// audit logging handled by auditLog() in helpers.php — uses correct schema columns:
// resource, resource_id, details (JSON), ip_address, user_agent

function ensureJobOpeningsTable(): void {
    try {
        $db = getDB();
        if (tableExists('job_openings')) return;
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
    } catch (\Throwable $e) {
        error_log('ensureJobOpeningsTable error: ' . $e->getMessage());
    }
}
