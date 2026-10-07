<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/workspace.php';

sendSecurityHeaders();
$user = requireRole('hr_admin', 'super_admin');
$db   = getDB();

// All queries are fixed — no user input
$stats = array(
    'active_employees'   => (int)$db->query("SELECT COUNT(*) FROM users WHERE role = 'employee' AND status = 'active'")->fetchColumn(),
    'pending_docs'       => (int)$db->query("SELECT COUNT(*) FROM documents WHERE status = 'pending'")->fetchColumn(),
    'pending_timesheets' => (int)$db->query("SELECT COUNT(*) FROM timesheets WHERE status = 'pending'")->fetchColumn(),
    'overtime_pending'   => (int)$db->query("SELECT COUNT(*) FROM timesheets WHERE status = 'pending' AND is_overtime = 1")->fetchColumn(),
);

// Pending docs — oldest first (most urgent)
$recentDocs = $db->query(
    "SELECT d.id, d.doc_type, d.document_name, d.uploaded_at, u.full_name, u.email
     FROM documents d
     JOIN users u ON u.id = d.user_id
     WHERE d.status = 'pending'
     ORDER BY d.uploaded_at ASC
     LIMIT 8"
)->fetchAll();

// Pending timesheets
$recentTS = $db->query(
    "SELECT t.id, t.week_start, t.total_hours, t.is_overtime, u.full_name
     FROM timesheets t
     JOIN users u ON u.id = t.user_id
     WHERE t.status = 'pending'
     ORDER BY t.submitted_at ASC
     LIMIT 8"
)->fetchAll();

// Expiring docs within 60 days
$expiringCount = (int)$db->query(
    "SELECT COUNT(*) FROM documents
     WHERE expiry_date IS NOT NULL
       AND expiry_date >= CURDATE()
       AND expiry_date <= DATE_ADD(CURDATE(), INTERVAL 60 DAY)
       AND status = 'approved'"
)->fetchColumn();

$docLabels = array(
    'drivers_license'    => "Driver's License",
    'i9'                 => 'Form I-9',
    'passport'           => 'Passport',
    'work_authorization' => 'Work Auth / EAD',
    'h1b_i797'           => 'H-1B (I-797)',
    'social_security'    => 'SSN Card',
    'education'          => 'Education Certs',
    'direct_deposit'     => 'Direct Deposit',
    'other'              => 'Other Document',
);

$greeting = date('H') < 12 ? 'morning' : (date('H') < 17 ? 'afternoon' : 'evening');

require __DIR__ . '/../includes/advanced-dashboard.php';
