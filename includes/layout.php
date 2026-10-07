<?php
/**
 * CloudFen HR Portal - Layout Functions
 * Renders page shells: head, sidebar, topbar, footer.
 */

function pageHead(string $title, string $flashType = '', string $flashTitle = '', string $flashMsg = ''): void {
    $appName     = defined('APP_NAME')         ? APP_NAME         : 'CloudFen HR Portal';
    $sessionWarn = defined('SESSION_WARN')     ? SESSION_WARN     : 300;
    $sessionLife = defined('SESSION_LIFETIME') ? SESSION_LIFETIME : 1800;

    $flashMeta = '';
    if ($flashType && $flashTitle) {
        $ft = htmlspecialchars($flashType,  ENT_QUOTES, 'UTF-8');
        $fT = htmlspecialchars($flashTitle, ENT_QUOTES, 'UTF-8');
        $fM = htmlspecialchars($flashMsg,   ENT_QUOTES, 'UTF-8');
        $flashMeta = '<meta name="flash-toast" data-type="' . $ft . '" data-title="' . $fT . '" data-msg="' . $fM . '">';
    }

    $t = htmlspecialchars($title,   ENT_QUOTES, 'UTF-8');
    $a = htmlspecialchars($appName, ENT_QUOTES, 'UTF-8');

    echo '<!DOCTYPE html>' . "\n";
    echo '<html lang="en">' . "\n";
    echo '<head>' . "\n";
    echo '  <meta charset="UTF-8">' . "\n";
    echo '  <script>document.documentElement.dataset.appearance="light";try{localStorage.setItem("hr-appearance","light");}catch(e){}</script>' . "\n";
    echo '  <meta name="viewport" content="width=device-width,initial-scale=1">' . "\n";
    echo '  <title>' . $t . ' - ' . $a . '</title>' . "\n";
    echo '  <link rel="icon" href="/assets/img/favicon.ico" sizes="any">' . "\n";
    echo '  <link rel="icon" href="/assets/img/favicon-32.png" type="image/png" sizes="32x32">' . "\n";
    echo '  <link rel="apple-touch-icon" href="/assets/img/apple-touch-icon.png">' . "\n";
    $cssVer = @filemtime(__DIR__ . '/../assets/css/app.css') ?: time();
    echo '  <link rel="stylesheet" href="/assets/css/app.css?v=' . $cssVer . '">' . "\n";
    echo '<link rel="stylesheet" href="/assets/css/workspace.css?v=' . filemtime(__DIR__ . '/../assets/css/workspace.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/background-3d.css?v=' . filemtime(__DIR__ . '/../assets/css/background-3d.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/atelier.css?v=' . filemtime(__DIR__ . '/../assets/css/atelier.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/immersive.css?v=' . filemtime(__DIR__ . '/../assets/css/immersive.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/vivid.css?v=' . filemtime(__DIR__ . '/../assets/css/vivid.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/night.css?v=' . filemtime(__DIR__ . '/../assets/css/night.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/command-center.css?v=' . filemtime(__DIR__ . '/../assets/css/command-center.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/reference.css?v=' . filemtime(__DIR__ . '/../assets/css/reference.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/appearance.css?v=' . filemtime(__DIR__ . '/../assets/css/appearance.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/glass-ui.css?v=' . filemtime(__DIR__ . '/../assets/css/glass-ui.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/cursor-3d.css?v=' . filemtime(__DIR__ . '/../assets/css/cursor-3d.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/motion-ui.css?v=' . filemtime(__DIR__ . '/../assets/css/motion-ui.css') . '">';
    echo '<link rel="stylesheet" href="/assets/css/portal-motion.css?v=' . filemtime(__DIR__ . '/../assets/css/portal-motion.css') . '">';
    if ($flashMeta) { echo '  ' . $flashMeta . "\n"; }
    echo '  <script>window.SESSION_LIFETIME = ' . (int)$sessionLife . '; window.SESSION_WARN = ' . (int)$sessionWarn . ';</script>' . "\n";
    echo '</head>' . "\n";
}

function renderSidebar(array $user, string $activePage = ''): void {
    $role    = $user['role'] ?? '';
    $isAdmin = in_array($role, array('hr_admin', 'super_admin'), true);
    $isSA    = ($role === 'super_admin');
    $initials = htmlspecialchars(strtoupper(substr($user['name'] ?? 'U', 0, 1)), ENT_QUOTES, 'UTF-8');
    $name     = htmlspecialchars($user['name'] ?? '', ENT_QUOTES, 'UTF-8');

    $roleLabelMap = array('super_admin' => 'Administrator', 'hr_admin' => 'HR Manager');
    $roleLabel    = htmlspecialchars($roleLabelMap[$role] ?? 'Employee', ENT_QUOTES, 'UTF-8');
    $dashboardHref = $role === 'hr_admin' ? '/hr/dashboard.php' : '/admin/dashboard.php';
    $sectionLabel = $role === 'hr_admin' ? 'HR Manager' : 'Admin';
    $canUseTimesheets = function_exists('userCanAccessTimesheetsModule')
        ? userCanAccessTimesheetsModule((int)($user['id'] ?? 0), (string)$role)
        : true;
    $canUseProjectDetails = function_exists('userCanAccessProjectDetailsModule')
        ? userCanAccessProjectDetailsModule((int)($user['id'] ?? 0), (string)$role)
        : true;

    $a = function($p) use ($activePage) { return $activePage === $p ? ' active' : ''; };

    echo '<div class="sidebar-backdrop" id="sidebar-backdrop"></div>' . "\n";
    echo '<aside class="sidebar" id="sidebar">' . "\n";
    echo '  <div class="sidebar-logo">' . "\n";
    echo '    <div class="sidebar-brand" aria-label="CloudFen"><svg class="sidebar-brand-mark" aria-hidden="true" viewBox="0 0 48 34" fill="none"><path d="M14.2 28.5h20.1a8.2 8.2 0 0 0 .8-16.36A12.1 12.1 0 0 0 12.4 14.2a7.2 7.2 0 0 0 1.8 14.3Z" fill="rgba(255,255,255,.2)" stroke="currentColor" stroke-width="2.4"/><path d="m23.8 20.4 3.1 3.1 6.1-6.4" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg><span>CloudFen</span></div>' . "\n";
    echo '    <button type="button" class="sidebar-close" id="sidebar-close" aria-label="Close menu">&times;</button>' . "\n";
    echo '  </div>' . "\n";
    echo '  <nav class="sidebar-nav">' . "\n";

    if ($isAdmin) {
        echo '    <div class="nav-section">' . $sectionLabel . '</div>' . "\n";
        echo '    <a href="' . $dashboardHref . '"      class="nav-item' . $a('dashboard')      . '">Dashboard</a>' . "\n";
        echo '<a href="/admin/people.php" class="nav-item' . $a('people') . '">People directory</a>';
        echo '    <a href="/admin/employees.php"      class="nav-item' . $a('employees')      . '">Employees</a>' . "\n";
        echo '    <a href="/admin/create_account.php" class="nav-item' . $a('create_account') . '">Create Account</a>' . "\n";
        if ($canUseProjectDetails || $isSA) {
            echo '    <a href="/admin/project_details.php" class="nav-item' . $a('project_details') . '">Project Details</a>' . "\n";
        }
        if ($isSA) {
            // super_admin: plain link — they do not submit documents
            echo '    <a href="/admin/documents.php" class="nav-item' . $a('documents') . '">Documents</a>' . "\n";
        } else {
            // hr_admin: dropdown — they review docs AND must submit their own
            $docOpen    = in_array($activePage, ['documents', 'my_documents'], true);
            $docDisplay = $docOpen ? 'block' : 'none';
            $docRotate  = $docOpen ? 'rotate(90deg)' : 'rotate(0deg)';
            $docActive1 = $a('documents');
            $docActive2 = $a('my_documents');
            echo <<<HTML
    <div style="margin:1px 0;">
      <div onclick="(function(){var s=document.getElementById('doc-sub');var a=document.getElementById('doc-arrow');var open=s.style.display==='block';s.style.display=open?'none':'block';a.style.transform=open?'rotate(0deg)':'rotate(90deg)';})();" style="display:flex;align-items:center;gap:10px;padding:9px 20px;color:rgba(255,255,255,.42);font-weight:500;font-size:.87rem;margin:1px 8px;border-radius:8px;cursor:pointer;user-select:none;transition:background .14s,color .14s;" onmouseover="this.style.background='rgba(255,255,255,.05)';this.style.color='rgba(255,255,255,.85)';" onmouseout="this.style.background='';this.style.color='rgba(255,255,255,.42)';">Documents<span id="doc-arrow" style="margin-left:auto;font-size:.6rem;opacity:.8;display:inline-block;transition:transform .2s;transform:{$docRotate};">&#9654;</span></div>
      <div id="doc-sub" style="display:{$docDisplay};margin-left:28px;padding-left:12px;border-left:1px solid rgba(31,160,192,.25);">
        <a href="/admin/documents.php"    class="nav-item{$docActive1}">View Documents</a>
        <a href="/employee/documents.php" class="nav-item{$docActive2}">My Documents</a>
      </div>
    </div>
HTML;
        }
        $tsOpen    = in_array($activePage, ['timesheets', 'my_timesheets', 'submitted_timesheets'], true);
        $tsDisplay = $tsOpen ? 'block' : 'none';
        $tsRotate  = $tsOpen ? 'rotate(90deg)' : 'rotate(0deg)';
        $tsActive1 = $a('timesheets');
        $tsActive2 = $a('my_timesheets');
        $tsActive3 = $a('submitted_timesheets');
        if ($isSA || $canUseTimesheets) {
            if ($isSA) {
                // super_admin: View Submitted Timesheets only (no My Timesheets)
                echo <<<HTML
    <div style="margin:1px 0;">
      <div onclick="(function(){var s=document.getElementById('ts-sub');var a=document.getElementById('ts-arrow');var open=s.style.display==='block';s.style.display=open?'none':'block';a.style.transform=open?'rotate(0deg)':'rotate(90deg)';})();" style="display:flex;align-items:center;gap:10px;padding:9px 20px;color:rgba(255,255,255,.42);font-weight:500;font-size:.87rem;margin:1px 8px;border-radius:8px;cursor:pointer;user-select:none;transition:background .14s,color .14s;" onmouseover="this.style.background='rgba(255,255,255,.05)';this.style.color='rgba(255,255,255,.85)';" onmouseout="this.style.background='';this.style.color='rgba(255,255,255,.42)';">Timesheets<span id="ts-arrow" style="margin-left:auto;font-size:.6rem;opacity:.8;display:inline-block;transition:transform .2s;transform:{$tsRotate};">&#9654;</span></div>
      <div id="ts-sub" style="display:{$tsDisplay};margin-left:28px;padding-left:12px;border-left:1px solid rgba(31,160,192,.25);">
        <a href="/admin/submitted_timesheets.php" class="nav-item{$tsActive3}">View Submitted Timesheets</a>
      </div>
    </div>
HTML;
            } else {
                // hr_admin: View Submitted Timesheets + My Timesheets
                echo <<<HTML
    <div style="margin:1px 0;">
      <div onclick="(function(){var s=document.getElementById('ts-sub');var a=document.getElementById('ts-arrow');var open=s.style.display==='block';s.style.display=open?'none':'block';a.style.transform=open?'rotate(0deg)':'rotate(90deg)';})();" style="display:flex;align-items:center;gap:10px;padding:9px 20px;color:rgba(255,255,255,.42);font-weight:500;font-size:.87rem;margin:1px 8px;border-radius:8px;cursor:pointer;user-select:none;transition:background .14s,color .14s;" onmouseover="this.style.background='rgba(255,255,255,.05)';this.style.color='rgba(255,255,255,.85)';" onmouseout="this.style.background='';this.style.color='rgba(255,255,255,.42)';">Timesheets<span id="ts-arrow" style="margin-left:auto;font-size:.6rem;opacity:.8;display:inline-block;transition:transform .2s;transform:{$tsRotate};">&#9654;</span></div>
      <div id="ts-sub" style="display:{$tsDisplay};margin-left:28px;padding-left:12px;border-left:1px solid rgba(31,160,192,.25);">
        <a href="/admin/submitted_timesheets.php" class="nav-item{$tsActive3}">View Submitted Timesheets</a>
        <a href="/employee/timesheets.php"        class="nav-item{$tsActive2}">My Timesheets</a>
      </div>
    </div>
HTML;
            }
        }
        echo '    <a href="/admin/manage_jobs.php"    class="nav-item' . $a('manage_jobs')    . '">Job Openings</a>' . "\n";
        echo '    <a href="/admin/reports.php"        class="nav-item' . $a('reports')        . '">Reports</a>' . "\n";
        echo '    <a href="/employee/profile.php"     class="nav-item' . $a('profile')        . '">My Profile</a>' . "\n";
        echo '    <a href="/employee/h1b_documents.php" class="nav-item' . $a('h1b_documents') . '">Document Library</a>' . "\n";
        echo '    <a href="/admin/audit_log.php"      class="nav-item' . $a('audit_log')      . '">Audit Log</a>' . "\n";
        echo '    <a href="/notifications.php"           class="nav-item' . $a('notifs') . '">🔔 Notifications<span class="nav-badge" data-notif style="display:none;"></span></a>' . "\n";

        if ($isSA) {
            echo '    <div class="nav-section">Super Admin</div>' . "\n";
            echo '    <a href="/admin/super/users.php"    class="nav-item sa-nav-item' . $a('sa_users')    . '">User Management</a>' . "\n";
            echo '    <a href="/admin/super/settings.php" class="nav-item sa-nav-item' . $a('sa_settings') . '">Settings</a>' . "\n";
            echo '    <a href="/admin/super/offboard.php" class="nav-item sa-nav-item' . $a('sa_offboard') . '">Offboarding</a>' . "\n";
            echo '    <a href="/admin/super/ip_block.php" class="nav-item sa-nav-item' . $a('sa_ip')       . '">IP Block</a>' . "\n";
        }
    } else {
        echo '    <div class="nav-section">My Portal</div>' . "\n";
        echo '    <a href="/employee/dashboard.php"  class="nav-item' . $a('dashboard')  . '">Dashboard</a>' . "\n";
        echo '    <a href="/employee/documents.php"  class="nav-item' . $a('documents')  . '">My Documents</a>' . "\n";
        if ($canUseTimesheets) {
            echo '    <a href="/employee/timesheets.php" class="nav-item' . $a('timesheets') . '">My Timesheets</a>' . "\n";
        }
        echo '<a href="/employee/projects.php" class="nav-item">My Projects</a>';
        echo '    <a href="/employee/profile.php"    class="nav-item' . $a('profile')    . '">My Profile</a>' . "\n";
        echo '    <a href="/employee/h1b_documents.php" class="nav-item' . $a('h1b_documents') . '">Document Library</a>' . "\n";
        echo '    <a href="/notifications.php"           class="nav-item' . $a('notifs') . '">🔔 Notifications<span class="nav-badge" data-notif style="display:none;"></span></a>' . "\n";
    }

    echo '<div class="nav-section">Workspace</div><a class="nav-item" href="/analytics.php">Analytics</a><a class="nav-item" href="/project-board.php">Project board</a><a class="nav-item" href="/employee/attendance.php">Attendance</a><a class="nav-item" href="/employee/leave.php">Leave management</a><a class="nav-item" href="/employee/performance.php">Goals &amp; performance</a><a class="nav-item" href="/workspace.php">3D workspace</a>';
    echo '<div class="nav-section">People operations</div><a class="nav-item" href="/employee/reviews.php">Performance reviews</a><a class="nav-item" href="/announcements.php">Announcements</a><a class="nav-item" href="/organization.php">Organization</a>';
    if ($isAdmin) echo '<a class="nav-item" href="/admin/recruitment.php">Recruitment pipeline</a><a class="nav-item" href="/admin/workforce.php">Workforce analytics</a><a class="nav-item" href="/admin/leave_policy.php">Leave policy</a>';
    $csrfToken = htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8');

    echo '  </nav>' . "\n";
    echo '  <div class="sidebar-footer">' . "\n";
    echo '    <div class="sidebar-user">' . "\n";
    echo '      <div class="sidebar-avatar">' . $initials . '</div>' . "\n";
    echo '      <div class="sidebar-user-info">' . "\n";
    echo '        <div class="name">' . $name . '</div>' . "\n";
    echo '        <div class="role-label">' . $roleLabel . '</div>' . "\n";
    echo '      </div>' . "\n";
    echo '    </div>' . "\n";
    echo '    <form method="POST" action="/auth/logout.php" style="margin-top:10px;">' . "\n";
    echo '      <input type="hidden" name="csrf_token" value="' . $csrfToken . '">' . "\n";
    echo '      <button type="submit" class="btn btn-outline btn-sm btn-block">Sign Out</button>' . "\n";
    echo '    </form>' . "\n";
    echo '  </div>' . "\n";
    echo '</aside>' . "\n";
}

function renderTopbar(string $pageTitle, array $user): void {
    $t = htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8');

    echo '<div class="topbar">' . "\n";
    echo '  <div style="display:flex;align-items:center;gap:12px;">' . "\n";
    echo '    <button id="menu-toggle" class="btn btn-icon btn-outline" style="display:none;" aria-label="Open menu"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg></button>' . "\n";
    echo '    <span class="topbar-title">' . $t . '</span>' . "\n";
    echo '  </div>' . "\n";
    echo '<div class="workspace-tools"><button type="button" class="btn btn-outline" data-command><span class="search-label">Search workspace </span>⌘ K</button><a class="btn btn-outline" href="/">Home ↗</a><a class="btn btn-outline" href="/workspace.php">Workspace ↗</a></div>';
    echo '  <div class="topbar-right">' . "\n";
    echo '    <a href="/notifications.php" class="btn btn-icon btn-outline notif-bell" title="Notifications" style="position:relative;">🔔<span class="count" style="display:none;"></span></a>' . "\n";
    echo '  </div>' . "\n";
    echo '</div>' . "\n";
}

function pageFooter(): void {
    echo '<script src="/assets/js/workspace.js"></script>';
    echo '<script src="/assets/js/spatial-ui.js"></script>';
    echo '<script src="/assets/js/vendor/three.min.js"></script>';
    echo '<script src="/assets/js/reference-scene.js?v=' . filemtime(__DIR__ . '/../assets/js/reference-scene.js') . '"></script>';
    echo '<script src="/assets/js/appearance.js?v=' . filemtime(__DIR__ . '/../assets/js/appearance.js') . '"></script>';
    echo '<script src="/assets/js/cursor-3d.js?v=' . filemtime(__DIR__ . '/../assets/js/cursor-3d.js') . '"></script>';
    echo '<div id="toast-container"></div>' . "\n";
    echo '<div id="session-warn" style="display:none;">' . "\n";
    echo '  Your session expires soon. <a href="#" onclick="window.location.reload();return false;" style="color:var(--cyan);font-weight:700;">Stay signed in</a>' . "\n";
    echo '</div>' . "\n";
    $jsVer = @filemtime(__DIR__ . '/../assets/js/app.js') ?: time();
    echo '<script src="/assets/js/app.js?v=' . $jsVer . '"></script>' . "\n";
}
?>
