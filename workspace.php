<?php
require_once __DIR__.'/config/config.php';
require_once __DIR__.'/includes/helpers.php';
require_once __DIR__.'/includes/security.php';
require_once __DIR__.'/includes/layout.php';
require_once __DIR__.'/includes/workspace.php';
sendSecurityHeaders(); $user=requireAnyRole();
$admin=in_array($user['role'],['hr_admin','super_admin'],true);
$modules=[['Attendance','Clock in, clock out, and review working hours.','/employee/attendance.php','◷'],['Leave management','Request time off and track approval decisions.','/employee/leave.php','▦'],['Goals & performance','Set personal goals and track your progress.','/employee/performance.php','◎'],['Documents','Upload and review your secure document library.',$admin?'/admin/documents.php':'/employee/documents.php','▤'],['Timesheets','Record hours and manage weekly submissions.',$admin?'/admin/submitted_timesheets.php':'/employee/timesheets.php','▥'],['My profile','Keep your personal and employment details current.','/employee/profile.php','◉']];
if($admin){$modules[]=['People','Explore profiles, departments, and team members.','/admin/people.php','◇'];$modules[]=['Recruitment','Manage your current job openings.','/admin/manage_jobs.php','↗'];$modules[]=['Reports','Explore workforce and compliance reports.','/admin/reports.php','◴'];}
else {$modules[]=['My projects','See your assigned projects and record hours.','/employee/projects.php','◇'];}
$modules[]=['Performance reviews','Complete assessments, feedback, and development plans.','/employee/reviews.php','◎'];
$modules[]=['Announcements','Read workplace updates and news.','/announcements.php','▤'];
if($admin){$modules[]=['Recruitment pipeline','Track candidates, interviews, offers, and hires.','/admin/recruitment.php','↗'];$modules[]=['Workforce analytics','Filter working hours and export workforce reports.','/admin/workforce.php','◴'];}
$modules[]=['Organization','Explore your team by department.','/organization.php','◇'];
$modules[]=['Analytics','Explore attendance, team distribution, and progress charts.','/analytics.php','◴'];
$modules[]=['Project board','Create tasks, set priorities, and track delivery.','/project-board.php','▥'];
pageHead('Digital workspace'); ?>
<body><div class="app-shell"><?php renderSidebar($user,'workspace'); ?><main class="main-content"><?php renderTopbar('Digital workspace',$user); ?><div class="page-body"><?php renderWorkspaceHero($user); ?><div class="page-header"><h1>Everything in its place.</h1><p>Your connected HR workspace. Select a station in the office or a module below.</p></div><div class="module-grid"><?php foreach($modules as [$title,$copy,$url,$icon]): ?><a class="card module-card lift" href="<?=e($url)?>"><span style="color:var(--cyan);font-size:28px"><?=e($icon)?></span><h3><?=e($title)?> ↗</h3><p><?=e($copy)?></p></a><?php endforeach; ?></div></div></main></div><?php pageFooter(); ?></body></html>
