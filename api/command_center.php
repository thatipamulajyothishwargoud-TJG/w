<?php
require_once __DIR__.'/../config/config.php';require_once __DIR__.'/../includes/helpers.php';require_once __DIR__.'/../includes/security.php';
sendSecurityHeaders();sendNoCacheHeaders();$user=requireAnyRole();header('Content-Type: application/json; charset=utf-8');$db=getDB();$admin=in_array($user['role'],['hr_admin','super_admin'],true);
function centerCount(PDO $db,string $sql,array $args=[]): int {$q=$db->prepare($sql);$q->execute($args);return (int)$q->fetchColumn();}
foreach(['attendance','performance_goals','leave_requests','performance_reviews','recruitment_candidates'] as $table){if(!tableExists($table)){http_response_code(503);echo json_encode(['error'=>'Run the documented workspace database setup to enable live metrics.']);exit;}}
$id=(int)$user['id'];$today=date('Y-m-d');
$stations=[];
if($admin)$stations[]=['label'=>'People','value'=>centerCount($db,"SELECT COUNT(*) FROM users WHERE role='employee' AND status='active'"),'unit'=>'active employees','url'=>'/admin/people.php','color'=>'#53e4d3'];
else $stations[]=['label'=>'Goals','value'=>centerCount($db,'SELECT COUNT(*) FROM performance_goals WHERE user_id=? AND progress<100',[$id]),'unit'=>'goals in progress','url'=>'/employee/performance.php','color'=>'#53e4d3'];
$stations[]=['label'=>'Attendance','value'=>centerCount($db,'SELECT COUNT(*) FROM attendance WHERE work_date=? AND clock_out IS NULL'.($admin?'':' AND user_id=?'),$admin?[$today]:[$today,$id]),'unit'=>$admin?'people clocked in':'active clock-ins','url'=>'/employee/attendance.php','color'=>'#6ab5ff'];
$stations[]=['label'=>'Leave','value'=>centerCount($db,"SELECT COUNT(*) FROM leave_requests WHERE status='pending'".($admin?'':' AND user_id=?'),$admin?[]:[$id]),'unit'=>'pending requests','url'=>'/employee/leave.php','color'=>'#ffaf70'];
$stations[]=['label'=>'Projects','value'=>centerCount($db,'SELECT COUNT(*) FROM projects'.($admin?'':' WHERE employee_id=?'),$admin?[]:[$id]),'unit'=>'project assignments','url'=>'/project-board.php','color'=>'#bb9eff'];
$stations[]=['label'=>'Reviews','value'=>centerCount($db,"SELECT COUNT(*) FROM performance_reviews WHERE status<>'completed'".($admin?'':' AND employee_id=?'),$admin?[]:[$id]),'unit'=>'reviews to complete','url'=>'/employee/reviews.php','color'=>'#ff87ad'];
if($admin)$stations[]=['label'=>'Hiring','value'=>centerCount($db,"SELECT COUNT(*) FROM recruitment_candidates WHERE stage NOT IN ('hired','rejected')"),'unit'=>'active candidates','url'=>'/admin/recruitment.php','color'=>'#f0dd80'];
else $stations[]=['label'=>'Tasks','value'=>tableExists('project_tasks')?centerCount($db,"SELECT COUNT(*) FROM project_tasks t JOIN projects p ON p.id=t.project_id WHERE p.employee_id=? AND t.state<>'done'",[$id]):0,'unit'=>'tasks remaining','url'=>'/project-board.php','color'=>'#f0dd80'];
echo json_encode(['scope'=>$admin?'Team overview':'Your workspace','updated_at'=>date(DATE_ATOM),'stations'=>$stations],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT);
