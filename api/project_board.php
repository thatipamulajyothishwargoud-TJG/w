<?php
require_once __DIR__.'/../config/config.php';
require_once __DIR__.'/../includes/helpers.php';
require_once __DIR__.'/../includes/security.php';
sendSecurityHeaders();sendNoCacheHeaders();$user=requireAnyRole();
header('Content-Type: application/json; charset=utf-8');
$db=getDB();$admin=in_array($user['role'],['hr_admin','super_admin'],true);
function boardReply(array $body,int $status=200): never {http_response_code($status);echo json_encode($body,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT);exit;}
if(!tableExists('project_tasks'))boardReply(['error'=>'The project board database migration is required.'],503);
if($_SERVER['REQUEST_METHOD']==='GET'){
 $q=$db->prepare('SELECT p.id,p.project_name,p.client_name,u.full_name AS owner FROM projects p JOIN users u ON u.id=p.employee_id'.($admin?'':' WHERE p.employee_id=?').' ORDER BY p.project_name,p.id');$q->execute($admin?[]:[$user['id']]);$projects=$q->fetchAll(PDO::FETCH_ASSOC);
 $q=$db->prepare('SELECT t.id,t.project_id,t.title,t.state,t.priority,t.due_date,t.version FROM project_tasks t JOIN projects p ON p.id=t.project_id'.($admin?'':' WHERE p.employee_id=?').' ORDER BY t.id DESC');$q->execute($admin?[]:[$user['id']]);
 boardReply(['projects'=>$projects,'tasks'=>$q->fetchAll(PDO::FETCH_ASSOC)]);
}
if($_SERVER['REQUEST_METHOD']!=='POST')boardReply(['error'=>'Method not allowed.'],405);
verifyCsrf();
foreach(['action','project_id','id','version','title','state','priority','due_date'] as $field){if(isset($_POST[$field])&&!is_string($_POST[$field]))boardReply(['error'=>'Invalid form data.'],422);}
$action=(string)($_POST['action']??'');
$projectId=filter_var($_POST['project_id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
if(!$projectId)boardReply(['error'=>'Choose a valid project.'],422);
$db->beginTransaction();
try {
 // Lock the parent assignment so ownership cannot change during this update.
 $q=$db->prepare('SELECT employee_id FROM projects WHERE id=? FOR UPDATE');$q->execute([$projectId]);$owner=$q->fetchColumn();
 if($owner===false||(!$admin&&(int)$owner!==(int)$user['id'])){$db->rollBack();boardReply(['error'=>'Project access denied.'],403);}
 if(!in_array($action,['create','update','delete'],true)){$db->rollBack();boardReply(['error'=>'Unknown action.'],422);}
 $title=mb_substr(trim(strip_tags($_POST['title']??'')),0,200,'UTF-8');$state=validateEnum($_POST['state']??'todo',['todo','in_progress','done']);$priority=validateEnum($_POST['priority']??'normal',['low','normal','high']);
 $rawDate=trim((string)($_POST['due_date']??''));$due=$rawDate===''?null:sanitizeDate($rawDate);
 if($action!=='delete'&&(!$title||!$state||!$priority||($rawDate!==''&&!$due))){$db->rollBack();boardReply(['error'=>'Enter a title, valid status, priority, and optional due date.'],422);}
 if($action==='create'){
  $db->prepare('INSERT INTO project_tasks(project_id,title,state,priority,due_date,created_by) VALUES(?,?,?,?,?,?)')->execute([$projectId,$title,$state,$priority,$due,$user['id']]);$id=(int)$db->lastInsertId();
 } else {
  $id=filter_var($_POST['id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);$version=filter_var($_POST['version']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
  $q=$db->prepare('SELECT version FROM project_tasks WHERE id=? AND project_id=? FOR UPDATE');$q->execute([$id?:0,$projectId]);$current=$q->fetchColumn();
  if($current===false){$db->rollBack();boardReply(['error'=>'Task not found.'],404);}
  if(!$version||(int)$current!==$version){$db->rollBack();boardReply(['error'=>'This task changed in another window. Refresh the board and try again.'],409);}
  if($action==='delete')$db->prepare('DELETE FROM project_tasks WHERE id=?')->execute([$id]);
  else $db->prepare('UPDATE project_tasks SET title=?,state=?,priority=?,due_date=?,version=version+1 WHERE id=?')->execute([$title,$state,$priority,$due,$id]);
 }
 auditLog('project_task_'.$action,'project_tasks',(int)$id);$db->commit();boardReply(['ok'=>true,'id'=>(int)$id]);
} catch(Throwable $error){if($db->inTransaction())$db->rollBack();error_log('Project board: '.$error->getMessage());boardReply(['error'=>'Could not save this task. Please try again.'],500);}
