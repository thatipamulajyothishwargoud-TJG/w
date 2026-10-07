<?php
// Add fictional task examples only to explicitly marked demo employee projects.
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require_once __DIR__.'/../config/config.php';require_once __DIR__.'/../includes/helpers.php';
if(!defined('APP_DEMO_MODE')||!APP_DEMO_MODE||!in_array('--local-demo',$argv,true)){fwrite(STDERR,"Enable APP_DEMO_MODE and pass --local-demo to seed fictional project tasks.\n");exit(1);}
$db=getDB();$added=0;
foreach($db->query('SELECT p.id,p.employee_id FROM projects p JOIN workspace_people w ON w.user_id=p.employee_id WHERE w.is_demo=1') as $project){
 foreach([['Demo: agree delivery milestones','done','normal',-2],['Demo: prepare weekly progress update','in_progress','high',3],['Demo: review next sprint priorities','todo','normal',7]] as [$title,$state,$priority,$days]){
  $q=$db->prepare('SELECT id FROM project_tasks WHERE project_id=? AND title=?');$q->execute([$project['id'],$title]);if($q->fetch())continue;
  $db->prepare('INSERT INTO project_tasks(project_id,title,state,priority,due_date,created_by) VALUES(?,?,?,?,?,?)')->execute([$project['id'],$title,$state,$priority,date('Y-m-d',strtotime("$days days")),$project['employee_id']]);$added++;
 }
}
echo "$added fictional demo tasks added. Existing tasks were preserved.\n";
