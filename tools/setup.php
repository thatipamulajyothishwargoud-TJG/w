<?php
// CLI only. Creates missing tables; never resets data or imports sample employees.
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require_once __DIR__.'/../config/config.php';
require_once __DIR__.'/../includes/helpers.php';
$db=getDB();
$schema=file_get_contents(__DIR__.'/../config/cloudfen_deploy.sql');
preg_match_all('/CREATE TABLE IF NOT EXISTS\s+`[^`]+`\s*\(.*?\) ENGINE=[^;]+;/s',$schema,$tables);
foreach($tables[0] as $sql)$db->exec($sql);
foreach(explode(';',file_get_contents(__DIR__.'/../config/migration_workspace.sql')) as $sql){if(trim($sql)!=='')$db->exec($sql);}
$db->exec(file_get_contents(__DIR__.'/../config/migration_people.sql'));
foreach(explode(';',file_get_contents(__DIR__.'/../config/migration_hr_operations.sql')) as $sql){if(trim($sql)!=='')$db->exec($sql);}
$db->exec("ALTER TABLE leave_requests MODIFY COLUMN status ENUM('pending','approved','rejected','cancelled') NOT NULL DEFAULT 'pending'");
foreach(explode(';',file_get_contents(__DIR__.'/../config/migration_project_board.sql')) as $sql){if(trim($sql)!=='')$db->exec($sql);}
echo "Database tables ready. Existing records were preserved.\n";
if(in_array('--admin',$argv,true)){
 $email=getenv('SETUP_ADMIN_EMAIL');$name=getenv('SETUP_ADMIN_NAME')?:'Workspace Administrator';$password=getenv('SETUP_ADMIN_PASSWORD');
 if(!filter_var($email,FILTER_VALIDATE_EMAIL)||!$password||strlen($password)<14){fwrite(STDERR,"Set SETUP_ADMIN_EMAIL and a SETUP_ADMIN_PASSWORD of at least 14 characters.\n");exit(1);}
 if((int)$db->query("SELECT COUNT(*) FROM users WHERE role='super_admin'")->fetchColumn()>0){fwrite(STDERR,"A super administrator already exists. No account changed.\n");exit(1);}
 $db->prepare("INSERT INTO users(full_name,email,password_hash,role,status,email_verified) VALUES(?,?,?,'super_admin','active',1)")->execute([$name,$email,password_hash($password,PASSWORD_DEFAULT)]);
 echo "Administrator created. Clear the SETUP_ADMIN_PASSWORD environment variable now.\n";
}
