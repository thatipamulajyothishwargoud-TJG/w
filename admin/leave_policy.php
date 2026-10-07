<?php
require_once __DIR__.'/../includes/module-shell.php';
if(!$isAdmin){http_response_code(403);exit('Access denied.');}
moduleReady('leave_policies',$user,'Leave policy');$message='';
if($_SERVER['REQUEST_METHOD']==='POST'){
 verifyCsrf();$valid=true;$values=[];
 foreach(['annual','sick','personal'] as $type){$days=filter_var($_POST[$type]??'',FILTER_VALIDATE_INT);if($days===false||$days<0||$days>366)$valid=false;$values[$type]=$days;}
 if(!$valid)$message='Each allowance must be a whole number from 0 to 366 days.';
 else{$db->beginTransaction();try{foreach($values as $type=>$days)$db->prepare('UPDATE leave_policies SET annual_days=?,updated_by=? WHERE leave_type=?')->execute([$days,$user['id'],$type]);auditLog('leave_policy_update','leave_policies',null,$values);$db->commit();$message='Annual allowances saved. Existing approved leave is retained.';}catch(Throwable $e){$db->rollBack();$message='Could not update leave policies.';}}
}
$policies=$db->query('SELECT * FROM leave_policies')->fetchAll();moduleStart('Leave policy',$user,$message);?>
<div class="card"><div class="card-header"><h3>Annual leave allowances</h3></div><form method="post" class="card-body"><?php moduleToken();?><p style="margin-bottom:20px">Allowances apply per calendar year. Monday–Friday days are counted; public holidays are not excluded. Pending requests reserve allowance. Default values are editable starting points for your HR policy.</p><div class="module-grid"><?php foreach($policies as $policy):?><div class="form-group"><label><?=e(ucfirst($policy['leave_type']))?> days per year</label><input class="form-control" name="<?=e($policy['leave_type'])?>" type="number" min="0" max="366" step="1" value="<?=(int)$policy['annual_days']?>" required></div><?php endforeach;?></div><button class="btn btn-primary">Save allowances</button> <a class="btn btn-outline" href="/employee/leave.php">Review requests</a></form></div><?php moduleEnd();
