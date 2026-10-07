<?php
require_once __DIR__.'/hr-operations.php';
moduleReady('leave_policies',$user,'Leave management');$message='';
if($_SERVER['REQUEST_METHOD']==='POST'){
 verifyCsrf();$action=$_POST['action']??'';
 if($action==='request'){
  $start=sanitizeDate($_POST['start_date']??'');$end=sanitizeDate($_POST['end_date']??'');$type=validateEnum($_POST['leave_type']??'',['annual','sick','personal']);$reason=sanitizeString($_POST['reason']??'',1000);
  if(!$start||!$end||$end<$start||$start<date('Y-m-d')||!$type||!$reason||strtotime($end)-strtotime($start)>366*86400||businessDays($start,$end)<1){$message='Provide a reason and a valid range with at least one weekday, within one year of the start date.';}
  else{$db->beginTransaction();try{
   $db->prepare('SELECT id FROM users WHERE id=? FOR UPDATE')->execute([$user['id']]);
   $q=$db->prepare("SELECT id FROM leave_requests WHERE user_id=? AND status IN ('pending','approved') AND start_date<=? AND end_date>=?");$q->execute([$user['id'],$end,$start]);
   if($q->fetch())$message='These dates overlap an existing request.';
   elseif(!leavesFitPolicy($db,$user['id'],$type,$start,$end))$message='This request exceeds your available leave balance.';
   else{$db->prepare('INSERT INTO leave_requests(user_id,leave_type,start_date,end_date,reason) VALUES(?,?,?,?,?)')->execute([$user['id'],$type,$start,$end,$reason]);$id=(int)$db->lastInsertId();auditLog('leave_request','leave_requests',$id);foreach($db->query("SELECT id FROM users WHERE role IN ('hr_admin','super_admin') AND status='active'") as $admin)createNotification((int)$admin['id'],'leave','New leave request',$user['name'].' requested time off.','/employee/leave.php');$message='Your leave request has been submitted.';}
   $db->commit();
  }catch(Throwable $e){$db->rollBack();error_log('Leave request failed');$message='Unable to save this request. Please try again.';}}
 }elseif(in_array($action,['approved','rejected','cancel'],true)){
  if($action!=='cancel'&&!$isAdmin){http_response_code(403);exit('Access denied.');}
  $id=sanitizeInt($_POST['id']??0,1);$note=sanitizeString($_POST['review_note']??'',1000);$q=$db->prepare('SELECT user_id FROM leave_requests WHERE id=?');$q->execute([$id]);$owner=$q->fetchColumn();
  if(!$owner){$message='Request not found.';}else{$db->beginTransaction();try{
   $db->prepare('SELECT id FROM users WHERE id=? FOR UPDATE')->execute([$owner]);$q=$db->prepare('SELECT * FROM leave_requests WHERE id=? FOR UPDATE');$q->execute([$id]);$request=$q->fetch();
   if($action==='cancel'){
    if((int)$owner!==$user['id']){http_response_code(403);$message='You can only cancel your own request.';}
    elseif(!in_array($request['status'],['pending','approved'],true)||$request['start_date']<date('Y-m-d'))$message='Only upcoming pending or approved leave can be cancelled.';
    else{$db->prepare("UPDATE leave_requests SET status='cancelled' WHERE id=?")->execute([$id]);auditLog('leave_cancel','leave_requests',$id);$message='Request cancelled. Reserved leave has been released.';}
   }elseif((int)$owner===$user['id']||$request['status']!=='pending')$message='This request is no longer pending, or you cannot review your own request.';
   else{
    $fits=true;if($action==='approved')for($year=(int)substr($request['start_date'],0,4);$year<=(int)substr($request['end_date'],0,4);$year++){$balance=leaveBalance($db,(int)$owner,$request['leave_type'],$year);if($balance['used']+$balance['pending']>$balance['allowance'])$fits=false;}
    if(!$fits)$message='Current policy no longer covers the reserved days. Update the policy or reject the request.';
    else{$db->prepare('UPDATE leave_requests SET status=?,reviewer_id=?,review_note=? WHERE id=?')->execute([$action,$user['id'],$note,$id]);createNotification((int)$owner,'leave','Leave request '.$action,$note?:'Your leave request has been '.$action.'.','/employee/leave.php');auditLog('leave_'.$action,'leave_requests',$id);$message='Decision saved and employee notified.';}
   }$db->commit();
  }catch(Throwable $e){$db->rollBack();$message='Unable to update the request. Please try again.';}}
 }else{http_response_code(400);$message='Invalid action.';}
}
