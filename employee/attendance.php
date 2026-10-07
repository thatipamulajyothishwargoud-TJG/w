<?php
require_once __DIR__.'/../includes/module-shell.php';
moduleReady('attendance',$user,'Attendance');

$message='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    verifyCsrf();
    $action=$_POST['action']??'';
    if($action==='clock_in'){
        $q=$db->prepare('INSERT IGNORE INTO attendance(user_id,work_date,clock_in) VALUES(?,CURRENT_DATE,NOW())');
        $q->execute([$user['id']]);
        $message=$q->rowCount()?'You are clocked in. Have a productive day.':'You have already clocked in today.';
    }elseif($action==='clock_out'){
        $q=$db->prepare('UPDATE attendance SET clock_out=NOW() WHERE user_id=? AND work_date=CURRENT_DATE AND clock_out IS NULL');
        $q->execute([$user['id']]);
        $message=$q->rowCount()?'You are clocked out. Your hours have been saved.':'No open attendance record for today.';
    }else{
        http_response_code(400);
        $message='Invalid attendance action.';
    }
    if(isset($q)&&$q->rowCount())auditLog($action,'attendance',null,['user_id'=>$user['id']]);
}

$currentMonth=date('Y-m');
$selectedMonth=(string)($_GET['month']??$currentMonth);
if(!preg_match('/^(\d{4})-(0[1-9]|1[0-2])$/',$selectedMonth,$monthParts)
    ||(int)$monthParts[1]<(int)date('Y')-3
    ||(int)$monthParts[1]>(int)date('Y')+3){
    $selectedMonth=$currentMonth;
}
$monthStart=new DateTimeImmutable($selectedMonth.'-01');
$nextMonth=$monthStart->modify('+1 month');
$monthEnd=$nextMonth->format('Y-m-d');
$startDate=$monthStart->format('Y-m-d');

$profileQuery=$db->prepare(
    'SELECT u.full_name,u.email,u.phone,u.employee_type,u.status,u.start_date'
    .(tableExists('workspace_people')?',p.department,p.job_title,p.location':",'General' department,'Team member' job_title,'' location")
    .' FROM users u '.(tableExists('workspace_people')?'LEFT JOIN workspace_people p ON p.user_id=u.id ':'')
    .'WHERE u.id=? LIMIT 1'
);
$profileQuery->execute([$user['id']]);
$profile=$profileQuery->fetch()?:['full_name'=>$user['name'],'email'=>'','phone'=>'','employee_type'=>'','status'=>'active','department'=>'General','job_title'=>'Team member','location'=>''];

$query=$db->prepare('SELECT work_date,clock_in,clock_out FROM attendance WHERE user_id=? AND work_date>=? AND work_date<? ORDER BY work_date DESC');
$query->execute([$user['id'],$startDate,$monthEnd]);
$rows=$query->fetchAll();
$byDate=[];$totalHours=0.0;$completedDays=0;$arrivalMinutes=[];$departureMinutes=[];
foreach($rows as $row){
    $byDate[$row['work_date']]=$row;
    if($row['clock_out']){
        $seconds=max(0,strtotime($row['clock_out'])-strtotime($row['clock_in']));
        $totalHours+=$seconds/3600;
        $completedDays++;
        $arrivalMinutes[]=(int)date('G',strtotime($row['clock_in']))*60+(int)date('i',strtotime($row['clock_in']));
        $departureMinutes[]=(int)date('G',strtotime($row['clock_out']))*60+(int)date('i',strtotime($row['clock_out']));
    }
}
$averageTime=static function(array $minutes):string{
    if(!$minutes)return '—';
    return gmdate('g:i a',(int)round(array_sum($minutes)/count($minutes))*60);
};
$todayQuery=$db->prepare('SELECT work_date,clock_in,clock_out FROM attendance WHERE user_id=? AND work_date=CURRENT_DATE LIMIT 1');
$todayQuery->execute([$user['id']]);$today=$todayQuery->fetch()?:null;

if(($_GET['export']??'')==='csv'){
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="attendance-'.$selectedMonth.'.csv"');
    $out=fopen('php://output','w');
    fputcsv($out,['Date','Clock in','Clock out','Hours']);
    foreach($rows as $row){
        $hours=$row['clock_out']?round(max(0,strtotime($row['clock_out'])-strtotime($row['clock_in']))/3600,2):'';
        fputcsv($out,[$row['work_date'],$row['clock_in'],$row['clock_out']??'',$hours]);
    }
    fclose($out);
    exit;
}

$initials='';
foreach(array_slice(preg_split('/\s+/',trim((string)$profile['full_name']))?:[],0,2) as $part)$initials.=strtoupper(substr($part,0,1));
moduleStart('Attendance',$user,$message,false,'attendance');
?>
<section class="attendance-heading">
  <div><div class="eyebrow">PEOPLE OPERATIONS / ATTENDANCE</div><h1>Human Resource</h1><p>Track attendance clearly and manage your workday.</p></div>
  <div class="attendance-heading-actions">
    <form method="get" class="attendance-month-form"><label for="attendance-month">Month</label><input id="attendance-month" type="month" name="month" value="<?=e($selectedMonth)?>"><button class="btn btn-outline" type="submit">View</button></form>
    <a class="btn btn-primary" href="/employee/leave.php">＋ Request time off</a>
  </div>
</section>

<section class="attendance-summary-grid" aria-label="Attendance overview">
  <article class="card attendance-identity">
    <div class="attendance-card-head"><h2><span class="attendance-blue-dot"></span>Employee details</h2><a class="btn btn-outline btn-sm" href="/employee/profile.php">Edit profile</a></div>
    <div class="attendance-person">
      <div class="attendance-avatar" aria-hidden="true"><?=e($initials?:'U')?></div>
      <div class="attendance-person-content">
        <div class="attendance-person-name-row"><h3><?=e($profile['full_name'])?></h3><span class="attendance-status"><?=e(ucfirst((string)$profile['status']))?></span></div>
        <div class="attendance-person-fields">
          <div><span>Position</span><strong><?=e($profile['job_title']?:'Team member')?></strong></div>
          <div><span>Email address</span><strong><?=e($profile['email']?:'—')?></strong></div>
          <div><span>Department</span><strong><?=e($profile['department']?:'General')?></strong></div>
        </div>
        <div class="attendance-clock-action">
          <span><?=!$today?'Not clocked in today':($today['clock_out']?'Workday completed':'Clocked in at '.date('g:i a',strtotime($today['clock_in'])))?></span>
          <?php if(!$today||!$today['clock_out']):?><form method="post"><?php moduleToken();?><button class="btn btn-primary" name="action" value="<?=$today?'clock_out':'clock_in'?>"><?=$today?'Clock out':'Clock in'?></button></form><?php endif;?>
        </div>
      </div>
    </div>
  </article>
  <div class="attendance-stats">
    <article class="card attendance-stat"><span>Attendance days</span><strong><?=count($rows)?></strong><small>Recorded in <?=e($monthStart->format('F Y'))?></small></article>
    <article class="card attendance-stat"><span>Hours recorded</span><strong><?=number_format($totalHours,1)?><small> hrs</small></strong><small>Completed shifts this month</small></article>
    <article class="card attendance-stat"><span>Average clock-in</span><strong><?=e($averageTime($arrivalMinutes))?></strong><small>Completed shifts</small></article>
    <article class="card attendance-stat"><span>Average clock-out</span><strong><?=e($averageTime($departureMinutes))?></strong><small>Completed shifts</small></article>
  </div>
</section>

<section class="card attendance-calendar-card" aria-labelledby="attendance-calendar-title">
  <div class="attendance-section-heading"><div><h2 id="attendance-calendar-title">Attendance</h2><p><?=e($monthStart->format('F Y'))?> · Dates with a saved record are marked</p></div><div class="attendance-legend"><span><i class="is-recorded"></i>Recorded</span><span><i class="is-empty"></i>No record</span><span><i class="is-future"></i>Upcoming</span></div></div>
  <div class="attendance-days" role="list" aria-label="Daily attendance for <?=e($monthStart->format('F Y'))?>">
    <?php $days=(int)$monthStart->format('t');for($day=1;$day<=$days;$day++):$date=$monthStart->setDate((int)$monthStart->format('Y'),(int)$monthStart->format('m'),$day);$key=$date->format('Y-m-d');$record=$byDate[$key]??null;$isFuture=$key>date('Y-m-d');$isToday=$key===date('Y-m-d');$dayClass=$record?'recorded':($isFuture?'upcoming':'no-record');if($isToday)$dayClass.=' is-today';?>
      <div class="attendance-day <?=$dayClass?>" role="listitem" aria-label="<?=e($date->format('l, F j'))?>: <?=$record?'attendance recorded':($isFuture?'upcoming':'no attendance record')?>"><span class="attendance-day-name"><?=e($date->format('D'))?></span><span class="attendance-day-number"><?=$day?></span><span class="attendance-day-mark" aria-hidden="true"><?=$record?'✓':($isFuture?'·':'–')?></span></div>
    <?php endfor;?>
  </div>
</section>

<section class="card attendance-history-card">
  <div class="attendance-history-header"><div><h2>Attendance history</h2><p>Saved clock-in and clock-out times for <?=e($monthStart->format('F Y'))?>.</p></div><a class="btn btn-primary" href="?month=<?=e(urlencode($selectedMonth))?>&amp;export=csv">↓ Download report</a></div>
  <?php if($rows):?><div class="attendance-history-list">
    <?php foreach($rows as $row):$worked=$row['clock_out']?max(0,((int)strtotime($row['clock_out'])-(int)strtotime($row['clock_in']))/3600):null;?>
      <article class="attendance-history-row"><div class="attendance-history-date"><span><?=e(date('D',strtotime($row['work_date'])))?></span><strong><?=e(date('d',strtotime($row['work_date'])))?></strong><small><?=e(date('M Y',strtotime($row['work_date'])))?></small></div><div class="attendance-history-track"><div class="attendance-time-range"><span class="attendance-time-line"></span><div><strong><?=e(date('g:i a',strtotime($row['clock_in'])))?> – <?=$row['clock_out']?e(date('g:i a',strtotime($row['clock_out']))):'In progress'?></strong><small><?=$worked!==null?number_format($worked,2).' hours recorded':'Shift is still in progress'?></small></div></div><?php if($worked!==null):?><span class="attendance-worked-pill"><?=number_format($worked,1)?> hrs</span><?php endif;?></div></article>
    <?php endforeach;?>
  </div><?php else:?><div class="attendance-empty"><span aria-hidden="true">◷</span><strong>No attendance records for this month</strong><p>Your saved clock-ins will appear here.</p></div><?php endif;?>
</section>

<?php if($isAdmin):$team=$db->query('SELECT a.*,u.full_name FROM attendance a JOIN users u ON u.id=a.user_id WHERE a.work_date=CURRENT_DATE ORDER BY a.clock_in DESC')->fetchAll();?><section class="card attendance-team-card"><div class="attendance-history-header"><div><h2>Team attendance today</h2><p>Current records for your team.</p></div><span class="attendance-team-count"><?=count($team)?> records</span></div><?php if($team):?><div class="table-scroll"><table class="table"><thead><tr><th>Employee</th><th>Clock in</th><th>Clock out</th><th>Status</th></tr></thead><tbody><?php foreach($team as $row):?><tr><td><?=e($row['full_name'])?></td><td><?=e(date('g:i a',strtotime($row['clock_in'])))?></td><td><?=$row['clock_out']?e(date('g:i a',strtotime($row['clock_out']))):'—'?></td><td><?=$row['clock_out']?'Completed':'Working'?></td></tr><?php endforeach;?></tbody></table></div><?php else:?><div class="attendance-empty"><strong>No team clock-ins yet today.</strong></div><?php endif;?></section><?php endif;moduleEnd();
