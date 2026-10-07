<?php
function businessDays(string $start,string $end): int {
    $first=new DateTimeImmutable($start);$last=new DateTimeImmutable($end);$count=0;
    for($date=$first;$date<=$last;$date=$date->modify('+1 day'))if((int)$date->format('N')<=5)$count++;
    return $count;
}
function leaveBalance(PDO $db,int $userId,string $type,int $year): array {
    $q=$db->prepare('SELECT annual_days FROM leave_policies WHERE leave_type=?');$q->execute([$type]);$allowance=(float)($q->fetchColumn()?:0);
    $q=$db->prepare("SELECT start_date,end_date,status FROM leave_requests WHERE user_id=? AND leave_type=? AND status IN ('pending','approved') AND start_date<=? AND end_date>=?");
    $q->execute([$userId,$type,"$year-12-31","$year-01-01"]);$approved=0;$pending=0;
    foreach($q as $request){$days=businessDays(max($request['start_date'],"$year-01-01"),min($request['end_date'],"$year-12-31"));if($request['status']==='approved')$approved+=$days;else $pending+=$days;}
    return ['allowance'=>$allowance,'used'=>$approved,'pending'=>$pending,'available'=>max(0,$allowance-$approved-$pending)];
}
function leavesFitPolicy(PDO $db,int $userId,string $type,string $start,string $end): bool {
    for($year=(int)substr($start,0,4);$year<=(int)substr($end,0,4);$year++){
        $days=businessDays(max($start,"$year-01-01"),min($end,"$year-12-31"));
        if($days>leaveBalance($db,$userId,$type,$year)['available'])return false;
    }return true;
}
function csvCell(mixed $value): string {
    $text=(string)($value??'');return preg_match('/^[\s]*[=+@-]/u',$text)?"'".$text:$text;
}
