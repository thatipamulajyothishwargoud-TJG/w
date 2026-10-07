<?php
require_once __DIR__.'/../includes/hr-operations.php';
$cases=[['2026-10-03','2026-10-04',0],['2026-10-05','2026-10-09',5],['2026-12-31','2027-01-01',2],['2028-02-28','2028-03-01',3]];
foreach($cases as [$start,$end,$expected])if(businessDays($start,$end)!==$expected)throw new RuntimeException('Weekday calculation failed.');
foreach(['=1+1',' +SUM(A1:A2)','@SUM(A1:A2)','-1+2'] as $formula)if(!str_starts_with(csvCell($formula),"'"))throw new RuntimeException('CSV formula escaping failed.');
if(csvCell('Ava Bennett')!=='Ava Bennett')throw new RuntimeException('CSV plain text changed.');
echo "PASS weekday boundaries, leap-year dates and CSV formula protection\n";
