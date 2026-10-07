<?php
function renderDashboardOperations(PDO $db,array $user): void {
 $admin=in_array($user['role'],['hr_admin','super_admin'],true);
 if(tableExists('performance_reviews')){
  $q=$db->prepare('SELECT COUNT(*) FROM performance_reviews WHERE '.($admin?'reviewer_id':'employee_id')."=? AND status<>'completed'");$q->execute([$user['id']]);$reviews=(int)$q->fetchColumn();
  echo '<section class="card" style="margin:24px 0"><div class="card-header"><h3>People operations</h3></div><div class="card-body workspace-links"><a class="btn btn-primary" href="/employee/reviews.php">Performance reviews · '.$reviews.' open</a><a class="btn btn-outline" href="/announcements.php">Announcements</a><a class="btn btn-outline" href="/organization.php">Organization</a>';
  if($admin)echo '<a class="btn btn-outline" href="/admin/recruitment.php">Recruitment pipeline</a><a class="btn btn-outline" href="/admin/workforce.php">Workforce analytics</a>';
  echo '<a class="btn btn-primary" href="/analytics.php">Explore analytics ↗</a><a class="btn btn-outline" href="/project-board.php">Project board</a></div></section>';
 }
}
