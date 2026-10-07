<?php
require_once __DIR__.'/../config/config.php';
require_once __DIR__.'/helpers.php';
require_once __DIR__.'/security.php';
require_once __DIR__.'/layout.php';
sendSecurityHeaders(); $user=requireAnyRole(); $db=getDB();
$isAdmin=in_array($user['role'],['hr_admin','super_admin'],true);
function moduleStart(string $title,array $user,string $message='',bool $showHeading=true,string $activePage=''): void {
 pageHead($title); echo '<body><div class="app-shell">';renderSidebar($user,$activePage);echo '<main class="main-content">';renderTopbar($title,$user);echo '<div class="page-body">';if($showHeading)echo '<div class="page-header"><div class="eyebrow">CloudFen / People operations</div><h1>'.e($title).'</h1><p>Your workday, connected.</p></div>';
 if($message!=='')echo '<div class="alert alert-info" role="status">'.e($message).'</div>';
}
function moduleEnd(): void {echo '</div></main></div>';pageFooter();echo '</body></html>';}
function moduleToken(): void {echo '<input type="hidden" name="csrf_token" value="'.e(generateCsrfToken()).'">';}
function moduleReady(string $table,array $user,string $title): void {if(!tableExists($table)){moduleStart($title,$user);echo '<div class="card empty-state">This module needs the workspace database migration. Ask your administrator to run the documented setup.</div>';moduleEnd();exit;}}
