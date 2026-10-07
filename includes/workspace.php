<?php
function renderWorkspaceHero(array $user): void {
    if (defined('APP_DEMO_MODE') && APP_DEMO_MODE && function_exists('tableExists') && tableExists('workspace_people')) {
        $demo = getDB()->prepare('SELECT is_demo FROM workspace_people WHERE user_id=?');
        $demo->execute([$user['id']]);
        if ((int)$demo->fetchColumn() === 1) echo '<div class="demo-banner"><span>FICTIONAL DEMO ACCOUNT</span>Sample profile and activity for exploring the portal.</div>';
    }
    $admin = in_array($user['role'], ['hr_admin', 'super_admin'], true);
    $root = $admin ? '/admin/' : '/employee/';
    echo '<section class="workspace-hero"><div class="workspace-copy"><div class="eyebrow"><span class="status-dot"></span>CloudFen / Digital workspace</div><h2>Your people.<br>A world of possibilities.</h2><p>A clearer view of your workday. Manage people, time, and documents from one connected workspace.</p><div class="workspace-links"><a class="btn btn-primary" href="/workspace.php">Explore workspace ↗</a><a class="btn btn-outline" href="' . $root . 'documents.php">Open documents</a></div></div><div class="office-scene" data-office aria-label="Interactive 3D office. Use the workspace links for keyboard navigation."><span class="scene-caption">YOUR CONNECTED WORKPLACE · 3D VIEW</span></div></section>';
}
