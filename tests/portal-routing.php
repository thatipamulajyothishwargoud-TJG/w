<?php
require_once __DIR__ . '/../includes/helpers.php';

$cases = [
    'super_admin' => '/admin/dashboard.php',
    'hr_admin' => '/hr/dashboard.php',
    'employee' => '/employee/dashboard.php',
    'unknown' => '/employee/dashboard.php',
];

foreach ($cases as $role => $expected) {
    if (roleDashboardPath($role) !== $expected) {
        throw new RuntimeException('Role dashboard routing failed for ' . $role . '.');
    }
}

echo "PASS administrator, HR manager, employee, and fallback portal routing\n";
