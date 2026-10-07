<?php
// Render startup hook. Initializes the MySQL schema and safe fictional demo data.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/../config/config.php';

$dsn = 'mysql:host=' . DB_HOST . ';port=' . DB_PORT . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

$db = null;
$deadline = time() + 240;
while (time() < $deadline) {
    try {
        $db = new PDO($dsn, DB_USER, DB_PASS, $options);
        break;
    } catch (PDOException $error) {
        sleep(3);
    }
}

if (!$db instanceof PDO) {
    fwrite(STDERR, "Render MySQL did not become ready within four minutes. Check the private database service and its environment variables.\n");
    exit(1);
}

function runBootstrapCommand(string $script, array $arguments = []): void
{
    $command = array_merge([PHP_BINARY, $script], $arguments);
    $pipes = [];
    $process = proc_open($command, [
        0 => ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes, dirname(__DIR__));

    if (!is_resource($process)) {
        throw new RuntimeException('Could not start the CloudFen database setup command.');
    }

    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);

    if ($stdout !== '') {
        echo $stdout;
    }
    if ($exitCode !== 0) {
        if ($stderr !== '') {
            fwrite(STDERR, $stderr);
        }
        throw new RuntimeException('CloudFen database setup failed with exit code ' . $exitCode . '.');
    }
}

runBootstrapCommand(__DIR__ . '/setup.php');

$email = getenv('SETUP_ADMIN_EMAIL') ?: '';
$name = getenv('SETUP_ADMIN_NAME') ?: 'CloudFen Administrator';
$password = getenv('SETUP_ADMIN_PASSWORD') ?: '';
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 14) {
    fwrite(STDERR, "Set SETUP_ADMIN_EMAIL and SETUP_ADMIN_PASSWORD (at least 14 characters) in the Render web service environment.\n");
    exit(1);
}

$adminCount = (int)$db->query("SELECT COUNT(*) FROM users WHERE role = 'super_admin'")->fetchColumn();
if ($adminCount === 0) {
    $insertAdmin = $db->prepare("INSERT INTO users(full_name, email, password_hash, role, status, email_verified) VALUES(?, ?, ?, 'super_admin', 'active', 1)");
    $insertAdmin->execute([$name, $email, password_hash($password, PASSWORD_DEFAULT)]);
    echo "Initial CloudFen administrator created.\n";
} else {
    echo "Existing CloudFen administrator retained.\n";
}

$demoPassword = getenv('DEMO_ACCOUNT_PASSWORD') ?: '';
if (strlen($demoPassword) < 14) {
    fwrite(STDERR, "Set DEMO_ACCOUNT_PASSWORD (at least 14 characters) in the Render web service environment.\n");
    exit(1);
}

runBootstrapCommand(__DIR__ . '/seed-demo.php', ['--local-demo', '--enable-logins']);
runBootstrapCommand(__DIR__ . '/seed-project-board.php', ['--local-demo']);

echo "CloudFen database initialization is complete.\n";
