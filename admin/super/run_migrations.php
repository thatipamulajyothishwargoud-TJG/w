<?php
/**
 * CloudFen HR Portal — Migration Runner
 * Access: Super Admin session, OR a matching X-Deploy-Token header
 * (for the automated deploy script to trigger this remotely over HTTPS,
 * since this host has no SSH/cron-over-git access).
 *
 * Applies any config/migration_*.sql file not yet recorded in
 * `schema_migrations`, in filename order. Safe to call repeatedly —
 * already-applied files are skipped, and the shipped migration files
 * are themselves written to be idempotent (CREATE TABLE IF NOT EXISTS /
 * ADD COLUMN IF NOT EXISTS), so a partially-applied history is harmless.
 */
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/helpers.php';
require_once __DIR__ . '/../../includes/security.php';

sendSecurityHeaders();
header('Content-Type: application/json; charset=UTF-8');

/* ── Auth: super_admin session OR X-Deploy-Token header ────────────── */
$deployToken   = getServerVar('HTTP_X_DEPLOY_TOKEN');
$hasValidToken = defined('DEPLOY_MIGRATION_SECRET')
    && DEPLOY_MIGRATION_SECRET !== ''
    && $deployToken !== ''
    && hash_equals(DEPLOY_MIGRATION_SECRET, $deployToken);

if (!$hasValidToken) {
    // No deploy token: falling back to a super_admin browser session. Require
    // POST here (unlike the token path, which is a cookie-less machine call) so
    // a top-level GET navigation to this URL — e.g. a link on another site —
    // can't silently trigger production migrations via the ambient session cookie.
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['success' => false, 'message' => 'Method not allowed. Use POST with a Super Admin session, or the X-Deploy-Token header.']);
        exit;
    }
    startSecureSession();
    if (empty($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'super_admin') {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Forbidden. Super Admin session or valid X-Deploy-Token header required.']);
        exit;
    }
    verifyCsrfToken(true);
}

/* Dedicated, explicitly-buffered connection for this script only — the
   shared getDB() singleton uses PDO::ATTR_EMULATE_PREPARES => false, which
   combined with the mixed query()/exec()/prepare() calls this migration
   runner needs can trip "SQLSTATE[HY000]: ... unbuffered queries are
   active" on the native mysqlnd driver. Isolated here so the app-wide
   connection's behavior for every other page is unchanged. */
$db = new PDO(
    'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET,
    DB_USER,
    DB_PASS,
    [
        PDO::ATTR_ERRMODE                  => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE       => PDO::FETCH_ASSOC,
        PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,
    ]
);

/* ── Tracking table ──────────────────────────────────────────────── */
$db->exec("
    CREATE TABLE IF NOT EXISTS `schema_migrations` (
      `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
      `filename`   VARCHAR(255) NOT NULL,
      `applied_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      `checksum`   CHAR(64)     NOT NULL,
      PRIMARY KEY (`id`),
      UNIQUE KEY `idx_schema_migrations_filename` (`filename`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");

$applied = $db->query('SELECT filename FROM schema_migrations')->fetchAll(PDO::FETCH_COLUMN);
$appliedSet = array_flip($applied);

$migrationDir = __DIR__ . '/../../config';
$files = glob($migrationDir . '/migration_*.sql') ?: [];
sort($files, SORT_STRING);

$results = ['applied' => [], 'skipped' => [], 'failed' => []];

foreach ($files as $path) {
    $filename = basename($path);
    if (isset($appliedSet[$filename])) {
        $results['skipped'][] = $filename;
        continue;
    }

    $sql = file_get_contents($path);
    if ($sql === false) {
        $results['failed'][] = ['file' => $filename, 'error' => 'Could not read file.'];
        continue;
    }

    $statements = splitSqlStatements($sql);
    $checksum   = hash('sha256', $sql);

    try {
        // No beginTransaction()/commit() wrapper: MySQL DDL statements
        // (ALTER/CREATE TABLE) cause an implicit commit, which desyncs
        // PDO's transaction tracking from the server ("There is no active
        // transaction") on any DDL-heavy script. Every shipped migration
        // file is written to be idempotent (IF NOT EXISTS / INSERT IGNORE
        // guards), so it's safe to re-run from a partially-applied state
        // if one statement fails partway through.
        foreach ($statements as $stmt) {
            if (trim($stmt) === '') continue;
            // query() (not exec()) + closeCursor(): some shipped migration
            // files end with a plain SELECT meant for a human to read in
            // phpMyAdmin. exec() is documented as unreliable for statements
            // that return a result set and can leave the cursor open,
            // breaking every later statement on the same connection.
            $result = $db->query($stmt);
            if ($result instanceof PDOStatement) {
                $result->closeCursor();
            }
        }
        $ins = $db->prepare('INSERT INTO schema_migrations (filename, checksum) VALUES (?, ?)');
        $ins->execute([$filename, $checksum]);
        $results['applied'][] = $filename;
        auditLog('migration_applied', 'schema_migrations', 0, ['file' => $filename]);
    } catch (\Throwable $e) {
        $results['failed'][] = ['file' => $filename, 'error' => $e->getMessage()];
        error_log('CloudFen migration failed (' . $filename . '): ' . $e->getMessage());
        // Keep going — later migrations may be independent of this one.
    }
}

echo json_encode(['success' => empty($results['failed']), 'results' => $results], JSON_PRETTY_PRINT);

/**
 * Splits a .sql file into individual statements on top-level `;`,
 * ignoring `;` inside single/double-quoted strings and `--`/`#` line
 * comments. These migration files have no stored procedures, so a
 * DELIMITER-aware parser isn't needed — just quote-aware.
 */
function splitSqlStatements(string $sql): array {
    $statements = [];
    $current    = '';
    $len        = strlen($sql);
    $inString   = null; // null | "'" | '"'
    $inComment  = false;

    for ($i = 0; $i < $len; $i++) {
        $ch = $sql[$i];

        if ($inComment) {
            $current .= $ch;
            if ($ch === "\n") $inComment = false;
            continue;
        }

        if ($inString !== null) {
            $current .= $ch;
            if ($ch === '\\' && $i + 1 < $len) {
                // escaped char — consume it too so we don't misread the quote after it
                $current .= $sql[++$i];
                continue;
            }
            if ($ch === $inString) $inString = null;
            continue;
        }

        if ($ch === '-' && ($sql[$i + 1] ?? '') === '-') {
            $inComment = true;
            $current .= $ch;
            continue;
        }
        if ($ch === '#') {
            $inComment = true;
            $current .= $ch;
            continue;
        }
        if ($ch === "'" || $ch === '"') {
            $inString = $ch;
            $current .= $ch;
            continue;
        }
        if ($ch === ';') {
            $statements[] = $current;
            $current = '';
            continue;
        }
        $current .= $ch;
    }
    if (trim($current) !== '') $statements[] = $current;

    return $statements;
}
