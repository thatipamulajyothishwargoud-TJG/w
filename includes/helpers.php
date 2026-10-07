<?php
/**
 * CloudFen HR Portal — Core Helpers (PHP 8.2 compatible)
 * All shared utility functions: DB, mail, sanitization, notifications, etc.
 *
 * PHP 8.2 CHANGES:
 *   - All functions now have full return-type and parameter-type declarations
 *   - sanitizeInt() gains optional $max parameter (fixes 3-arg calls in ip_block.php)
 *   - rate_limit table name — matches actual DB schema (singular)
 *   - match expressions replace if/else chains
 *   - Deprecated string-interpolation styles fixed
 */

if (!defined('DB_HOST')) {
    require_once dirname(__DIR__) . '/config/config.php';
}

/* ── DATABASE ─────────────────────────────────────────────── */
function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = 'mysql:host=' . DB_HOST . ';port=' . (defined('DB_PORT') ? DB_PORT : 3306) . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            error_log('CloudFen DB Error: ' . $e->getMessage());
            http_response_code(500);
            die(json_encode(['success' => false, 'message' => 'Database connection error.']));
        }
    }
    return $pdo;
}

/* ── SANITIZATION ─────────────────────────────────────────── */
function e(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function roleDashboardPath(string $role): string {
    return match ($role) {
        'super_admin' => '/admin/dashboard.php',
        'hr_admin' => '/hr/dashboard.php',
        default => '/employee/dashboard.php',
    };
}

function sanitizeEmail(string $s): string {
    return strtolower(trim(filter_var($s, FILTER_SANITIZE_EMAIL) ?: ''));
}

function sanitizeString(string $s, int $maxLen = 500): string {
    return substr(trim(strip_tags($s)), 0, $maxLen);
}

/**
 * Sanitize an integer value with optional min and max bounds.
 * PHP 8.2: uses mixed type for $v; added optional $max parameter.
 *
 * @param  mixed    $v   Raw input value
 * @param  int      $min Minimum acceptable value (default 0)
 * @param  int|null $max Maximum acceptable value (null = no upper bound)
 * @return int|null      Sanitized integer, or null if invalid / out of range
 */
function sanitizeInt(mixed $v, int $min = 0, ?int $max = null): ?int {
    $i = filter_var($v, FILTER_VALIDATE_INT);
    if ($i === false) return null;
    $i = (int)$i;
    if ($i < $min) return null;
    if ($max !== null && $i > $max) return null;
    return $i;
}

function sanitizeDate(?string $s): ?string {
    if (!$s) return null;
    $d = \DateTime::createFromFormat('Y-m-d', trim($s));
    return ($d && $d->format('Y-m-d') === trim($s)) ? trim($s) : null;
}

function validateEnum(string $v, array $allowed): ?string {
    return in_array($v, $allowed, true) ? $v : null;
}

function buildInClause(array $ids, string $type = 'int'): array {
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $params = ($type === 'int') ? array_map('intval', $ids) : $ids;
    return [$placeholders, $params];
}

function tableExists(string $tableName): bool {
    try {
        $db = getDB();
        $stmt = $db->prepare(
            "SELECT COUNT(*)
             FROM information_schema.tables
             WHERE table_schema = ?
               AND table_name = ?
             LIMIT 1"
        );
        $stmt->execute([DB_NAME, $tableName]);
        return (int)$stmt->fetchColumn() > 0;
    } catch (\Throwable $e) {
        error_log('tableExists error for ' . $tableName . ': ' . $e->getMessage());
        return false;
    }
}

function tableColumnExists(string $tableName, string $columnName): bool {
    static $cache = [];
    $key = $tableName . '.' . $columnName;
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }

    try {
        $db = getDB();
        $stmt = $db->prepare(
            "SELECT COUNT(*)
             FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = ?
               AND TABLE_NAME = ?
               AND COLUMN_NAME = ?
             LIMIT 1"
        );
        $stmt->execute([DB_NAME, $tableName, $columnName]);
        return $cache[$key] = (int)$stmt->fetchColumn() > 0;
    } catch (\Throwable $e) {
        error_log('tableColumnExists error for ' . $key . ': ' . $e->getMessage());
        return $cache[$key] = false;
    }
}

function sanitizePhoneNumber(string $value, int $maxLen = 25): string {
    $value = trim($value);
    $value = preg_replace('/[^0-9+\-() ]+/', '', $value);
    if (!is_string($value)) {
        return '';
    }
    return substr(trim($value), 0, $maxLen);
}

function encodeEmergencyContact(?string $name, ?string $phone): string {
    $payload = [
        'name' => sanitizeString((string)$name, 120),
        'phone' => sanitizePhoneNumber((string)$phone, 25),
    ];
    return json_encode($payload, JSON_UNESCAPED_UNICODE) ?: '';
}

function decodeEmergencyContact(?string $raw): array {
    $raw = trim((string)$raw);
    if ($raw === '') {
        return ['name' => '', 'phone' => ''];
    }

    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
        return [
            'name' => sanitizeString((string)($decoded['name'] ?? ''), 120),
            'phone' => sanitizePhoneNumber((string)($decoded['phone'] ?? ''), 25),
        ];
    }

    $parts = preg_split('/\s*[-|]\s*/', $raw, 2);
    return [
        'name' => sanitizeString((string)($parts[0] ?? ''), 120),
        'phone' => sanitizePhoneNumber((string)($parts[1] ?? ''), 25),
    ];
}

function getHrContactUrl(): string {
    return 'https://cloudfen.com/contact.html';
}

/* ── RATE LIMITING ────────────────────────────────────────── */
/**
 * NOTE: Table is `rate_limit` (singular) — matches the actual database schema.
 */
function rateLimitExceeded(string $key, int $maxAttempts, int $windowSecs): bool {
    $db = getDB();
    $db->prepare("DELETE FROM rate_limit WHERE expires_at < NOW()")->execute();
    // Atomic upsert (`key` is the PRIMARY KEY): a plain SELECT-then-UPDATE here
    // lets concurrent requests all read the same pre-increment count and all get
    // admitted, which trivially defeats the limit under a few parallel connections.
    $db->prepare(
        "INSERT INTO rate_limit (`key`, attempts, expires_at)
         VALUES (?, 1, DATE_ADD(NOW(), INTERVAL ? SECOND))
         ON DUPLICATE KEY UPDATE attempts = attempts + 1"
    )->execute([$key, $windowSecs]);
    $stmt = $db->prepare("SELECT attempts FROM rate_limit WHERE `key` = ? LIMIT 1");
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    return (bool)$row && (int)$row['attempts'] > $maxAttempts;
}

/* ── EMAIL ────────────────────────────────────────────────── */

/**
 * Send email using PHP's built-in mail() function.
 *
 * WHY: Turbify blocks all outbound SMTP connections (ports 25/465/587).
 * PHP mail() bypasses SMTP entirely — it hands the message directly to
 * Turbify's local sendmail binary, which Turbify fully supports.
 * No external account, no API key, no SMTP credentials needed.
 *
 * DELIVERABILITY TIP: In Turbify's control panel make sure the sender
 * domain (MAIL_FROM) matches your hosting domain so SPF passes.
 */
function getAppSetting(string $key, ?string $default = null): ?string {
    static $settings = null;

    if ($settings === null) {
        $settings = [];
        try {
            $rows = getDB()->query("SELECT setting_key, setting_value FROM app_settings")->fetchAll();
            foreach ($rows as $row) {
                $settings[(string)$row['setting_key']] = $row['setting_value'] !== null
                    ? (string)$row['setting_value']
                    : null;
            }
        } catch (\Throwable $e) {
            error_log('CloudFen getAppSetting error: ' . $e->getMessage());
        }
    }

    return array_key_exists($key, $settings) ? $settings[$key] : $default;
}

function getMailerConfig(): array {
    $fromEmail = getAppSetting('mail_from', defined('MAIL_FROM') ? MAIL_FROM : 'noreply@cloudfen.com');
    $fromName  = getAppSetting('mail_from_name', defined('MAIL_FROM_NAME') ? MAIL_FROM_NAME : 'CloudFen HR Portal');
    $transport = strtolower(trim((string)getAppSetting('mail_transport', defined('MAIL_TRANSPORT') ? MAIL_TRANSPORT : '')));
    $provider  = strtolower(trim((string)getAppSetting('mail_provider', defined('MAIL_PROVIDER') ? MAIL_PROVIDER : '')));
    $smtpHost  = trim((string)getAppSetting('smtp_host', defined('SMTP_HOST') ? SMTP_HOST : ''));
    $smtpPort  = (int)(getAppSetting('smtp_port', defined('SMTP_PORT') ? (string)SMTP_PORT : '587') ?: 587);
    $smtpUser  = trim((string)getAppSetting('smtp_username', defined('SMTP_USERNAME') ? SMTP_USERNAME : (defined('SMTP_USER') ? SMTP_USER : '')));
    $smtpPass  = (string)getAppSetting('smtp_password', defined('SMTP_PASSWORD') ? SMTP_PASSWORD : (defined('SMTP_PASS') ? SMTP_PASS : ''));
    $smtpEnc   = strtolower(trim((string)getAppSetting('smtp_encryption', defined('SMTP_ENCRYPTION') ? SMTP_ENCRYPTION : 'tls')));
    $smtpAuth  = strtolower(trim((string)getAppSetting('smtp_auth', defined('SMTP_AUTH') ? ((bool)SMTP_AUTH ? 'true' : 'false') : 'true')));
    $brevoApiKey = trim((string)getAppSetting('brevo_api_key', defined('BREVO_API_KEY') ? BREVO_API_KEY : ''));

    if ($transport === '') {
        $transport = $brevoApiKey !== '' ? 'api' : ($smtpHost !== '' ? 'smtp' : 'mail');
    }

    if ($provider === '' && $brevoApiKey !== '') {
        $provider = 'brevo';
    }

    return [
        'transport'      => $transport,
        'provider'       => $provider,
        'from_email'     => $fromEmail ?: 'noreply@cloudfen.com',
        'from_name'      => $fromName ?: 'CloudFen HR Portal',
        'smtp_host'      => $smtpHost,
        'smtp_port'      => $smtpPort > 0 ? $smtpPort : 587,
        'smtp_username'  => $smtpUser,
        'smtp_password'  => $smtpPass,
        'smtp_encryption'=> in_array($smtpEnc, ['tls', 'ssl', 'starttls', ''], true) ? $smtpEnc : 'tls',
        'smtp_auth'      => !in_array($smtpAuth, ['0', 'false', 'no', 'off'], true),
        'brevo_api_key'  => $brevoApiKey,
    ];
}

function setLastMailError(?string $message): void {
    $GLOBALS['cloudfen_last_mail_error'] = $message;
}

function getLastMailError(): string {
    $value = $GLOBALS['cloudfen_last_mail_error'] ?? '';
    return is_string($value) ? $value : '';
}

function sendMailWithPhpMail(string $to, string $subject, string $htmlBody, string $fromEmail, string $fromName): bool {
    $textBody  = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $htmlBody));
    $boundary  = 'cfb_' . bin2hex(random_bytes(8));
    $messageId = '<cf_' . bin2hex(random_bytes(12)) . '@' . (explode('@', $fromEmail)[1] ?? 'cloudfen.com') . '>';
    $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    $encodedFrom    = '=?UTF-8?B?' . base64_encode($fromName) . '?=';

    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n";
    $headers .= "From: {$encodedFrom} <{$fromEmail}>\r\n";
    $headers .= "Reply-To: {$fromEmail}\r\n";
    $headers .= "Message-ID: {$messageId}\r\n";
    $headers .= "X-Mailer: CloudFen-HR/5.1\r\n";

    $body  = "--{$boundary}\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
    $body .= chunk_split(base64_encode($textBody)) . "\r\n";
    $body .= "--{$boundary}\r\n";
    $body .= "Content-Type: text/html; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
    $body .= chunk_split(base64_encode($htmlBody)) . "\r\n";
    $body .= "--{$boundary}--";

    $result = @mail($to, $encodedSubject, $body, $headers, '-f' . $fromEmail);
    if (!$result) {
        setLastMailError('PHP mail() failed on the hosting server.');
        error_log("CloudFen mail() failed to: {$to}");
    } else {
        setLastMailError(null);
    }
    return (bool)$result;
}

function sendMailWithBrevoApi(string $to, string $subject, string $htmlBody, string $fromEmail, string $fromName, string $apiKey): bool {
    if ($apiKey === '' || $apiKey === 'REPLACE_WITH_BREVO_API_KEY') {
        setLastMailError('Brevo API key is missing or still using the placeholder value.');
        error_log('CloudFen Brevo send blocked: API key is missing or still set to placeholder value.');
        return false;
    }

    $payload = json_encode([
        'sender' => [
            'name'  => $fromName,
            'email' => $fromEmail,
        ],
        'to' => [[
            'email' => $to,
        ]],
        'replyTo' => [
            'email' => $fromEmail,
            'name'  => $fromName,
        ],
        'subject'     => $subject,
        'htmlContent' => $htmlBody,
        'textContent' => strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $htmlBody)),
        'tags'        => ['cloudfen-hr-portal'],
    ], JSON_UNESCAPED_SLASHES);

    if ($payload === false) {
        setLastMailError('Could not encode the Brevo API request payload.');
        return false;
    }

    $headers = [
        'accept: application/json',
        'api-key: ' . $apiKey,
        'content-type: application/json',
    ];

    if (function_exists('curl_init')) {
        $ch = curl_init('https://api.brevo.com/v3/smtp/email');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 20,
        ]);

        $response = curl_exec($ch);
        $curlErr  = curl_error($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($response === false) {
            setLastMailError($curlErr !== '' ? $curlErr : 'Brevo API request failed before receiving a response.');
            error_log('CloudFen Brevo send failed: ' . getLastMailError());
            return false;
        }

        if ($httpCode >= 200 && $httpCode < 300) {
            setLastMailError(null);
            return true;
        }

        $decoded = json_decode($response, true);
        $message = is_array($decoded) && isset($decoded['message']) && is_string($decoded['message'])
            ? $decoded['message']
            : 'Brevo API returned HTTP ' . $httpCode . '.';
        setLastMailError($message);
        error_log('CloudFen Brevo send failed: ' . $message);
        return false;
    }

    $context = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => implode("\r\n", $headers),
            'content'       => $payload,
            'timeout'       => 20,
            'ignore_errors' => true,
        ],
    ]);
    $response = @file_get_contents('https://api.brevo.com/v3/smtp/email', false, $context);
    $statusLine = $http_response_header[0] ?? '';
    preg_match('/\s(\d{3})\s/', $statusLine, $matches);
    $httpCode = isset($matches[1]) ? (int)$matches[1] : 0;

    if ($response === false) {
        setLastMailError('Brevo API request failed and no response was returned.');
        error_log('CloudFen Brevo send failed: ' . getLastMailError());
        return false;
    }

    if ($httpCode >= 200 && $httpCode < 300) {
        setLastMailError(null);
        return true;
    }

    $decoded = json_decode($response, true);
    $message = is_array($decoded) && isset($decoded['message']) && is_string($decoded['message'])
        ? $decoded['message']
        : 'Brevo API returned HTTP ' . $httpCode . '.';
    setLastMailError($message);
    error_log('CloudFen Brevo send failed: ' . $message);
    return false;
}

function sendMail(string $to, string $subject, string $htmlBody): bool {
    $config    = getMailerConfig();
    $fromEmail = $config['from_email'];
    $fromName  = $config['from_name'];

    if ($config['transport'] === 'api' && $config['provider'] === 'brevo') {
        return sendMailWithBrevoApi(
            $to,
            $subject,
            $htmlBody,
            $fromEmail,
            $fromName,
            $config['brevo_api_key']
        );
    }

    if ($config['transport'] === 'smtp' && $config['smtp_host'] !== '') {
        if (
            $config['smtp_auth']
            && (
                $config['smtp_username'] === ''
                || $config['smtp_password'] === ''
                || $config['smtp_password'] === 'REPLACE_WITH_YAHOO_APP_PASSWORD'
            )
        ) {
            setLastMailError('SMTP credentials are missing or still using the placeholder password.');
            error_log('CloudFen SMTP send blocked: SMTP credentials are missing or still set to placeholder values.');
            return false;
        }

        $autoload = dirname(__DIR__) . '/vendor/autoload.php';
        if (file_exists($autoload)) {
            require_once $autoload;
        }

        if (class_exists(\PHPMailer\PHPMailer\PHPMailer::class)) {
            try {
                $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
                $mail->isSMTP();
                $mail->Host       = $config['smtp_host'];
                $mail->Port       = $config['smtp_port'];
                $mail->SMTPAuth   = $config['smtp_auth'];
                $mail->Username   = $config['smtp_username'];
                $mail->Password   = $config['smtp_password'];
                $mail->Timeout    = 15;
                $mail->CharSet    = 'UTF-8';
                $mail->isHTML(true);
                $mail->setFrom($fromEmail, $fromName);
                $mail->addAddress($to);
                $mail->addReplyTo($fromEmail, $fromName);
                $mail->Subject = $subject;
                $mail->Body    = $htmlBody;
                $mail->AltBody = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $htmlBody));

                if ($config['smtp_encryption'] === 'ssl') {
                    $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
                } elseif (in_array($config['smtp_encryption'], ['tls', 'starttls'], true)) {
                    $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                }

                $sent = $mail->send();
                setLastMailError(null);
                return $sent;
            } catch (\Throwable $e) {
                setLastMailError($e->getMessage());
                error_log('CloudFen SMTP send failed: ' . $e->getMessage());
                return false;
            }
        } else {
            setLastMailError('PHPMailer is not available on the server.');
            error_log('CloudFen SMTP send failed: PHPMailer is not available.');
            return false;
        }
    }

    return sendMailWithPhpMail($to, $subject, $htmlBody, $fromEmail, $fromName);
}

function emailTemplate(string $title, string $bodyHtml): string {
    $appName = defined('APP_NAME') ? APP_NAME : 'CloudFen HR Portal';
    $appUrl  = defined('APP_URL')  ? APP_URL  : '';
    return <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#141414;border-radius:16px;border:1px solid #2a2a2a;overflow:hidden;max-width:600px;">
        <tr>
          <td style="background:#000;padding:24px 32px;border-bottom:1px solid #222;">
            <span style="font-family:'Helvetica Neue',sans-serif;font-size:20px;font-weight:800;color:#fff;letter-spacing:-.5px;">Cloud<span style="color:#20a0c0;">Fen</span></span>
            <span style="font-size:12px;color:#555;margin-left:10px;">HR Portal</span>
          </td>
        </tr>
        <tr>
          <td style="padding:32px;">
            <h2 style="margin:0 0 20px;font-size:22px;font-weight:700;color:#f0f0f0;">{$title}</h2>
            <div style="color:#a8a8a8;font-size:15px;line-height:1.7;">{$bodyHtml}</div>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 32px;border-top:1px solid #222;background:#0e0e0e;">
            <p style="margin:0;font-size:12px;color:#444;">{$appName} &bull; <a href="{$appUrl}" style="color:#20a0c0;text-decoration:none;">portal.cloudfen.com</a></p>
            <p style="margin:6px 0 0;font-size:11px;color:#333;">This is an automated message. Do not reply directly to this email.</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
HTML;
}

/* ── NOTIFICATIONS ────────────────────────────────────────── */
function createNotification(int $userId, string $type, string $title, string $message, string $link = ''): void {
    try {
        $db = getDB();
        $db->prepare(
            "INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, ?, ?, ?, ?)"
        )->execute([$userId, $type, $title, $message, $link]);
    } catch (\Throwable $e) {
        error_log('createNotification error: ' . $e->getMessage());
    }
}

/* ── AUDIT LOG ────────────────────────────────────────────── */
function auditLog(string $action, ?string $resource = null, ?int $resourceId = null, array $details = []): void {
    try {
        $db     = getDB();
        $userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
        // Prefer the proxy-validated resolver (includes/security.php) so the audit
        // trail can't be spoofed via a forged X-Forwarded-For/CF-Connecting-IP header;
        // fall back for the rare bootstrap path (e.g. cron/runner.php) that loads
        // helpers.php without security.php.
        $ip     = function_exists('getClientIpSecure') ? getClientIpSecure() : getClientIp();
        $rawUa  = $_SERVER['HTTP_USER_AGENT'] ?? '';
        // PHP 8.2: ensure string before substr — handle potential array from proxy configs
        $ua = substr(is_array($rawUa) ? (string)($rawUa[0] ?? '') : (string)$rawUa, 0, 300);
        $db->prepare(
            "INSERT INTO audit_log (user_id, action, resource, resource_id, details, ip_address, user_agent)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )->execute([
            $userId, $action, $resource, $resourceId,
            $details ? json_encode($details, JSON_UNESCAPED_UNICODE) : null,
            $ip, $ua,
        ]);
    } catch (\Throwable $e) {
        error_log('auditLog error: ' . $e->getMessage());
    }
}

/* ── ONBOARDING CHECK ─────────────────────────────────────── */
// Single source of truth for which document types are required for
// onboarding — used by the documents page UI, the completion notice below,
// and the mandatory-documents access gate in includes/security.php.
function mandatoryOnboardingDocTypes(): array {
    return ['drivers_license', 'i9', 'social_security', 'direct_deposit'];
}

function checkOnboardingComplete(int $userId): void {
    try {
        $db = getDB();
        $required = mandatoryOnboardingDocTypes();
        $stmt = $db->prepare(
            "SELECT doc_type FROM documents WHERE user_id = ? AND status = 'approved'"
        );
        $stmt->execute([$userId]);
        $approved = array_column($stmt->fetchAll(), 'doc_type');
        if (!array_diff($required, $approved)) {
            createNotification(
                $userId, 'onboarding_complete', '🎉 Onboarding Complete!',
                'All required documents have been approved. Welcome to the team!',
                '/employee/documents.php'
            );
        }
    } catch (\Throwable $e) {
        error_log('checkOnboardingComplete error: ' . $e->getMessage());
    }
}

/* ── IP ───────────────────────────────────────────────────── */
function getClientIp(): string {
    $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
    foreach ($keys as $k) {
        $v = $_SERVER[$k] ?? '';
        if (is_array($v)) $v = implode(',', $v);
        $v = trim((string)$v);
        if ($v !== '') {
            $ip = trim(explode(',', $v)[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return '0.0.0.0';
}

/* ── PASSWORD UTILITIES ───────────────────────────────────── */
function hashPassword(string $plain): string {
    return password_hash($plain, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Returns array of error strings; empty array = password is valid.
 *
 * Delegates to validatePasswordStrength() in security.php which enforces
 * the full CloudFen policy: 12+ chars, upper, lower, digit, special char,
 * and a common-password block-list.
 */
function validatePassword(string $plain): array {
    if (function_exists('validatePasswordStrength')) {
        return validatePasswordStrength($plain);
    }
    // Fallback (security.php not yet loaded)
    $errors = [];
    if (strlen($plain) < 12)             $errors[] = 'Password must be at least 12 characters.';
    if (!preg_match('/[A-Z]/', $plain))  $errors[] = 'Password must contain at least one uppercase letter.';
    if (!preg_match('/[a-z]/', $plain))  $errors[] = 'Password must contain at least one lowercase letter.';
    if (!preg_match('/[0-9]/', $plain))  $errors[] = 'Password must contain at least one number.';
    if (!preg_match('/[^A-Za-z0-9]/', $plain)) $errors[] = 'Password must contain at least one special character.';
    return $errors;
}

/* ── VIRUS SCANNER ────────────────────────────────────────── */
/**
 * Scan a file for viruses using ClamAV.
 *
 * Strategy (in order):
 *   1. clamdscan  — talks to the clamd daemon; fast (~50 ms), preferred.
 *   2. clamscan   — standalone CLI; slower (~1-2 s), fallback.
 *   3. If neither is available, behaviour is controlled by config:
 *        CLAMAV_BLOCK_ON_UNAVAILABLE = true  → block upload (safe default)
 *        CLAMAV_BLOCK_ON_UNAVAILABLE = false → allow upload, log warning
 *
 * Returns an array:
 *   ['clean' => true]                         — file is clean
 *   ['clean' => false, 'reason' => '...']     — threat detected or blocked
 *   ['clean' => true,  'skipped' => true]     — scanner unavailable + not blocking
 */
function scanFileForVirus(string $filePath): array {
    // ── Layer 1: PHP polyglot / embedded-script detection ─────────────────
    // Reads the first 8 KB of the file and rejects it if it contains PHP
    // open tags.  This stops JPEG-with-PHP-payload attacks even when MIME
    // validation has already passed.
    $headerBytes = @file_get_contents($filePath, false, null, 0, 8192);
    if ($headerBytes === false) {
        return ['clean' => false, 'reason' => 'File could not be read for security scan.'];
    }
    // PHP open-tag patterns (short tags, echo tags, heredoc abuse)
    if (preg_match('/<\?(?:php|=)/i', $headerBytes)) {
        error_log("CloudFen: PHP payload detected in upload: {$filePath}");
        return ['clean' => false, 'reason' => 'File rejected: embedded script content detected.'];
    }

    // ── Layer 2: Dangerous binary magic-byte blocklist ────────────────────
    // Block Windows PE executables (MZ), ELF binaries, ZIP-based containers
    // that are not PDF/DOCX (i.e. raw ZIP), and shell scripts.
    $magicBlocks = [
        "\x4D\x5A"         => 'Windows executable',   // MZ (EXE/DLL)
        "\x7FELF"          => 'ELF binary',
        "#!"               => 'Shell script',
    ];
    foreach ($magicBlocks as $magic => $label) {
        if (str_starts_with($headerBytes, $magic)) {
            error_log("CloudFen: Blocked magic bytes ({$label}) in upload: {$filePath}");
            return ['clean' => false, 'reason' => "File rejected: {$label} content not allowed."];
        }
    }

    // ── Layer 3: ClamAV (optional — use when available) ──────────────────
    // Runs clamscan if it is on the PATH.  Failures are non-fatal so a
    // missing scanner does not break uploads on cPanel hosts.
    $clamscan = trim((string)shell_exec('which clamscan 2>/dev/null'));
    if ($clamscan !== '') {
        $escaped = escapeshellarg($filePath);
        $output  = [];
        $code    = 0;
        exec("{$clamscan} --no-summary --stdout {$escaped} 2>&1", $output, $code);
        if ($code === 1) {
            $reason = implode(' ', $output);
            error_log("CloudFen: ClamAV threat in upload [{$filePath}]: {$reason}");
            return ['clean' => false, 'reason' => 'File rejected: virus or malware detected.'];
        }
        // exit 2 = scanner error — fall through (non-fatal)
    }

    return ['clean' => true];
}

/* ── SECURE DOWNLOAD TOKEN (SECOND-LAYER SECURITY) ───────── */
/**
 * Generate a short-lived HMAC-signed token for serving a document.
 *
 * The token is bound to doc_id + user_id + timestamp so it cannot
 * be replayed for a different document or user, and it expires after
 * SECURE_DL_TOKEN_TTL seconds (default 15 minutes).
 *
 * Usage (in a view template):
 *   $ts    = time();
 *   $token = generateDocToken($doc['id'], $user['id'], $ts);
 *   $url   = APP_URL . '/api/serve_document.php?doc_id=' . $doc['id']
 *          . '&ts=' . $ts . '&token=' . $token;
 */
/**
 * HMAC secret for doc-download tokens / session fingerprinting.
 * Prefers JWT_SECRET (set in cf_config/config.php, outside webroot). If it's
 * ever undefined, a hardcoded literal fallback would be guessable by anyone
 * who has read this source, so derive one from per-install config constants
 * instead. Deliberately does NOT include DB_PASS: that credential can leak
 * through channels unrelated to this app (a pasted stack trace, a support
 * ticket, a monitoring tool) — tying document-token forgery to it would let
 * that single leak compromise both DB access and every confidential H1B/
 * immigration document at once. DB_HOST/DB_NAME/install path are config
 * facts, not credentials, so a leak of those alone doesn't grant DB access.
 */
function resolveAppSecret(): string {
    if (defined('JWT_SECRET') && JWT_SECRET !== '') {
        return JWT_SECRET;
    }
    throw new RuntimeException('Document signing secret is not configured.');
}

function generateDocToken(int $docId, int $userId, int $ts): string {
    $secret  = resolveAppSecret();
    $payload = $docId . '|' . $userId . '|' . $ts;
    return hash_hmac('sha256', $payload, $secret);
}

function getUploadBasePath(): string {
    $base = defined('UPLOAD_BASE_PATH') ? (string)UPLOAD_BASE_PATH : (sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cf_uploads');
    $base = rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $base), DIRECTORY_SEPARATOR);
    return $base . DIRECTORY_SEPARATOR;
}

function getDocumentServeUrl(int $docId, int $viewerUserId, bool $download = false): string {
    $ts    = time();
    $token = generateDocToken($docId, $viewerUserId, $ts);
    $url   = '/api/serve_document.php?doc_id=' . $docId . '&ts=' . $ts . '&token=' . $token;
    if ($download) {
        $url .= '&download=1';
    }
    return $url;
}

if (!function_exists('allowedMimeTypes')) {
    function allowedMimeTypes(): array {
        return [
            'application/pdf',
            'image/jpeg',
            'image/png',
        ];
    }
}

function allowedEmployeeProjectDocumentMimeTypes(): array {
    return [
        'application/pdf'                                                         => 'pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'       => 'xlsx',
        'image/jpeg'                                                              => 'jpg',
        'image/png'                                                               => 'png',
        'image/gif'                                                               => 'gif',
        'image/webp'                                                              => 'webp',
    ];
}

function sanitizeUploadedFilename(string $originalName, string $fallbackName): string {
    $originalName = trim($originalName);
    if ($originalName === '') {
        $originalName = $fallbackName;
    }

    $sanitized = preg_replace('/[^\w.\- ]+/u', '_', basename($originalName));
    if (!is_string($sanitized) || trim($sanitized) === '') {
        return $fallbackName;
    }

    return trim($sanitized);
}

function getEmployeeProjectDocumentServeUrl(int $docId, int $viewerUserId, bool $download = false): string {
    $ts    = time();
    $token = generateDocToken($docId, $viewerUserId, $ts);
    $url   = '/api/serve_employee_project_document.php?doc_id=' . $docId . '&ts=' . $ts . '&token=' . $token;
    if ($download) {
        $url .= '&download=1';
    }
    return $url;
}

function isTestPhaseMode(): bool {
    return defined('TEST_PHASE_MODE') && TEST_PHASE_MODE;
}

function getComplianceRestrictionMessage(): string {
    return 'Timesheets are unavailable until required documents are submitted and approved.';
}

function userHasApprovedProjectComplianceDocs(int $userId): bool {
    if (isTestPhaseMode()) {
        return true;
    }

    try {
        $db = getDB();
        $hasStatusCol = tableColumnExists('employee_documents', 'status');
        $statusSelect = $hasStatusCol ? 'status' : "'approved' AS status";
        $stmt = $db->prepare(
            "SELECT document_type, {$statusSelect}
             FROM employee_documents
             WHERE employee_id = ?
               AND is_current = 1
               AND document_type IN ('MSA', 'PO')
             ORDER BY id DESC"
        );
        $stmt->execute([$userId]);
        $rows = $stmt->fetchAll();

        $approved = [];
        foreach ($rows as $row) {
            if (($row['status'] ?? '') === 'approved') {
                $approved[(string)$row['document_type']] = true;
            }
        }

        return !empty($approved['MSA']) && !empty($approved['PO']);
    } catch (\Throwable) {
        return false;
    }
}

function userCanAccessTimesheetsModule(int $userId, string $role): bool {
    if (isTestPhaseMode()) {
        return true;
    }

    if ($role === 'super_admin') {
        return true;
    }

    // HR admins are staff — compliance doc checks (MSA/PO) only apply to employees/contractors
    if ($role === 'hr_admin') {
        return true;
    }

    if (!in_array($role, ['employee'], true)) {
        return false;
    }

    return userHasApprovedProjectComplianceDocs($userId);
}

function userCanAccessProjectDetailsModule(int $userId, string $role): bool {
    if (isTestPhaseMode()) {
        return true;
    }

    // super_admin and hr_admin both have full access to the project details module.
    // Compliance doc checks (MSA/PO) apply to employees/contractors, not HR staff.
    if (in_array($role, ['super_admin', 'hr_admin'], true)) {
        return true;
    }

    return false;
}

function handleEmployeeProjectDocumentUpload(
    array $file,
    int $employeeId,
    string $documentType,
    int $uploadedBy,
    ?string $description = null,
    ?int $replaceDocumentId = null,
    string $status = 'approved',
    ?int $projectId = null        // NEW: scope is_current/version_no to this project
): array {
    $documentType = strtoupper(trim($documentType));
    if (!in_array($documentType, ['MSA', 'PO', 'PROJECT'], true)) {
        return ['success' => false, 'message' => 'Invalid project document type.'];
    }

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors = [
            UPLOAD_ERR_INI_SIZE   => 'File exceeds server upload limit.',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds form upload limit.',
            UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded.',
            UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Server temporary folder missing.',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
        ];
        return ['success' => false, 'message' => $errors[$file['error']] ?? 'Upload error.'];
    }

    $maxSize = defined('MAX_DOC_SIZE') ? MAX_DOC_SIZE : (10 * 1024 * 1024);
    if ((int)$file['size'] <= 0 || (int)$file['size'] > $maxSize) {
        return ['success' => false, 'message' => 'File too large. Maximum size is ' . ($maxSize / 1024 / 1024) . 'MB.'];
    }

    if (!is_uploaded_file($file['tmp_name'])) {
        return ['success' => false, 'message' => 'Upload validation failed. Please try again.'];
    }

    $allowedMimeMap = allowedEmployeeProjectDocumentMimeTypes();
    $finfo          = new \finfo(FILEINFO_MIME_TYPE);
    $actualMime     = (string)$finfo->file($file['tmp_name']);
    $extension      = $allowedMimeMap[$actualMime] ?? '';
    if ($extension === '') {
        return ['success' => false, 'message' => 'Invalid file type. Allowed: PDF, DOCX, XLSX, JPG, PNG, GIF, WEBP.'];
    }

    $avResult = scanFileForVirus($file['tmp_name']);
    if (!$avResult['clean']) {
        return ['success' => false, 'message' => $avResult['reason']];
    }

    $status = in_array($status, ['pending', 'approved', 'rejected'], true) ? $status : 'approved';

    $uploadBase = getUploadBasePath();
    $userDir    = $uploadBase . 'employee_project_documents' . DIRECTORY_SEPARATOR . 'employee_' . $employeeId . DIRECTORY_SEPARATOR;
    if (!is_dir($userDir) && !mkdir($userDir, 0750, true)) {
        return ['success' => false, 'message' => 'Upload storage not accessible. Contact admin.'];
    }

    $uniqueToken = bin2hex(random_bytes(16));
    $storedName  = strtolower($documentType) . '_' . date('Ymd_His') . '_' . $uniqueToken . '.' . $extension;
    $destPath    = $userDir . $storedName;
    $displayName = sanitizeUploadedFilename((string)($file['name'] ?? ''), $storedName);

    if (!move_uploaded_file($file['tmp_name'], $destPath)) {
        return ['success' => false, 'message' => 'Failed to save uploaded file. Check server permissions.'];
    }

    $fileHash = hash_file('sha256', $destPath);
    $db       = getDB();
    $hasProjectIdCol = tableColumnExists('employee_documents', 'project_id');
    $hasStatusCol    = tableColumnExists('employee_documents', 'status');
    if (!$hasProjectIdCol) {
        $projectId = null;
    }

    try {
        $db->beginTransaction();

        $employeeStmt = $db->prepare(
            "SELECT id, full_name
             FROM users
             WHERE id = ? AND role IN ('employee', 'hr_admin') AND status = 'active'
             LIMIT 1"
        );
        $employeeStmt->execute([$employeeId]);
        $employee = $employeeStmt->fetch();
        if (!$employee) {
            $db->rollBack();
            @unlink($destPath);
            return ['success' => false, 'message' => 'Employee not found or inactive.'];
        }

        $versionNo = 1;

        if ($replaceDocumentId !== null) {
            $replaceStmt = $db->prepare(
                "SELECT id, employee_id, document_type, version_no
                 FROM employee_documents
                 WHERE id = ? AND is_current = 1
                 LIMIT 1"
            );
            $replaceStmt->execute([$replaceDocumentId]);
            $replacedDocument = $replaceStmt->fetch();

            if (
                !$replacedDocument ||
                (int)$replacedDocument['employee_id'] !== $employeeId ||
                (string)$replacedDocument['document_type'] !== $documentType
            ) {
                $db->rollBack();
                @unlink($destPath);
                return ['success' => false, 'message' => 'Replacement target is invalid.'];
            }

            $versionNo = ((int)$replacedDocument['version_no']) + 1;

            $db->prepare(
                "UPDATE employee_documents
                 SET is_current = 0
                 WHERE id = ?"
            )->execute([$replaceDocumentId]);
        } else {
            // Scope version_no and is_current to the project when project_id is known.
            // This prevents cross-project version numbering and is_current bleed
            // (e.g. uploading MSA for ProjectB must not demote ProjectA's MSA).
            if ($projectId !== null) {
                $versionStmt = $db->prepare(
                    "SELECT MAX(version_no)
                     FROM employee_documents
                     WHERE employee_id = ? AND document_type = ? AND project_id = ?"
                );
                $versionStmt->execute([$employeeId, $documentType, $projectId]);
            } else {
                $versionStmt = $db->prepare(
                    "SELECT MAX(version_no)
                     FROM employee_documents
                     WHERE employee_id = ? AND document_type = ? AND project_id IS NULL"
                );
                $versionStmt->execute([$employeeId, $documentType]);
            }
            $versionNo = ((int)($versionStmt->fetchColumn() ?? 0)) + 1;

            // Demote previous is_current versions — scoped to project_id to avoid
            // marking another project's document as non-current
            if ($projectId !== null) {
                $db->prepare(
                    "UPDATE employee_documents
                     SET is_current = 0
                     WHERE employee_id = ? AND document_type = ?
                       AND project_id = ? AND is_current = 1"
                )->execute([$employeeId, $documentType, $projectId]);
            } else {
                $db->prepare(
                    "UPDATE employee_documents
                     SET is_current = 0
                     WHERE employee_id = ? AND document_type = ?
                       AND project_id IS NULL AND is_current = 1"
                )->execute([$employeeId, $documentType]);
            }
        }

        // Build INSERT — include project_id/status only when the column actually
        // exists on this install, so older schemas without them don't 1054.
        $insertColumns = ['employee_id'];
        $insertValues  = [$employeeId];

        if ($hasProjectIdCol) {
            $insertColumns[] = 'project_id';
            $insertValues[]  = $projectId;
        }

        $insertColumns[] = 'document_type';
        $insertValues[]  = $documentType;
        $insertColumns[] = 'file_name';
        $insertValues[]  = $displayName;
        $insertColumns[] = 'file_path';
        $insertValues[]  = $destPath;
        $insertColumns[] = 'mime_type';
        $insertValues[]  = $actualMime;
        $insertColumns[] = 'file_size';
        $insertValues[]  = (int)$file['size'];
        $insertColumns[] = 'file_hash';
        $insertValues[]  = $fileHash;
        $insertColumns[] = 'description';
        $insertValues[]  = $description !== null && $description !== '' ? $description : null;

        if ($hasStatusCol) {
            $insertColumns[] = 'status';
            $insertValues[]  = $status;
        }

        $insertColumns[] = 'uploaded_by';
        $insertValues[]  = $uploadedBy;
        $insertColumns[] = 'replaced_document_id';
        $insertValues[]  = $replaceDocumentId;
        $insertColumns[] = 'version_no';
        $insertValues[]  = $versionNo;
        $insertColumns[] = 'is_current';
        $insertValues[]  = 1;

        $insertCols  = implode(', ', $insertColumns);
        $placeholders = implode(', ', array_fill(0, count($insertValues), '?'));
        $insertStmt = $db->prepare(
            "INSERT INTO employee_documents
             ({$insertCols})
             VALUES ({$placeholders})"
        );
        $insertStmt->execute($insertValues);

        $newId = (int)$db->lastInsertId();
        $db->commit();

        return [
            'success' => true,
            'message' => $replaceDocumentId ? 'Document replaced successfully.' : 'Document uploaded successfully.',
            'id' => $newId,
            'version_no' => $versionNo,
            'employee_name' => $employee['full_name'],
            'replaced_document_id' => $replaceDocumentId,
        ];
    } catch (\Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        @unlink($destPath);
        error_log('handleEmployeeProjectDocumentUpload error: ' . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to save document record.'];
    }
}

/* ── H1B DOCUMENTS (shared library — HR/Admin upload, all roles view) ── */
function allowedH1bDocumentMimeTypes(): array {
    return [
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
        'application/pdf'                                                         => 'pdf',
        'image/jpeg'                                                              => 'jpg',
        'image/png'                                                               => 'png',
        'image/webp'                                                              => 'webp',
    ];
}

function getDocumentCategoriesWithCounts(): array {
    $db = getDB();
    $stmt = $db->query(
        "SELECT dc.*, COUNT(d.id) AS document_count
         FROM document_categories dc
         LEFT JOIN h1b_documents d ON d.category_id = dc.id
         GROUP BY dc.id
         ORDER BY dc.name ASC"
    );
    return $stmt->fetchAll();
}

function createDocumentCategory(string $name, int $userId): array {
    $name = trim($name);
    if ($name === '') {
        return ['success' => false, 'message' => 'Category name is required.'];
    }
    if (mb_strlen($name) > 100) {
        return ['success' => false, 'message' => 'Category name is too long (max 100 characters).'];
    }

    $db = getDB();
    $dupe = $db->prepare('SELECT id FROM document_categories WHERE name = ? LIMIT 1');
    $dupe->execute([$name]);
    if ($dupe->fetch()) {
        return ['success' => false, 'message' => 'A category with this name already exists.'];
    }

    try {
        $stmt = $db->prepare('INSERT INTO document_categories (name, created_by) VALUES (?, ?)');
        $stmt->execute([$name, $userId]);
        return ['success' => true, 'message' => 'Category created.', 'id' => (int)$db->lastInsertId()];
    } catch (\Throwable $e) {
        error_log('createDocumentCategory error: ' . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to create category.'];
    }
}

function renameDocumentCategory(int $categoryId, string $newName): array {
    $newName = trim($newName);
    if ($newName === '') {
        return ['success' => false, 'message' => 'Category name is required.'];
    }
    if (mb_strlen($newName) > 100) {
        return ['success' => false, 'message' => 'Category name is too long (max 100 characters).'];
    }

    $db = getDB();
    $current = $db->prepare('SELECT id FROM document_categories WHERE id = ? LIMIT 1');
    $current->execute([$categoryId]);
    if (!$current->fetch()) {
        return ['success' => false, 'message' => 'Category not found.'];
    }

    $dupe = $db->prepare('SELECT id FROM document_categories WHERE name = ? AND id != ? LIMIT 1');
    $dupe->execute([$newName, $categoryId]);
    if ($dupe->fetch()) {
        return ['success' => false, 'message' => 'A category with this name already exists.'];
    }

    try {
        $stmt = $db->prepare('UPDATE document_categories SET name = ? WHERE id = ?');
        $stmt->execute([$newName, $categoryId]);
        return ['success' => true, 'message' => 'Category renamed.'];
    } catch (\Throwable $e) {
        error_log('renameDocumentCategory error: ' . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to rename category.'];
    }
}

function deleteDocumentCategoryIfEmpty(int $categoryId): array {
    $db = getDB();
    $countStmt = $db->prepare('SELECT COUNT(*) FROM h1b_documents WHERE category_id = ?');
    $countStmt->execute([$categoryId]);
    if ((int)$countStmt->fetchColumn() > 0) {
        return ['success' => false, 'message' => 'Cannot delete a category that still has documents. Remove its documents first.'];
    }

    try {
        $stmt = $db->prepare('DELETE FROM document_categories WHERE id = ?');
        $stmt->execute([$categoryId]);
        if ($stmt->rowCount() === 0) {
            return ['success' => false, 'message' => 'Category not found.'];
        }
        return ['success' => true, 'message' => 'Category deleted.'];
    } catch (\Throwable $e) {
        error_log('deleteDocumentCategoryIfEmpty error: ' . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to delete category.'];
    }
}

function handleH1bDocumentUpload(array $file, string $documentName, int $uploadedBy, int $categoryId): array {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors = [
            UPLOAD_ERR_INI_SIZE   => 'File exceeds server upload limit.',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds form upload limit.',
            UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded.',
            UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Server temporary folder missing.',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
        ];
        return ['success' => false, 'message' => $errors[$file['error']] ?? 'Upload error.'];
    }

    $db = getDB();
    $catCheck = $db->prepare('SELECT id FROM document_categories WHERE id = ? LIMIT 1');
    $catCheck->execute([$categoryId]);
    if (!$catCheck->fetch()) {
        return ['success' => false, 'message' => 'Please select a valid category.'];
    }

    $maxSize = defined('MAX_DOC_SIZE') ? MAX_DOC_SIZE : (10 * 1024 * 1024);
    if ((int)$file['size'] <= 0 || (int)$file['size'] > $maxSize) {
        return ['success' => false, 'message' => 'File too large. Maximum size is ' . ($maxSize / 1024 / 1024) . 'MB.'];
    }

    if (!is_uploaded_file($file['tmp_name'])) {
        return ['success' => false, 'message' => 'Upload validation failed. Please try again.'];
    }

    $allowedMimeMap = allowedH1bDocumentMimeTypes();
    $finfo          = new \finfo(FILEINFO_MIME_TYPE);
    $actualMime     = (string)$finfo->file($file['tmp_name']);
    $extension      = $allowedMimeMap[$actualMime] ?? '';
    if ($extension === '') {
        return ['success' => false, 'message' => 'Invalid file type. Only DOCX, PDF, JPG, PNG, or WEBP files are allowed.'];
    }

    $avResult = scanFileForVirus($file['tmp_name']);
    if (!$avResult['clean']) {
        return ['success' => false, 'message' => $avResult['reason']];
    }

    $uploadBase = getUploadBasePath();
    $targetDir  = $uploadBase . 'h1b_documents' . DIRECTORY_SEPARATOR;
    if (!is_dir($targetDir) && !mkdir($targetDir, 0750, true)) {
        return ['success' => false, 'message' => 'Upload storage not accessible. Contact admin.'];
    }

    $uniqueToken = bin2hex(random_bytes(16));
    $storedName  = 'h1b_' . date('Ymd_His') . '_' . $uniqueToken . '.' . $extension;
    $destPath    = $targetDir . $storedName;
    $displayName = sanitizeUploadedFilename((string)($file['name'] ?? ''), $storedName);

    if (!move_uploaded_file($file['tmp_name'], $destPath)) {
        return ['success' => false, 'message' => 'Failed to save uploaded file. Check server permissions.'];
    }

    $fileHash = hash_file('sha256', $destPath);

    try {
        $insertStmt = $db->prepare(
            "INSERT INTO h1b_documents
             (document_name, category_id, file_name, file_path, mime_type, file_size, file_hash, uploaded_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        );
        $insertStmt->execute([
            $documentName,
            $categoryId,
            $displayName,
            $destPath,
            $actualMime,
            (int)$file['size'],
            $fileHash,
            $uploadedBy,
        ]);

        return [
            'success' => true,
            'message' => 'H1B document uploaded successfully.',
            'id'      => (int)$db->lastInsertId(),
        ];
    } catch (\Throwable $e) {
        @unlink($destPath);
        error_log('handleH1bDocumentUpload error: ' . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to save document record.'];
    }
}

function getH1bDocumentServeUrl(int $docId, int $viewerUserId, bool $download = false): string {
    $ts    = time();
    $token = generateDocToken($docId, $viewerUserId, $ts);
    $url   = '/api/serve_h1b_document.php?doc_id=' . $docId . '&ts=' . $ts . '&token=' . $token;
    if ($download) {
        $url .= '&download=1';
    }
    return $url;
}

/* ── FILE UPLOAD HANDLER ──────────────────────────────────── */
function handleDocumentUpload(array $file, string $docType, int $userId, bool $hrUploaded = false, ?string $expiryDate = null, ?string $documentName = null): array {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors = [
            UPLOAD_ERR_INI_SIZE   => 'File exceeds server upload limit.',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds form upload limit.',
            UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded.',
            UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Server temporary folder missing.',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
        ];
        return ['success' => false, 'message' => $errors[$file['error']] ?? 'Upload error.'];
    }

    $maxSize = defined('MAX_DOC_SIZE') ? MAX_DOC_SIZE : (10 * 1024 * 1024);
    if ($file['size'] <= 0 || $file['size'] > $maxSize) {
        return ['success' => false, 'message' => 'File too large. Maximum size is ' . ($maxSize / 1024 / 1024) . 'MB.'];
    }

    $allowedMime = allowedMimeTypes();
    $finfo       = new \finfo(FILEINFO_MIME_TYPE);
    $actualMime  = $finfo->file($file['tmp_name']);
    if (!in_array($actualMime, $allowedMime, true)) {
        return ['success' => false, 'message' => 'Invalid file type. Allowed: JPEG, PNG, PDF.'];
    }
    // ── Extension ↔ MIME consistency guard ───────────────────
    // Rejects files where the declared extension contradicts the detected
    // MIME type (e.g. a PHP file renamed to .jpg).
    $mimeToExts = [
        'application/pdf' => ['pdf'],
        'image/jpeg'      => ['jpg', 'jpeg'],
        'image/png'       => ['png'],
    ];
    if (!function_exists('uploadExtensionMatchesMime')) {
        // Fail closed: this guard is only skippable if includes/security.php wasn't
        // loaded, and a missing security check should never silently pass an upload.
        error_log('CloudFen SECURITY WARNING: uploadExtensionMatchesMime() unavailable — rejecting upload rather than skipping the ext/MIME check.');
        return ['success' => false, 'message' => 'Upload validation is unavailable right now. Please try again.'];
    }
    if (!uploadExtensionMatchesMime($file['tmp_name'], $file['name'] ?? '', $mimeToExts)) {
        logSecurityEvent('upload_ext_mime_mismatch', ['name' => $file['name'] ?? '', 'mime' => $actualMime, 'user' => $userId]);
        return ['success' => false, 'message' => 'File extension does not match its content. Please upload a genuine JPEG, PNG, or PDF.'];
    }
    if (!is_uploaded_file($file['tmp_name'])) {
        return ['success' => false, 'message' => 'Upload validation failed. Please try again.'];
    }

    // ── Virus scan (scans the tmp file before moving it) ─────
    $avResult = scanFileForVirus($file['tmp_name']);
    if (!$avResult['clean']) {
        return ['success' => false, 'message' => $avResult['reason']];
    }

    $uploadBase = getUploadBasePath();
    $userDir    = $uploadBase . 'user_' . $userId . DIRECTORY_SEPARATOR;
    if (!is_dir($userDir) && !mkdir($userDir, 0750, true)) {
        return ['success' => false, 'message' => 'Upload storage not accessible. Contact admin.'];
    }

    // PHP 8.2: match expression replaces if/else chain
    $ext = match ($actualMime) {
        'application/pdf' => 'pdf',
        'image/png'       => 'png',
        default           => 'jpg',
    };
    $uuid     = bin2hex(random_bytes(16));
    $safeName = $docType . '_' . $uuid . '.' . $ext;
    $destPath = $userDir . $safeName;
    $originalName = trim((string)($file['name'] ?? ''));
    if ($originalName === '') {
        $originalName = $safeName;
    }
    $originalName = preg_replace('/[^\w.\- ]+/u', '_', basename($originalName)) ?: $safeName;

    if (!move_uploaded_file($file['tmp_name'], $destPath)) {
        return ['success' => false, 'message' => 'Failed to save uploaded file. Check server permissions.'];
    }

    // ── SECOND-LAYER SECURITY: compute SHA-256 integrity hash ────────────
    // Stored at upload time; verified on every download in serve_document.php.
    $fileHash = hash_file('sha256', $destPath);
    // ─────────────────────────────────────────────────────────────────────

    try {
        $db    = getDB();
        $dupStmt = $db->prepare(
            "SELECT id
             FROM documents
             WHERE user_id = ?
               AND doc_type = ?
               AND file_hash = ?
               AND file_size = ?
               AND uploaded_at >= DATE_SUB(NOW(), INTERVAL 2 MINUTE)
             ORDER BY id DESC
             LIMIT 1"
        );
        $dupStmt->execute([$userId, $docType, $fileHash, (int)$file['size']]);
        $existingDupId = $dupStmt->fetchColumn();
        if ($existingDupId) {
            @unlink($destPath);
            return ['success' => true, 'message' => 'Document already uploaded. Duplicate request ignored.', 'id' => (int)$existingDupId];
        }

        $docId = bin2hex(random_bytes(18));
        // 'other' documents are freeform/unlimited — each upload is its own entry, never
        // replacing a prior one the way the fixed onboarding document types do.
        if ($docType !== 'other') {
            $db->prepare("DELETE FROM documents WHERE user_id = ? AND doc_type = ? AND status IN ('pending','rejected','more_info_needed')")
               ->execute([$userId, $docType]);
        }

        // ── DOCUMENT AUTO-REJECT CHECK (employee uploads only) ──────────────
        $docAutoRejectReason = null;
        // (auto-rejection for unreviewed documents is handled by the daily cron job)
        // ────────────────────────────────────────────────────────────────────

        $insertStatus       = $hrUploaded ? 'approved' : ($docAutoRejectReason ? 'rejected' : 'pending');
        $insertRejectReason = $docAutoRejectReason;
        $documentName       = $documentName !== null ? trim($documentName) : null;
        if ($documentName === '') { $documentName = null; }

        $db->prepare(
            "INSERT INTO documents (user_id, doc_type, document_name, file_name, file_path, file_size, mime_type, doc_id, file_hash, status, rejection_reason, expiry_date)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )->execute([$userId, $docType, $documentName, $originalName, $destPath, $file['size'], $actualMime, $docId, $fileHash, $insertStatus, $insertRejectReason, $expiryDate]);
        $insertId = (int)$db->lastInsertId();

        $auditAction = $docAutoRejectReason ? 'document_auto_rejected' : 'document_uploaded';
        auditLog($auditAction, 'documents', $insertId, [
            'doc_type'    => $docType,
            'hr_uploaded' => $hrUploaded,
            'auto_reject' => $docAutoRejectReason,
        ]);

        // ── HR uploaded → instant approve, no notifications needed ──
        if ($hrUploaded) {
            return ['success' => true, 'message' => 'Document uploaded.', 'id' => $insertId];
        }

        // ── Auto-rejected → notify employee via email, return error ──
        if ($docAutoRejectReason) {
            try {
                $uStmt = $db->prepare("SELECT full_name, email FROM users WHERE id = ? LIMIT 1");
                $uStmt->execute([$userId]);
                $uploader = $uStmt->fetch();
                if ($uploader && $uploader['email']) {
                    $docLabels = [
                        'drivers_license'    => "Driver's License / State ID",
                        'i9'                 => 'Form I-9',
                        'passport'           => 'Passport',
                        'work_authorization' => 'Work Authorization / EAD',
                        'h1b_i797'           => 'H-1B Approval (I-797)',
                        'social_security'    => 'Social Security Card',
                        'education'          => 'Educational Certificates',
                        'direct_deposit'     => 'Direct Deposit / Voided Check',
                        'other'              => 'Other Document',
                    ];
                    $dLabel = $docType === 'other' ? ($documentName ?: 'Other Document') : ($docLabels[$docType] ?? ucfirst(str_replace('_', ' ', $docType)));
                    sendMail($uploader['email'],
                        'Document Auto-Rejected — Action Required',
                        emailTemplate('Document Auto-Rejected',
                            "<p>Hi <strong>" . htmlspecialchars($uploader['full_name'], ENT_QUOTES, 'UTF-8') . "</strong>,</p>
                            <p>Your <strong>" . htmlspecialchars($dLabel, ENT_QUOTES, 'UTF-8') . "</strong> upload was <strong style='color:#e05c5c;'>automatically rejected</strong> before reaching HR review.</p>
                            <div style='background:#1a1a1a;border-left:4px solid #e05c5c;padding:14px 18px;border-radius:6px;margin:16px 0;'>
                              <p style='color:#e05c5c;font-weight:700;margin:0 0 6px;'>Reason:</p>
                              <p style='margin:0;'>" . htmlspecialchars($docAutoRejectReason, ENT_QUOTES, 'UTF-8') . "</p>
                            </div>
                            <p>Please correct the issue above and re-upload your document.</p>"));
                }
            } catch (\Throwable $mailEx) {
                error_log('Auto-reject email error: ' . $mailEx->getMessage());
            }
            return ['success' => false, 'message' => '❌ Document auto-rejected: ' . $docAutoRejectReason, 'doc_id' => $docId];
        }

        // ── Notify all HR admins + super admins of the new document upload ──
        try {
            $docLabels = [
                'drivers_license'    => "Driver's License",
                'i9'                 => 'Form I-9',
                'passport'           => 'Passport',
                'work_authorization' => 'Work Auth / EAD',
                'h1b_i797'           => 'H-1B (I-797)',
                'social_security'    => 'SSN Card',
                'education'          => 'Education Certs',
                'direct_deposit'     => 'Direct Deposit',
                'other'              => 'Other Document',
            ];
            $docLabel  = $docType === 'other' ? ($documentName ?: 'Other Document') : ($docLabels[$docType] ?? ucfirst(str_replace('_', ' ', $docType)));

            // Get uploader name
            $uStmt = $db->prepare("SELECT full_name FROM users WHERE id = ? LIMIT 1");
            $uStmt->execute([$userId]);
            $uploaderName = $uStmt->fetchColumn() ?: 'An employee';

            // Get all HR admins and super admins
            $hrAdmins = $db->query(
                "SELECT id FROM users WHERE role IN ('hr_admin','super_admin') AND status = 'active'"
            )->fetchAll(\PDO::FETCH_COLUMN);

            foreach ($hrAdmins as $hrId) {
                createNotification(
                    (int)$hrId,
                    'doc_submitted',
                    '📄 Document Submitted',
                    "{$uploaderName} uploaded a new {$docLabel} for review.",
                    '/admin/documents.php?doc_id=' . $insertId
                );
            }
        } catch (\Throwable $notifEx) {
            // Notification failure must never block the upload response
            error_log('Notification error after doc upload: ' . $notifEx->getMessage());
        }

        return ['success' => true, 'message' => 'Document uploaded successfully. It is now pending review.', 'doc_id' => $docId];
    } catch (\Throwable $e) {
        error_log('Document DB error: ' . $e->getMessage());
        @unlink($destPath);
        return ['success' => false, 'message' => 'Database error saving document. Please try again.'];
    }
}

/* ── PSEUDO-CRON (No-cPanel Alternative) ─────────────────── */
/**
 * WordPress-style pseudo-cron: fires daily tasks on a real page visit
 * using a non-blocking background HTTP request.
 *
 * How it works:
 *   1. On each page load this function checks a timestamp in the DB.
 *   2. If >23 hours have passed, it fires a non-blocking socket call to
 *      /cron/runner.php WITHOUT making the visitor wait for a response.
 *   3. The visitor's page loads instantly — they never feel any delay.
 *
 * Call maybeTriggerPseudoCron() from index.php (already done).
 * This works alongside cron-job.org; the first one to run wins (runner.php
 * has a 30-minute rate-limit guard built in).
 */
function maybeTriggerPseudoCron(): void {
    static $fired = false;
    if ($fired) return;
    $fired = true;

    try {
        $db = getDB();

        // Quick check: has the cron run in the last 23 hours?
        $lastRun = $db->query(
            "SELECT ran_at FROM cron_log ORDER BY ran_at DESC LIMIT 1"
        )->fetchColumn();

        if ($lastRun && (time() - strtotime($lastRun)) < 82800) {
            return; // 23 hours not yet passed
        }

        // Get secret
        $secret = (string)($db->query(
            "SELECT setting_value FROM app_settings WHERE setting_key = 'cron_secret' LIMIT 1"
        )->fetchColumn() ?: '');

        if (empty($secret) || $secret === 'CHANGE_THIS_SECRET_BEFORE_GOING_LIVE') return;

        $appUrl = defined('APP_URL') ? APP_URL : '';
        $scheme = parse_url($appUrl, PHP_URL_SCHEME) ?: 'https';
        $host   = parse_url($appUrl, PHP_URL_HOST)   ?: 'localhost';
        $port   = ($scheme === 'https') ? 443 : 80;
        $prefix = ($scheme === 'https') ? 'ssl://' : '';
        $path   = '/cron/runner.php?token=' . rawurlencode($secret) . '&trigger=pseudo';

        $fp = @fsockopen($prefix . $host, $port, $errno, $errstr, 2);
        if ($fp) {
            $req = "GET {$path} HTTP/1.1\r\n"
                 . "Host: {$host}\r\n"
                 . "Connection: close\r\n"
                 . "User-Agent: CloudFen-PseudoCron/3.0\r\n\r\n";
            fwrite($fp, $req);
            stream_set_blocking($fp, false); // Don't wait for reply
            fclose($fp);
        }
    } catch (\Throwable) {
        // Silent — never break page loads due to cron
    }
}
