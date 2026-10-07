-- ═══════════════════════════════════════════════════════════════════
-- CloudFen HR Portal — COMBINED Security Migration (v13 + v14)
-- Run ONCE in cPanel → phpMyAdmin on your live database.
-- Safe to re-run: every statement uses IF NOT EXISTS / INSERT IGNORE.
-- Order matters — run top to bottom as-is.
-- ═══════════════════════════════════════════════════════════════════

-- ── 1. SHA-256 integrity hash on documents ───────────────────────
--    Computed at upload time, verified on every download.
--    Existing rows stay NULL — serve_document.php skips the check
--    for NULL rows (correct: we can't retroactively hash old files).
ALTER TABLE `documents`
    ADD COLUMN IF NOT EXISTS `file_hash` CHAR(64) NULL
        COMMENT 'SHA-256 hex digest computed at upload; verified on download'
    AFTER `doc_id`;

ALTER TABLE `documents`
    ADD INDEX IF NOT EXISTS `idx_file_hash` (`file_hash`);

-- ── 2. Audit trail columns on users ─────────────────────────────
--    Tracks last successful login time and originating IP.
--    Useful for detecting account sharing or suspicious access.
ALTER TABLE `users`
    ADD COLUMN IF NOT EXISTS `last_login_at` DATETIME NULL
        COMMENT 'Timestamp of most recent successful login',
    ADD COLUMN IF NOT EXISTS `last_login_ip` VARCHAR(45) NULL
        COMMENT 'IP address of most recent successful login';

-- ── 3. Download failure log ──────────────────────────────────────
--    Every rejected download attempt (bad token, wrong user,
--    integrity failure, etc.) is written here for admin review.
CREATE TABLE IF NOT EXISTS `download_failures` (
    `id`         INT UNSIGNED     AUTO_INCREMENT PRIMARY KEY,
    `user_id`    INT UNSIGNED     NOT NULL,
    `doc_id`     INT UNSIGNED     NULL,
    `ip_address` VARCHAR(45)      NOT NULL,
    `reason`     VARCHAR(120)     NOT NULL,
    `created_at` DATETIME         NOT NULL DEFAULT NOW(),
    INDEX `idx_user_time` (`user_id`, `created_at`),
    INDEX `idx_ip_time`   (`ip_address`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 4. PHP error log (optional) ──────────────────────────────────
--    Captures PHP errors to the DB so super-admins can review them
--    without needing server SSH access.
CREATE TABLE IF NOT EXISTS `php_error_log` (
    `id`         INT UNSIGNED     AUTO_INCREMENT PRIMARY KEY,
    `level`      VARCHAR(20)      NOT NULL,
    `message`    TEXT             NOT NULL,
    `file`       VARCHAR(300)     NULL,
    `line`       INT UNSIGNED     NULL,
    `url`        VARCHAR(500)     NULL,
    `user_id`    INT UNSIGNED     NULL,
    `ip_address` VARCHAR(45)      NULL,
    `created_at` DATETIME         NOT NULL DEFAULT NOW(),
    INDEX `idx_created` (`created_at`),
    INDEX `idx_level`   (`level`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 5. App settings for security constants ───────────────────────
--    These are read by configT.php as fallback defaults.
--    INSERT IGNORE means re-running this script won't overwrite
--    values you have already customised in the admin panel.
INSERT IGNORE INTO `app_settings` (`setting_key`, `setting_value`) VALUES
    ('secure_dl_token_ttl',  '900'),   -- signed URL lifetime in seconds (15 min)
    ('secure_dl_rate_limit', '30'),    -- max downloads per user per minute
    ('session_fingerprint',  '1'),     -- 1 = enable session hijack detection
    ('honeypot_enabled',     '1');     -- 1 = enable bot honeypot on auth forms

-- ── 6. Verification — confirm all columns exist ──────────────────
SELECT
    TABLE_NAME,
    COLUMN_NAME,
    COLUMN_TYPE,
    IS_NULLABLE,
    COLUMN_COMMENT
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND (
      (TABLE_NAME = 'documents' AND COLUMN_NAME = 'file_hash')
   OR (TABLE_NAME = 'users'     AND COLUMN_NAME IN ('last_login_at', 'last_login_ip'))
  )
ORDER BY TABLE_NAME, COLUMN_NAME;
-- ═══════════════════════════════════════════════════════════════════
-- Done. You should see 3 rows in the verification output above.
-- ═══════════════════════════════════════════════════════════════════
