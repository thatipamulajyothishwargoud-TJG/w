-- ─────────────────────────────────────────────────────────────────
-- CloudFen Security v2 — Migration
-- Run once in phpMyAdmin or MySQL CLI.
-- All ALTER TABLE statements use IF NOT EXISTS — safe to re-run.
-- ─────────────────────────────────────────────────────────────────

-- 1. users: add last_login_at and last_login_ip (used by login alert)
ALTER TABLE `users`
  ADD COLUMN IF NOT EXISTS `last_login_at` DATETIME    DEFAULT NULL AFTER `mfa_enabled`,
  ADD COLUMN IF NOT EXISTS `last_login_ip` VARCHAR(45) DEFAULT NULL AFTER `last_login_at`;

-- 2. sessions: add user_agent (used by session tracking)
ALTER TABLE `sessions`
  ADD COLUMN IF NOT EXISTS `user_agent` VARCHAR(300) DEFAULT NULL AFTER `ip_address`;

-- 3. download_failures: ensure created_at and ip index exist (for auto-block window query)
--    (column likely already exists; this is a safety net)
ALTER TABLE `download_failures`
  ADD COLUMN IF NOT EXISTS `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE `download_failures`
  ADD INDEX IF NOT EXISTS `idx_ip_created` (`ip_address`, `created_at`);

-- 4. blocked_ips: ensure reason column exists (schema already has it; safety net)
ALTER TABLE `blocked_ips`
  ADD COLUMN IF NOT EXISTS `reason` VARCHAR(500) DEFAULT NULL AFTER `ip_address`;

-- NOTE: blocked_ips does NOT have a blocked_by column — code has been
-- updated to not reference it.

-- ─────────────────────────────────────────────────────────────────
-- Done. Verify with:
--   DESCRIBE users;
--   DESCRIBE sessions;
--   DESCRIBE blocked_ips;
-- ─────────────────────────────────────────────────────────────────
