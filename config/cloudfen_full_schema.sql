-- ============================================================
-- CloudFen HR Portal — COMPLETE DATABASE SETUP
-- Run this once in cPanel → phpMyAdmin
-- Select your database (e.g. bzx4bbckudfis8qg_portal) first.
--
-- SAFE TO RE-RUN: every statement uses IF NOT EXISTS.
-- New installs:     all tables and columns are created fresh.
-- Existing installs: only missing tables/columns are added.
-- ============================================================

SET SQL_MODE    = 'NO_AUTO_VALUE_ON_ZERO';
SET time_zone   = '+00:00';
SET FOREIGN_KEY_CHECKS = 0;

-- ─────────────────────────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `users` (
  `id`                    INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  `full_name`             VARCHAR(120)     NOT NULL,
  `email`                 VARCHAR(180)     NOT NULL UNIQUE,
  `phone`                 VARCHAR(25)      DEFAULT NULL,
  `password_hash`         VARCHAR(255)     NOT NULL,
  `role`                  ENUM('employee','hr_admin','super_admin') NOT NULL DEFAULT 'employee',
  `employee_type`         ENUM('W2','C2C','1099') DEFAULT NULL,
  `status`                ENUM('pending_verification','active','locked','deactivated') NOT NULL DEFAULT 'pending_verification',
  `email_verified`        TINYINT(1)       NOT NULL DEFAULT 0,
  `verify_token`          VARCHAR(100)     DEFAULT NULL,
  `verify_token_expiry`   DATETIME         DEFAULT NULL,
  `reset_token`           VARCHAR(100)     DEFAULT NULL,
  `reset_token_expiry`    DATETIME         DEFAULT NULL,
  `failed_logins`         TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `locked_until`          DATETIME         DEFAULT NULL,
  `employment_status`     ENUM('active','on_leave','offboarded') DEFAULT 'active',
  `start_date`            DATE             DEFAULT NULL,
  `end_date`              DATE             DEFAULT NULL,
  `date_of_birth`         DATE             DEFAULT NULL,
  `address`               TEXT             DEFAULT NULL,
  `emergency_contact`     VARCHAR(200)     DEFAULT NULL,
  `ssn_last4`             CHAR(4)          DEFAULT NULL,
  `profile_photo`         VARCHAR(255)     DEFAULT NULL,
  `mfa_enabled`           TINYINT(1)       NOT NULL DEFAULT 0,
  `force_password_change` TINYINT(1)       NOT NULL DEFAULT 0 COMMENT '1 = must change temp password on next login',
  `last_login_at`         DATETIME         DEFAULT NULL,
  `last_login_ip`         VARCHAR(45)      DEFAULT NULL,
  `created_at`            DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`            DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_users_email`  (`email`),
  KEY `idx_users_role`   (`role`),
  KEY `idx_users_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Patch columns that may be missing on existing installs
ALTER TABLE `users`
  ADD COLUMN IF NOT EXISTS `end_date`              DATE       DEFAULT NULL        AFTER `start_date`,
  ADD COLUMN IF NOT EXISTS `date_of_birth`         DATE       DEFAULT NULL        AFTER `end_date`,
  ADD COLUMN IF NOT EXISTS `force_password_change` TINYINT(1) NOT NULL DEFAULT 0  AFTER `mfa_enabled`,
  ADD COLUMN IF NOT EXISTS `last_login_at`         DATETIME   DEFAULT NULL        AFTER `force_password_change`,
  ADD COLUMN IF NOT EXISTS `last_login_ip`         VARCHAR(45) DEFAULT NULL       AFTER `last_login_at`;

-- ─────────────────────────────────────────────────────────────
-- DOCUMENTS  (employee personal compliance documents)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `documents` (
  `id`                INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`           INT UNSIGNED NOT NULL,
  `doc_type`          ENUM('drivers_license','i9','passport','work_authorization','h1b_i797','social_security','education','direct_deposit','other') NOT NULL,
  `document_name`     VARCHAR(180) NULL,
  `file_name`         VARCHAR(255) NOT NULL,
  `file_path`         VARCHAR(500) NOT NULL,
  `file_size`         INT UNSIGNED NOT NULL,
  `mime_type`         VARCHAR(100) NOT NULL,
  `doc_id`            VARCHAR(36)  NOT NULL UNIQUE,
  `file_hash`         CHAR(64)     DEFAULT NULL COMMENT 'SHA-256 hex digest — verified on every download',
  `status`            ENUM('missing','pending','approved','rejected','more_info_needed') NOT NULL DEFAULT 'pending',
  `rejection_reason`  TEXT         DEFAULT NULL,
  `reviewed_by`       INT UNSIGNED DEFAULT NULL,
  `reviewed_at`       DATETIME     DEFAULT NULL,
  `expiry_date`       DATE         DEFAULT NULL,
  `expiry_alerted_60` TINYINT(1)   NOT NULL DEFAULT 0,
  `expiry_alerted_30` TINYINT(1)   NOT NULL DEFAULT 0,
  `uploaded_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_docs_user_id`  (`user_id`),
  KEY `idx_docs_doc_type` (`doc_type`),
  KEY `idx_docs_status`   (`status`),
  KEY `idx_docs_doc_id`   (`doc_id`),
  CONSTRAINT `fk_docs_user`     FOREIGN KEY (`user_id`)    REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_docs_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- EMPLOYEE PROJECT DOCUMENTS  (MSA / PO / PROJECT files)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `employee_documents` (
  `id`                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `employee_id`          INT UNSIGNED NOT NULL,
  `project_id`           INT UNSIGNED DEFAULT NULL,
  `document_type`        ENUM('MSA','PO','PROJECT') NOT NULL,
  `file_name`            VARCHAR(255) NOT NULL,
  `file_path`            VARCHAR(500) NOT NULL,
  `mime_type`            VARCHAR(100) NOT NULL DEFAULT 'application/octet-stream',
  `file_size`            INT UNSIGNED NOT NULL DEFAULT 0,
  `file_hash`            CHAR(64)     DEFAULT NULL,
  `description`          TEXT         DEFAULT NULL,
  `status`               ENUM('pending','approved','rejected') NOT NULL DEFAULT 'approved',
  `uploaded_by`          INT UNSIGNED NOT NULL,
  `replaced_document_id` INT UNSIGNED DEFAULT NULL,
  `version_no`           INT UNSIGNED NOT NULL DEFAULT 1,
  `is_current`           TINYINT(1)   NOT NULL DEFAULT 1,
  `uploaded_at`          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`           DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_empdoc_employee`    (`employee_id`),
  KEY `idx_empdoc_type`        (`document_type`),
  KEY `idx_empdoc_current`     (`employee_id`, `document_type`, `is_current`),
  KEY `idx_empdoc_uploaded_by` (`uploaded_by`),
  CONSTRAINT `fk_empdoc_employee`    FOREIGN KEY (`employee_id`)          REFERENCES `users`(`id`)             ON DELETE CASCADE,
  CONSTRAINT `fk_empdoc_uploaded_by` FOREIGN KEY (`uploaded_by`)          REFERENCES `users`(`id`)             ON DELETE CASCADE,
  CONSTRAINT `fk_empdoc_replaced`    FOREIGN KEY (`replaced_document_id`) REFERENCES `employee_documents`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Patch columns that may be missing on existing installs
ALTER TABLE `employee_documents`
  ADD COLUMN IF NOT EXISTS `project_id`           INT UNSIGNED DEFAULT NULL                              AFTER `employee_id`,
  ADD COLUMN IF NOT EXISTS `mime_type`            VARCHAR(100) NOT NULL DEFAULT 'application/octet-stream' AFTER `file_path`,
  ADD COLUMN IF NOT EXISTS `file_size`            INT UNSIGNED NOT NULL DEFAULT 0                          AFTER `mime_type`,
  ADD COLUMN IF NOT EXISTS `file_hash`            CHAR(64)     DEFAULT NULL                               AFTER `file_size`,
  ADD COLUMN IF NOT EXISTS `description`          TEXT         DEFAULT NULL                               AFTER `file_hash`,
  ADD COLUMN IF NOT EXISTS `status`               ENUM('pending','approved','rejected') NOT NULL DEFAULT 'approved' AFTER `description`,
  ADD COLUMN IF NOT EXISTS `replaced_document_id` INT UNSIGNED DEFAULT NULL                              AFTER `uploaded_by`,
  ADD COLUMN IF NOT EXISTS `version_no`           INT UNSIGNED NOT NULL DEFAULT 1                        AFTER `replaced_document_id`,
  ADD COLUMN IF NOT EXISTS `is_current`           TINYINT(1)   NOT NULL DEFAULT 1                       AFTER `version_no`,
  ADD COLUMN IF NOT EXISTS `updated_at`           DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER `uploaded_at`;

-- ADD COLUMN IF NOT EXISTS is a no-op on installs where `document_type` already
-- exists with an older enum (e.g. missing 'PROJECT'), so widen it explicitly —
-- this previously caused "Data truncated for column 'document_type'" on insert.
ALTER TABLE `employee_documents`
  MODIFY COLUMN `document_type` ENUM('MSA','PO','PROJECT') NOT NULL;

-- ─────────────────────────────────────────────────────────────
-- H1B DOCUMENTS  (shared library — HR/Admin upload, all roles view)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `document_categories` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`       VARCHAR(100) NOT NULL,
  `created_by` INT UNSIGNED NOT NULL,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_doc_cat_name` (`name`),
  CONSTRAINT `fk_doc_cat_created_by` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `h1b_documents` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `document_name` VARCHAR(180) NOT NULL,
  `category_id`   INT UNSIGNED NOT NULL,
  `file_name`     VARCHAR(255) NOT NULL,
  `file_path`     VARCHAR(500) NOT NULL,
  `mime_type`     VARCHAR(150) NOT NULL DEFAULT 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  `file_size`     INT UNSIGNED NOT NULL DEFAULT 0,
  `file_hash`     CHAR(64)     DEFAULT NULL,
  `uploaded_by`   INT UNSIGNED NOT NULL,
  `uploaded_at`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_h1bdoc_uploaded_by` (`uploaded_by`),
  KEY `idx_h1bdoc_uploaded_at` (`uploaded_at`),
  KEY `idx_h1bdoc_category` (`category_id`),
  CONSTRAINT `fk_h1bdoc_uploaded_by` FOREIGN KEY (`uploaded_by`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_h1bdoc_category` FOREIGN KEY (`category_id`) REFERENCES `document_categories`(`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- PROJECTS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `projects` (
  `id`               INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  `employee_id`      INT UNSIGNED  NOT NULL,
  `client_name`      VARCHAR(120)  NOT NULL,
  `project_name`     VARCHAR(120)  NOT NULL,
  `invoicing_email`  VARCHAR(180)  DEFAULT NULL,
  `phone_number`     VARCHAR(30)   DEFAULT NULL,
  `point_of_contact` VARCHAR(120)  DEFAULT NULL,
  `billing_rate`     DECIMAL(10,2) DEFAULT NULL,
  `net_days`         INT UNSIGNED  DEFAULT NULL,
  `created_by`       INT UNSIGNED  NOT NULL,
  `created_at`       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_proj_employee` (`employee_id`),
  KEY `idx_proj_name`     (`project_name`),
  CONSTRAINT `fk_proj_employee`   FOREIGN KEY (`employee_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_proj_created_by` FOREIGN KEY (`created_by`)  REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- TIMESHEETS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `timesheets` (
  `id`               INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`          INT UNSIGNED NOT NULL,
  `week_start`       DATE         NOT NULL,
  `mon_hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `tue_hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `wed_hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `thu_hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `fri_hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `sat_hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `sun_hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `total_hours`      DECIMAL(5,1) GENERATED ALWAYS AS (`mon_hours`+`tue_hours`+`wed_hours`+`thu_hours`+`fri_hours`+`sat_hours`+`sun_hours`) STORED,
  `notes`            TEXT         DEFAULT NULL,
  `project_code`     VARCHAR(100) DEFAULT NULL,
  `status`           ENUM('draft','pending','approved','rejected') NOT NULL DEFAULT 'draft',
  `is_overtime`      TINYINT(1)   GENERATED ALWAYS AS (`total_hours` > 40) STORED,
  `rejection_reason` TEXT         DEFAULT NULL,
  `submitted_at`     DATETIME     DEFAULT NULL,
  `reviewed_by`      INT UNSIGNED DEFAULT NULL,
  `reviewed_at`      DATETIME     DEFAULT NULL,
  `created_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ts_user_week` (`user_id`, `week_start`),
  KEY `idx_ts_status`          (`status`),
  KEY `idx_ts_week_start`      (`week_start`),
  KEY `idx_ts_user_week`       (`user_id`, `week_start`),
  CONSTRAINT `fk_ts_user`     FOREIGN KEY (`user_id`)    REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ts_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- TIMESHEET ENTRIES  (per-project / per-task rows)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `timesheet_entries` (
  `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `timesheet_id` INT UNSIGNED NOT NULL,
  `project`      VARCHAR(100) NOT NULL,
  `task`         VARCHAR(100) NOT NULL,
  `hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `description`  VARCHAR(500) DEFAULT NULL,
  `created_at`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_te_timesheet_id` (`timesheet_id`),
  CONSTRAINT `fk_te_timesheet` FOREIGN KEY (`timesheet_id`) REFERENCES `timesheets`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- TIMESHEET ATTACHMENTS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `timesheet_attachments` (
  `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `timesheet_id` INT UNSIGNED NOT NULL,
  `user_id`      INT UNSIGNED NOT NULL,
  `file_name`    VARCHAR(255) NOT NULL,
  `file_path`    VARCHAR(500) NOT NULL,
  `file_size`    INT UNSIGNED NOT NULL DEFAULT 0,
  `mime_type`    VARCHAR(100) NOT NULL DEFAULT 'application/octet-stream',
  `created_at`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_ta_timesheet` (`timesheet_id`),
  KEY `idx_ta_user`      (`user_id`),
  CONSTRAINT `fk_ta_timesheet` FOREIGN KEY (`timesheet_id`) REFERENCES `timesheets`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ta_user`      FOREIGN KEY (`user_id`)      REFERENCES `users`(`id`)      ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- NOTIFICATIONS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `notifications` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`    INT UNSIGNED NOT NULL,
  `type`       VARCHAR(60)  NOT NULL,
  `title`      VARCHAR(200) NOT NULL,
  `message`    TEXT         NOT NULL,
  `link`       VARCHAR(300) DEFAULT NULL,
  `is_read`    TINYINT(1)   NOT NULL DEFAULT 0,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_notif_user`      (`user_id`),
  KEY `idx_notif_is_read`   (`is_read`),
  KEY `idx_notif_user_read` (`user_id`, `is_read`),
  CONSTRAINT `fk_notif_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- BIRTHDAY NOTIFICATION SEND LOG
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `birthday_notifications_sent` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `birthday_user_id`  INT UNSIGNED    NOT NULL,
  `recipient_user_id` INT UNSIGNED    NOT NULL,
  `sent_on`           DATE            NOT NULL,
  `created_at`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_birthday_sent`  (`birthday_user_id`, `recipient_user_id`, `sent_on`),
  KEY `idx_bday_sent_on`         (`sent_on`),
  CONSTRAINT `fk_bday_birthday_user`  FOREIGN KEY (`birthday_user_id`)  REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_bday_recipient_user` FOREIGN KEY (`recipient_user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- AUDIT LOG
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`     INT UNSIGNED    DEFAULT NULL,
  `action`      VARCHAR(100)    NOT NULL,
  `resource`    VARCHAR(100)    DEFAULT NULL,
  `resource_id` INT UNSIGNED    DEFAULT NULL,
  `details`     JSON            DEFAULT NULL,
  `ip_address`  VARCHAR(45)     DEFAULT NULL,
  `user_agent`  VARCHAR(300)    DEFAULT NULL,
  `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_al_user_id` (`user_id`),
  KEY `idx_al_action`  (`action`),
  KEY `idx_al_created` (`created_at`),
  KEY `idx_al_ip`      (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- DOCUMENT DOWNLOAD FAILURES  (feeds the auto-block system)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `download_failures` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`    INT UNSIGNED NOT NULL,
  `doc_id`     INT UNSIGNED DEFAULT NULL,
  `ip_address` VARCHAR(45)  NOT NULL,
  `reason`     VARCHAR(120) NOT NULL,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_df_user_time` (`user_id`, `created_at`),
  KEY `idx_df_ip_time`   (`ip_address`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- HR NOTES
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `hr_notes` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `employee_id` INT UNSIGNED NOT NULL,
  `hr_user_id`  INT UNSIGNED NOT NULL,
  `note`        TEXT         NOT NULL,
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_hrnote_employee` (`employee_id`),
  CONSTRAINT `fk_hrnote_employee` FOREIGN KEY (`employee_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_hrnote_hr`       FOREIGN KEY (`hr_user_id`)  REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- SESSIONS  (active session tracking + concurrent-session limit)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `sessions` (
  `session_id`  VARCHAR(128) NOT NULL,
  `user_id`     INT UNSIGNED NOT NULL,
  `ip_address`  VARCHAR(45)  DEFAULT NULL,
  `user_agent`  VARCHAR(300) DEFAULT NULL,
  `last_active` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`session_id`),
  KEY `idx_sess_user_id` (`user_id`),
  CONSTRAINT `fk_sess_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Patch existing installs
ALTER TABLE `sessions`
  ADD COLUMN IF NOT EXISTS `user_agent` VARCHAR(300) DEFAULT NULL AFTER `ip_address`;

-- ─────────────────────────────────────────────────────────────
-- CLIENT TIMESHEETS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `client_timesheets` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `client_name` VARCHAR(120) NOT NULL,
  `week_start`  DATE         NOT NULL,
  `file_name`   VARCHAR(255) NOT NULL,
  `file_path`   VARCHAR(500) NOT NULL,
  `file_size`   INT UNSIGNED NOT NULL,
  `notes`       TEXT         DEFAULT NULL,
  `uploaded_by` INT UNSIGNED NOT NULL,
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_cts_week_start`  (`week_start`),
  KEY `idx_cts_client_name` (`client_name`),
  CONSTRAINT `fk_cts_uploader` FOREIGN KEY (`uploaded_by`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- RATE LIMIT
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `rate_limit` (
  `key`        VARCHAR(200) NOT NULL,
  `attempts`   INT UNSIGNED NOT NULL DEFAULT 1,
  `expires_at` DATETIME     NOT NULL,
  PRIMARY KEY (`key`),
  KEY `idx_rl_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- BLOCKED IPs
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `blocked_ips` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip_address` VARCHAR(45)  NOT NULL UNIQUE,
  `reason`     VARCHAR(500) DEFAULT NULL,
  `blocked_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` DATETIME     DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_bip_ip`         (`ip_address`),
  KEY `idx_bip_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Patch existing installs (older schema had VARCHAR(255) reason; no blocked_by column)
ALTER TABLE `blocked_ips`
  ADD COLUMN IF NOT EXISTS `reason`     VARCHAR(500) DEFAULT NULL AFTER `ip_address`,
  ADD COLUMN IF NOT EXISTS `expires_at` DATETIME     DEFAULT NULL AFTER `blocked_at`,
  ADD INDEX  IF NOT EXISTS `idx_bip_expires_at` (`expires_at`);

-- ─────────────────────────────────────────────────────────────
-- CRON LOG
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `cron_log` (
  `id`           INT UNSIGNED      NOT NULL AUTO_INCREMENT,
  `triggered_by` ENUM('web_hook','manual_hr','auto_visit') NOT NULL DEFAULT 'web_hook',
  `triggered_ip` VARCHAR(45)       DEFAULT NULL,
  `tasks_run`    TEXT              DEFAULT NULL,
  `emails_sent`  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `errors`       TEXT              DEFAULT NULL,
  `duration_ms`  INT UNSIGNED      DEFAULT NULL,
  `ran_at`       DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_cron_ran_at` (`ran_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────
-- APP SETTINGS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `app_settings` (
  `setting_key`   VARCHAR(80) NOT NULL,
  `setting_value` TEXT        DEFAULT NULL,
  `updated_at`    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default settings — INSERT IGNORE skips if already exists
INSERT IGNORE INTO `app_settings` (`setting_key`, `setting_value`)
VALUES ('cron_secret', 'CHANGE_THIS_SECRET_BEFORE_GOING_LIVE');

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================
-- DONE.  All tables and columns are in place.
--
-- New install — create your first HR admin:
--   INSERT INTO `users`
--     (full_name, email, password_hash, role, status, email_verified)
--   VALUES
--     ('HR Admin', 'hr@yourdomain.com',
--      '$2y$12$REPLACE_WITH_REAL_BCRYPT_HASH', 'hr_admin', 'active', 1);
-- ============================================================
