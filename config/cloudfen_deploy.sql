-- ============================================================
-- CloudFen HR Portal — MASTER DEPLOYMENT SCHEMA
-- Generated: fresh-install only, safe to run on a blank database
--
-- HOW TO RUN:
--   cPanel → phpMyAdmin → select your database → Import this file
--
-- WHAT'S INCLUDED:
--   All 20 tables in FK-safe order, all columns (no ALTER patches
--   needed), all seed data for app_settings + job_openings.
--
-- All statements use CREATE TABLE IF NOT EXISTS + INSERT IGNORE
--   so the file is safe to re-run without data loss.
-- ============================================================

SET SQL_MODE        = 'NO_AUTO_VALUE_ON_ZERO';
SET time_zone       = '+00:00';
SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================
-- 1. USERS  (base table — referenced by almost everything)
-- ============================================================
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
  `force_password_change` TINYINT(1)       NOT NULL DEFAULT 0
    COMMENT '1 = user must change temp password on next login',
  `last_login_at`         DATETIME         DEFAULT NULL
    COMMENT 'Timestamp of most recent successful login',
  `last_login_ip`         VARCHAR(45)      DEFAULT NULL
    COMMENT 'IP address of most recent successful login',
  `created_at`            DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`            DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_email`  (`email`),
  KEY `idx_role`   (`role`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 2. DOCUMENTS  (employee onboarding docs)
-- ============================================================
CREATE TABLE IF NOT EXISTS `documents` (
  `id`                INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`           INT UNSIGNED NOT NULL,
  `doc_type`          ENUM('drivers_license','i9','passport','work_authorization',
                           'h1b_i797','social_security','education','direct_deposit','other') NOT NULL,
  `document_name`     VARCHAR(180) NULL,
  `file_name`         VARCHAR(255) NOT NULL,
  `file_path`         VARCHAR(500) NOT NULL,
  `file_size`         INT UNSIGNED NOT NULL,
  `mime_type`         VARCHAR(100) NOT NULL,
  `doc_id`            VARCHAR(36)  NOT NULL UNIQUE,
  `file_hash`         CHAR(64)     DEFAULT NULL
    COMMENT 'SHA-256 hex digest computed at upload; verified on every download',
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
  KEY `idx_user_id`   (`user_id`),
  KEY `idx_doc_type`  (`doc_type`),
  KEY `idx_status`    (`status`),
  KEY `idx_doc_id`    (`doc_id`),
  KEY `idx_file_hash` (`file_hash`),
  CONSTRAINT `fk_docs_user`     FOREIGN KEY (`user_id`)     REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_docs_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 3. EMPLOYEE PROJECT DOCUMENTS  (MSA / PO / PROJECT files)
-- ============================================================
CREATE TABLE IF NOT EXISTS `employee_documents` (
  `id`                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `employee_id`          INT UNSIGNED NOT NULL,
  `project_id`           INT UNSIGNED DEFAULT NULL
    COMMENT 'Scope version/is_current to a specific project when set',
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
  KEY `idx_emp_docs_employee`    (`employee_id`),
  KEY `idx_emp_docs_type`        (`document_type`),
  KEY `idx_emp_docs_current`     (`employee_id`, `document_type`, `is_current`),
  KEY `idx_emp_docs_uploaded_by` (`uploaded_by`),
  CONSTRAINT `fk_emp_docs_employee`    FOREIGN KEY (`employee_id`)          REFERENCES `users`(`id`)             ON DELETE CASCADE,
  CONSTRAINT `fk_emp_docs_uploaded_by` FOREIGN KEY (`uploaded_by`)          REFERENCES `users`(`id`)             ON DELETE CASCADE,
  CONSTRAINT `fk_emp_docs_replaced`    FOREIGN KEY (`replaced_document_id`) REFERENCES `employee_documents`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 3b. H1B DOCUMENTS  (shared library — HR/Admin upload, all roles view)
-- ============================================================
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

-- ============================================================
-- 4. PROJECTS
-- ============================================================
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
  KEY `idx_projects_employee` (`employee_id`),
  KEY `idx_projects_name`     (`project_name`),
  CONSTRAINT `fk_projects_employee`   FOREIGN KEY (`employee_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_projects_created_by` FOREIGN KEY (`created_by`)  REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 5. TIMESHEETS
-- ============================================================
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
  `total_hours`      DECIMAL(5,1) GENERATED ALWAYS AS
                       (`mon_hours`+`tue_hours`+`wed_hours`+`thu_hours`+
                        `fri_hours`+`sat_hours`+`sun_hours`) STORED,
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
  UNIQUE KEY `uq_user_week`  (`user_id`, `week_start`),
  KEY `idx_status`           (`status`),
  KEY `idx_week_start`       (`week_start`),
  KEY `idx_ts_user_week`     (`user_id`, `week_start`),
  CONSTRAINT `fk_ts_user`     FOREIGN KEY (`user_id`)    REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ts_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 6. TIMESHEET ENTRIES  (project / task level breakdown)
-- ============================================================
CREATE TABLE IF NOT EXISTS `timesheet_entries` (
  `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `timesheet_id` INT UNSIGNED NOT NULL,
  `project`      VARCHAR(100) NOT NULL,
  `task`         VARCHAR(100) NOT NULL,
  `hours`        DECIMAL(4,1) NOT NULL DEFAULT 0,
  `description`  VARCHAR(500) DEFAULT NULL,
  `created_at`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_timesheet_id` (`timesheet_id`),
  CONSTRAINT `fk_te_timesheet` FOREIGN KEY (`timesheet_id`) REFERENCES `timesheets`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 7. TIMESHEET ATTACHMENTS
-- ============================================================
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

-- ============================================================
-- 8. CLIENT TIMESHEETS  (HR-uploaded external timesheets)
-- ============================================================
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
  KEY `idx_week_start`  (`week_start`),
  KEY `idx_client_name` (`client_name`),
  CONSTRAINT `fk_cts_uploader` FOREIGN KEY (`uploaded_by`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 9. NOTIFICATIONS
-- ============================================================
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
  KEY `idx_notif_user_id`   (`user_id`),
  KEY `idx_notif_is_read`   (`is_read`),
  KEY `idx_notif_user_read` (`user_id`, `is_read`),
  CONSTRAINT `fk_notif_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 10. BIRTHDAY NOTIFICATIONS SENT LOG
-- ============================================================
CREATE TABLE IF NOT EXISTS `birthday_notifications_sent` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `birthday_user_id`  INT UNSIGNED    NOT NULL,
  `recipient_user_id` INT UNSIGNED    NOT NULL,
  `sent_on`           DATE            NOT NULL,
  `created_at`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_birthday_sent` (`birthday_user_id`, `recipient_user_id`, `sent_on`),
  KEY `idx_bday_sent_on` (`sent_on`),
  CONSTRAINT `fk_bday_birthday_user`   FOREIGN KEY (`birthday_user_id`)  REFERENCES `users`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_bday_recipient_user`  FOREIGN KEY (`recipient_user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 11. HR NOTES
-- ============================================================
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

-- ============================================================
-- 12. SESSIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS `sessions` (
  `session_id`  VARCHAR(128) NOT NULL,
  `user_id`     INT UNSIGNED NOT NULL,
  `ip_address`  VARCHAR(45)  DEFAULT NULL,
  `last_active` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`session_id`),
  KEY `idx_sess_user_id` (`user_id`),
  CONSTRAINT `fk_sess_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 13. AUDIT LOG
-- ============================================================
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
  KEY `idx_audit_user_id` (`user_id`),
  KEY `idx_audit_action`  (`action`),
  KEY `idx_audit_created` (`created_at`),
  KEY `idx_audit_ip`      (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 14. DOWNLOAD FAILURES
-- ============================================================
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

-- ============================================================
-- 15. PHP ERROR LOG  (super-admin review without SSH access)
-- ============================================================
CREATE TABLE IF NOT EXISTS `php_error_log` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `level`      VARCHAR(20)  NOT NULL,
  `message`    TEXT         NOT NULL,
  `file`       VARCHAR(300) DEFAULT NULL,
  `line`       INT UNSIGNED DEFAULT NULL,
  `url`        VARCHAR(500) DEFAULT NULL,
  `user_id`    INT UNSIGNED DEFAULT NULL,
  `ip_address` VARCHAR(45)  DEFAULT NULL,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_phperr_created` (`created_at`),
  KEY `idx_phperr_level`   (`level`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 16. RATE LIMIT
-- ============================================================
CREATE TABLE IF NOT EXISTS `rate_limit` (
  `key`        VARCHAR(200) NOT NULL,
  `attempts`   INT UNSIGNED NOT NULL DEFAULT 1,
  `expires_at` DATETIME     NOT NULL,
  PRIMARY KEY (`key`),
  KEY `idx_rl_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- 17. BLOCKED IPs
-- ============================================================
CREATE TABLE IF NOT EXISTS `blocked_ips` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip_address` VARCHAR(45)  NOT NULL UNIQUE,
  `reason`     VARCHAR(255) DEFAULT NULL,
  `blocked_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` DATETIME     DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_bip_ip` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 18. CRON LOG
-- ============================================================
CREATE TABLE IF NOT EXISTS `cron_log` (
  `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
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

-- ============================================================
-- 19. APP SETTINGS
-- ============================================================
CREATE TABLE IF NOT EXISTS `app_settings` (
  `setting_key`   VARCHAR(80) NOT NULL,
  `setting_value` TEXT        DEFAULT NULL,
  `updated_at`    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed all default settings in one statement (safe to re-run)
INSERT IGNORE INTO `app_settings` (`setting_key`, `setting_value`) VALUES
  ('cron_secret',         'CHANGE_THIS_SECRET_BEFORE_GOING_LIVE'),
  ('secure_dl_token_ttl', '900'),   -- signed URL lifetime in seconds (15 min)
  ('secure_dl_rate_limit','30'),    -- max downloads per user per minute
  ('session_fingerprint', '1'),     -- 1 = enable session hijack detection
  ('honeypot_enabled',    '1');     -- 1 = enable bot honeypot on auth forms

-- ============================================================
-- 20. JOB OPENINGS  (public job board — managed via HR portal)
-- ============================================================
CREATE TABLE IF NOT EXISTS `job_openings` (
  `id`              INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  `title`           VARCHAR(120)     NOT NULL,
  `employment_type` VARCHAR(60)      NOT NULL DEFAULT 'Full Time',
  `location`        VARCHAR(120)     NOT NULL,
  `description`     TEXT             NOT NULL,
  `posted_date`     DATE             DEFAULT NULL,
  `status`          ENUM('active','inactive') NOT NULL DEFAULT 'active',
  `created_by`      INT UNSIGNED     DEFAULT NULL COMMENT 'FK to users.id',
  `updated_by`      INT UNSIGNED     DEFAULT NULL COMMENT 'FK to users.id',
  `created_at`      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_jo_status`     (`status`),
  KEY `idx_jo_created_at` (`created_at`),
  KEY `idx_jo_created_by` (`created_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Dynamic job openings managed via HR Portal admin';

-- Seed all 9 original job openings (INSERT IGNORE = safe to re-run)
INSERT IGNORE INTO `job_openings`
  (`id`, `title`, `employment_type`, `location`, `description`, `posted_date`, `status`, `created_at`)
VALUES
(1,'Senior Engineers - RF','Full Time','Alpharetta, GA',
'<ul><li><b>Title: Senior Engineers - RF</b></li><li>Responsible to design, gathering requirements, configuring, implementation and troubleshooting of optimize innovative RF, Wireless networks like Smartsky Networks products utilizing Cisco Command line, LINUX, Python, XML, Xshell, Network Monitoring tools, Wireshark, NetMon, Matlab, LTE optimization tools etc.</li><li>Provide technical expertise to design and develop Network Topology utilizing IP addressing, IP subnetting, DHCP, QoS policy, Access-lists, SNMP, VLANs, VIPs, BGP, OSPF, LTE devices (Base Band Unit, Remote Radio Head) etc.</li><li>Responsible for troubleshooting, diagnosing, and resolving hardware, software, and other network and system problems.</li><li><b>Requirements:</b></li><li>MS or foreign equivalent in Computer Science / Information Technology / Engineering</li><li>Related and 3 years of experience in RF and wireless networks, including planning, designing, site integration, and performance testing</li><li><b>Location:</b> Alpharetta, GA. Full Time. Travel involved to client locations within the US.</li></ul>',
'2023-07-17','active','2023-07-17 00:00:00'),

(2,'Systems Architect','Full Time','Various, US',
'<ul><li>Design and implement enterprise-scale system architectures.</li><li>Collaborate with stakeholders to define technical requirements.</li><li>Guide development teams on best practices and architectural decisions.</li><li><b>Requirements:</b> 8+ years experience in systems architecture, cloud platforms (AWS/Azure/GCP), microservices design patterns.</li></ul>',
'2023-01-01','active','2023-01-01 00:00:00'),

(3,'Senior Software Engineer','Full Time, Travel/Relocation','Cumming, GA',
'<ul><li>Design, develop, and maintain scalable software solutions.</li><li>Collaborate with cross-functional teams.</li><li>Perform code reviews and mentor junior developers.</li><li><b>Requirements:</b> 5+ years software engineering experience, proficiency in Java/Python/React.</li></ul>',
'2023-01-01','active','2023-01-01 00:00:01'),

(4,'Full Stack Developer (Angular)','Full Time','West Palm Beach, FL',
'<ul><li>Develop and maintain full-stack web applications using Angular and Node.js.</li><li>Design RESTful APIs and integrate with backend services.</li><li><b>Requirements:</b> 3+ years Angular experience, strong TypeScript and CSS skills.</li></ul>',
'2023-01-01','active','2023-01-01 00:00:02'),

(5,'Network Engineers','Contract, Full Time','Alpharetta, GA',
'<ul><li>Design, implement and maintain enterprise network infrastructure.</li><li>Troubleshoot complex network issues across LAN/WAN environments.</li><li><b>Requirements:</b> CCNA/CCNP certification preferred, 3+ years networking experience.</li></ul>',
'2023-01-01','active','2023-01-01 00:00:03'),

(6,'Data Science','Contract, Full Time','New York, NY',
'<ul><li>Analyze large datasets to extract actionable business insights.</li><li>Build predictive models using ML algorithms.</li><li><b>Requirements:</b> Python, R, SQL, experience with pandas/scikit-learn/TensorFlow. MS in Data Science or related field.</li></ul>',
'2023-01-01','active','2023-01-01 00:00:04'),

(7,'Machine Learning','Full Time','Jersey City, NJ',
'<ul><li>Research and implement machine learning models for production systems.</li><li>Optimize model performance and scalability.</li><li><b>Requirements:</b> PhD or MS in CS/Math/Statistics, 2+ years ML experience, PyTorch/TensorFlow.</li></ul>',
'2023-01-01','active','2023-01-01 00:00:05'),

(8,'Cyber Security','Contract, Full Time','San Antonio, TX',
'<ul><li>Monitor and protect organizational systems from cyber threats.</li><li>Conduct vulnerability assessments and penetration testing.</li><li><b>Requirements:</b> CISSP or CEH certification preferred, 3+ years in cybersecurity, experience with SIEM tools.</li></ul>',
'2023-01-01','active','2023-01-01 00:00:06'),

(9,'Java Developer','Contract, Full Time','Minneapolis, MN',
'<ul><li>3+ years Java and server side development.</li><li>Strong problem solving and computer science fundamentals.</li><li>Strong database fundamentals, understanding of relational and NoSQL tradeoffs.</li><li>Azure is big plus.</li><li>Git, great presentation skills.</li><li>Design and develop reliable number crunching software.</li><li>Produce high quality maintainable code.</li></ul>',
'2023-01-01','active','2023-01-01 00:00:07');

-- ============================================================
SET FOREIGN_KEY_CHECKS = 1;
-- ============================================================
-- DONE — 20 tables created, all seed data inserted.
--
-- NEXT STEP: Create your first super_admin account.
-- Either register through the portal, or run:
--
-- INSERT INTO `users`
--   (full_name, email, password_hash, role, status, email_verified, force_password_change)
-- VALUES
--   ('HR Admin', 'hr@cloudfen.com',
--    '$2y$12$REPLACE_WITH_REAL_BCRYPT_HASH', 'super_admin', 'active', 1, 1);
--
-- Generate a bcrypt hash with: php -r "echo password_hash('YourPassword', PASSWORD_BCRYPT, ['cost'=>12]);"
-- IMPORTANT: Change cron_secret in app_settings before going live!
-- ============================================================
