-- ============================================================
-- CloudFen — Job Openings Table Migration
-- Run in cPanel → phpMyAdmin (select your database first)
-- Safe to re-run: uses CREATE TABLE IF NOT EXISTS
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
  KEY `idx_status`     (`status`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_created_by` (`created_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Dynamic job openings managed via HR Portal admin';

-- Optional: add FK constraints if you want strict referential integrity
-- ALTER TABLE `job_openings`
--   ADD CONSTRAINT `fk_jo_created_by` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
--   ADD CONSTRAINT `fk_jo_updated_by` FOREIGN KEY (`updated_by`) REFERENCES `users`(`id`) ON DELETE SET NULL;
