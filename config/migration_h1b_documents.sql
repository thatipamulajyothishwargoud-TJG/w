-- ============================================================
-- CloudFen — H1B Documents Migration
-- Run in cPanel → phpMyAdmin (select your database first)
-- Safe to re-run: uses CREATE TABLE IF NOT EXISTS
--
-- Shared document library (not per-employee): HR/Admin upload DOCX
-- files, all roles (employee, hr_admin, super_admin) may view/download.
-- ============================================================

CREATE TABLE IF NOT EXISTS `h1b_documents` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `document_name` VARCHAR(180) NOT NULL,
  `file_name`     VARCHAR(255) NOT NULL,
  `file_path`     VARCHAR(500) NOT NULL,
  `mime_type`     VARCHAR(150) NOT NULL DEFAULT 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  `file_size`     INT UNSIGNED NOT NULL DEFAULT 0,
  `file_hash`     CHAR(64)     DEFAULT NULL COMMENT 'SHA-256 hex digest — verified on every download',
  `uploaded_by`   INT UNSIGNED NOT NULL,
  `uploaded_at`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_h1bdoc_uploaded_by` (`uploaded_by`),
  KEY `idx_h1bdoc_uploaded_at` (`uploaded_at`),
  CONSTRAINT `fk_h1bdoc_uploaded_by` FOREIGN KEY (`uploaded_by`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
