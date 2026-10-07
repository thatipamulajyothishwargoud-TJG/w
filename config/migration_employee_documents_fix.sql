-- ============================================================
-- CloudFen — employee_documents Column Fix
-- Run in cPanel → phpMyAdmin (select your database first)
-- Safe to re-run: uses ADD COLUMN IF NOT EXISTS / idempotent MODIFY COLUMN
--
-- Fixes two production errors seen in admin/error_log:
--   1. "Unknown column 'project_id'" — this install's employee_documents
--      table was created without it.
--   2. "Data truncated for column 'document_type'" — this install's enum
--      predates the 'PROJECT' value.
-- ============================================================

ALTER TABLE `employee_documents`
  ADD COLUMN IF NOT EXISTS `project_id` INT UNSIGNED DEFAULT NULL AFTER `employee_id`;

ALTER TABLE `employee_documents`
  MODIFY COLUMN `document_type` ENUM('MSA','PO','PROJECT') NOT NULL;
