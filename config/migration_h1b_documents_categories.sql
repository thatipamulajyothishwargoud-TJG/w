-- ============================================================
-- CloudFen — Dynamic Document Categories Migration
-- Run in cPanel → phpMyAdmin (select your database first)
-- Safe to re-run: every statement is idempotent.
--
-- Upgrades the shared document library (previously fixed "H1B
-- Documents") so Admin/HR can create unlimited categories
-- (H1B, I-140, PERM, Passport, etc). Existing documents are
-- backfilled into a seeded "H1B" category so nothing is lost.
-- Must run AFTER migration_h1b_documents.sql (creates the table
-- this one alters) — filename sorts after it alphabetically so
-- the automated runner applies them in the correct order.
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

-- Seed a default "H1B" category (owned by the earliest super_admin) so
-- existing h1b_documents rows have somewhere to land.
INSERT INTO document_categories (name, created_by)
SELECT 'H1B', (SELECT id FROM users WHERE role = 'super_admin' ORDER BY id ASC LIMIT 1)
WHERE NOT EXISTS (SELECT 1 FROM document_categories WHERE name = 'H1B')
  AND EXISTS (SELECT 1 FROM users WHERE role = 'super_admin');

ALTER TABLE h1b_documents ADD COLUMN IF NOT EXISTS category_id INT UNSIGNED NULL AFTER document_name;

UPDATE h1b_documents SET category_id = (SELECT id FROM document_categories WHERE name = 'H1B' LIMIT 1)
WHERE category_id IS NULL;

ALTER TABLE h1b_documents MODIFY COLUMN category_id INT UNSIGNED NOT NULL;

SET @fk_exists = (
  SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'h1b_documents'
    AND CONSTRAINT_NAME = 'fk_h1bdoc_category'
);
SET @sql = IF(@fk_exists = 0,
  'ALTER TABLE h1b_documents ADD CONSTRAINT fk_h1bdoc_category FOREIGN KEY (category_id) REFERENCES document_categories(id) ON DELETE RESTRICT',
  'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists = (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'h1b_documents'
    AND INDEX_NAME = 'idx_h1bdoc_category'
);
SET @sql = IF(@idx_exists = 0,
  'CREATE INDEX idx_h1bdoc_category ON h1b_documents (category_id)',
  'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
