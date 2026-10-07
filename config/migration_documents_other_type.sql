-- ============================================================
-- CloudFen — "Other" Personal Document Type Migration
-- Run in cPanel → phpMyAdmin (select your database first)
-- Safe to re-run: every statement is idempotent.
--
-- Adds an 'other' value to the documents.doc_type ENUM so
-- employees (and HR/super admin on their behalf) can submit an
-- unlimited number of supplementary documents (educational
-- certificates, etc), each with a free-text title stored in the
-- new document_name column. 'other' documents are NOT part of
-- mandatoryOnboardingDocTypes() and do not replace one another
-- on re-upload the way the fixed document types do.
-- ============================================================

ALTER TABLE documents
  MODIFY COLUMN doc_type ENUM(
    'drivers_license','i9','passport','work_authorization','h1b_i797',
    'social_security','education','direct_deposit','other'
  ) NOT NULL;

ALTER TABLE documents ADD COLUMN IF NOT EXISTS document_name VARCHAR(180) NULL AFTER doc_type;
