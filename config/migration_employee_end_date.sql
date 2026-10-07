-- ============================================================
-- CloudFen — Employee End Date Migration
-- Run in cPanel → phpMyAdmin (select your database first)
-- Safe to re-run: uses ADD COLUMN IF NOT EXISTS
-- ============================================================

ALTER TABLE `users`
  ADD COLUMN IF NOT EXISTS `end_date` DATE DEFAULT NULL AFTER `start_date`;
