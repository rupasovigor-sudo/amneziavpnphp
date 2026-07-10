-- =====================================================================
-- Migration 093: common.back translation for the global back button
-- =====================================================================
-- Idempotent upsert; other locales fall back to English.
-- =====================================================================

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en','common','back','Back'),
('ru','common','back','Назад')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);
