-- =====================================================================
-- Migration 082: Add domain column to vpn_servers
-- =====================================================================
-- AmneziaWG 2.0 clients connect via a third-level domain (e.g.
-- awg.gptanalitika.com:443) instead of a raw IP, so the server can be
-- swapped by repointing the DNS A-record (Timeweb Cloud DNS API).
-- Idempotent: guarded by an information_schema check.
-- =====================================================================

SET @have := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vpn_servers' AND COLUMN_NAME = 'domain'
);
SET @sql := IF(@have = 0,
  "ALTER TABLE vpn_servers ADD COLUMN domain VARCHAR(255) NULL AFTER host",
  "SELECT 1"
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
