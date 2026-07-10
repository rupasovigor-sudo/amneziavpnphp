-- =====================================================================
-- Migration 081: Drop unused AIVPN counter columns from vpn_clients
-- =====================================================================
-- The AIVPN protocol was removed (migrations 079/080 + code cleanup). These
-- counter/offset columns (added by migration 062) are no longer referenced by
-- any code. Guarded so the migration is idempotent.
-- =====================================================================

SET @have := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vpn_clients' AND COLUMN_NAME = 'aivpn_raw_bytes_in'
);
SET @sql := IF(@have = 1,
  "ALTER TABLE vpn_clients DROP COLUMN aivpn_raw_bytes_in, DROP COLUMN aivpn_raw_bytes_out, DROP COLUMN aivpn_offset_bytes_in, DROP COLUMN aivpn_offset_bytes_out",
  "SELECT 1"
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
