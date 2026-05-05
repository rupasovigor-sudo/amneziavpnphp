-- Add last_key_sync_at column to cache expensive remote WireGuard/AWG key syncs

SET @dbname = DATABASE();
SET @tablename = "vpn_servers";
SET @columnname = "last_key_sync_at";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 1",
  "ALTER TABLE vpn_servers ADD COLUMN last_key_sync_at TIMESTAMP NULL AFTER last_check_at"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;
