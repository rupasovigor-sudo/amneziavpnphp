-- =====================================================================
-- Migration 078: Metrics retention/query indexes
-- =====================================================================

SET @idx_exists := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'client_metrics'
    AND INDEX_NAME = 'idx_client_metrics_collected_at'
);
SET @sql := IF(@idx_exists = 0,
  'ALTER TABLE client_metrics ADD INDEX idx_client_metrics_collected_at (collected_at)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'server_metrics'
    AND INDEX_NAME = 'idx_server_metrics_collected_at'
);
SET @sql := IF(@idx_exists = 0,
  'ALTER TABLE server_metrics ADD INDEX idx_server_metrics_collected_at (collected_at)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
