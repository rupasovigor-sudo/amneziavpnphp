-- =====================================================================
-- Migration 080: Remove Selective RU egress feature
-- =====================================================================
-- Reverts migration 077. The RU proxy role and the selective egress policy
-- feature are removed entirely; the panel keeps only awg2 + cf-warp.
-- The `ru-proxy` protocol row was already deleted by migration 079.
--
-- Tables are dropped children-first to respect foreign keys. The `role`
-- column and its index are dropped last. Idempotent: guarded by IF EXISTS
-- and an information_schema check for the column.
-- =====================================================================

DROP TABLE IF EXISTS egress_route_resolved_ips;
DROP TABLE IF EXISTS egress_route_rules;
DROP TABLE IF EXISTS egress_route_policies;
DROP TABLE IF EXISTS ru_proxy_configs;

SET @col_exists := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vpn_servers' AND COLUMN_NAME = 'role'
);
SET @sql := IF(@col_exists = 1,
  "ALTER TABLE vpn_servers DROP INDEX idx_role, DROP COLUMN role",
  "SELECT 1"
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
