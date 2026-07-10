-- =====================================================================
-- Migration 086: server pools (shared awg2 identity + DNS failover)
-- =====================================================================
-- A pool holds ONE shared awg2 server identity (keypair + PSK + AmneziaWG
-- obfuscation params + subnet + port + domain). Every member server runs that
-- identical identity and carries every client's peer, so one client config
-- works against any member. The domain's A-record points at the active member;
-- monitoring repoints it to a healthy member on failure.
-- Idempotent: CREATE TABLE IF NOT EXISTS + guarded ALTERs.
-- =====================================================================

CREATE TABLE IF NOT EXISTS server_pools (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  domain VARCHAR(255) NULL,
  server_public_key VARCHAR(255) NULL,
  server_private_key TEXT NULL COMMENT 'encrypted (SecretBox)',
  preshared_key TEXT NULL COMMENT 'encrypted (SecretBox)',
  awg_params JSON NULL,
  vpn_subnet VARCHAR(64) NULL,
  vpn_port INT NULL DEFAULT 443,
  active_server_id INT UNSIGNED NULL,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_active_server (active_server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- vpn_servers.pool_id — pool membership.
SET @have := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vpn_servers' AND COLUMN_NAME = 'pool_id');
SET @sql := IF(@have = 0,
  "ALTER TABLE vpn_servers ADD COLUMN pool_id INT UNSIGNED NULL AFTER domain, ADD KEY idx_pool (pool_id)",
  "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- vpn_servers.pool_priority — lower = preferred failover candidate.
SET @have := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vpn_servers' AND COLUMN_NAME = 'pool_priority');
SET @sql := IF(@have = 0,
  "ALTER TABLE vpn_servers ADD COLUMN pool_priority INT NOT NULL DEFAULT 100 AFTER pool_id",
  "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
