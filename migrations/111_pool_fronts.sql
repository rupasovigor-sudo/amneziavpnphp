-- =====================================================================
-- Migration 111: pool fronts (RU entry relay) + per-member egress metadata
-- =====================================================================
-- A "front" is a server (e.g. in Russia) that clients connect to; it relays
-- UDP/443 to the pool members (transparent nftables DNAT, no decryption), so
-- clients enter through a domestic IP and exit through the foreign pool. All
-- members share one awg2 identity, so any member accepts any client.
--
-- * vpn_servers.role: 'vpn' (normal awg2 member/standalone) | 'front'.
-- * vpn_servers.egress_country/egress_ip/egress_checked_at: where a member's
--   traffic actually exits (its WARP egress, detected via cdn-cgi/trace). The
--   front balances only across members of its primary country so a client's
--   exit country stays predictable.
-- * vpn_servers.relay_group: NULL = auto (primary if egress_country matches the
--   front's primary_country, else reserve) | 'primary' | 'reserve' | 'off'.
-- * vpn_servers.pool_sync_pending_at: when the member's peers were deliberately
--   dropped (force-migrate) — auto re-sync waits a grace period after it.
-- * pool_fronts: one front per pool. dns_mode says where the pool domain points
--   ('member' = active member as before, 'front' = the front).
-- Idempotent.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'role');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT ''vpn''', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'egress_country');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN egress_country VARCHAR(8) NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'egress_ip');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN egress_ip VARCHAR(45) NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'egress_checked_at');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN egress_checked_at DATETIME NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'relay_group');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN relay_group VARCHAR(12) NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'pool_sync_pending_at');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN pool_sync_pending_at DATETIME NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

CREATE TABLE IF NOT EXISTS pool_fronts (
    id              INT NOT NULL AUTO_INCREMENT,
    pool_id         INT NOT NULL,
    server_id       INT NOT NULL,
    enabled         TINYINT(1) NOT NULL DEFAULT 1,
    primary_country VARCHAR(8) NOT NULL,
    dns_mode        VARCHAR(8) NOT NULL DEFAULT 'member',
    backends_json   TEXT NULL,
    tier            VARCHAR(12) NULL,
    last_push_at    DATETIME NULL,
    last_push_msg   VARCHAR(512) NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_front_pool (pool_id),
    UNIQUE KEY uq_front_server (server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
