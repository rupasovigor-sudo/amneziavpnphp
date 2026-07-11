-- =====================================================================
-- Migration 096: vpn_servers.pool_sync_pending
-- =====================================================================
-- Marks a pool member whose client-peer sync is incomplete (some peers failed
-- to push). Such a member must NOT be picked as a failover target, or the
-- missing clients would be unable to connect after a failover to it.
-- Set/cleared by ServerPool::syncClientsToServer. Idempotent (guarded).
-- =====================================================================

SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'pool_sync_pending');
SET @sql := IF(@has_col = 0,
    'ALTER TABLE vpn_servers ADD COLUMN pool_sync_pending TINYINT NOT NULL DEFAULT 0',
    'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
