-- =====================================================================
-- Migration 121: linked pools share one authoritative client/peer set
-- =====================================================================
-- A linked pool keeps its own domain, members and ingress path, but reuses the
-- AWG identity and clients of a source pool.  This is useful for a direct KZ
-- endpoint next to a fronted FI pool: keys stay compatible while routing stays
-- completely separate.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'server_pools'
             AND column_name = 'peer_source_pool_id');
SET @s := IF(@c = 0,
    'ALTER TABLE server_pools ADD COLUMN peer_source_pool_id INT UNSIGNED NULL DEFAULT NULL, ADD KEY idx_peer_source_pool (peer_source_pool_id)',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
