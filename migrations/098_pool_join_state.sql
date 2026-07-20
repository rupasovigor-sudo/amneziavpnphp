-- =====================================================================
-- Migration 098: vpn_servers pool-join background state
-- =====================================================================
-- Tracks the background pool-join worker so the browser doesn't block on the
-- multi-minute join (awg2 image rebuild + peer sync + WARP install) and the
-- progress survives a page reload / disconnect.
--   pool_join_state:   NULL = none, 'deploying' = in progress, 'done', 'failed'
--   pool_join_message: human-readable progress / result
--   pool_join_started_at: when the worker started (to detect stuck jobs)
-- Set by bin/pool_join_worker.php; polled by GET /servers/{id}/join-status.
-- Idempotent (guarded).
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'pool_join_state');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN pool_join_state VARCHAR(16) NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'pool_join_message');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN pool_join_message VARCHAR(500) NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'pool_join_started_at');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN pool_join_started_at DATETIME NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
