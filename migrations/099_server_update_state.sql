-- =====================================================================
-- Migration 099: vpn_servers package-update background state
-- =====================================================================
-- Tracks the background package-update worker so the browser does not block on
-- a multi-minute apt run and progress survives a page reload / disconnect.
--   server_update_state:      NULL = none, 'running', 'done', 'failed'
--   server_update_message:    human-readable progress / result
--   server_update_started_at: when the worker started (to detect stuck jobs)
--   server_update_audit:      JSON snapshot of the last read-only audit
--   server_update_audited_at: when that audit was taken
-- Set by bin/server_update_worker.php; polled by GET /servers/{id}/updates/status.
-- Idempotent (guarded), mirrors the pool_join_state pattern from 098.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'server_update_state');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN server_update_state VARCHAR(16) NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'server_update_message');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN server_update_message VARCHAR(1000) NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'server_update_started_at');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN server_update_started_at DATETIME NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'server_update_audit');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN server_update_audit TEXT NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'server_update_audited_at');
SET @sql := IF(@c = 0, 'ALTER TABLE vpn_servers ADD COLUMN server_update_audited_at DATETIME NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
