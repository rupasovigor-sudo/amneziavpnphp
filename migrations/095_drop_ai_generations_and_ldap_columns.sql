-- =====================================================================
-- Migration 095: drop leftovers from removed features (AI, LDAP)
-- =====================================================================
-- ai_generations backed the removed AI protocol-assistant; nothing writes it
-- and ProtocolService no longer reads it. users.ldap_dn / ldap_synced backed
-- the removed LDAP auth. Idempotent (DROP TABLE IF EXISTS + guarded column drops).
-- =====================================================================

DROP TABLE IF EXISTS ai_generations;

-- users.ldap_dn (+ its index) — guarded so re-runs are no-ops.
SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'ldap_dn');
SET @sql := IF(@has_col > 0, 'ALTER TABLE users DROP COLUMN ldap_dn', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'ldap_synced');
SET @sql := IF(@has_col > 0, 'ALTER TABLE users DROP COLUMN ldap_synced', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
