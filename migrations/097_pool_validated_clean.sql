-- =====================================================================
-- Migration 097: vpn_servers validation flags (pool canary validation)
-- =====================================================================
-- Records whether a pool member's ingress IP has been validated as reachable
-- from censored client networks ("clean") vs blocked ("burned").
--   validated_clean: NULL = not validated yet, 1 = clean, 0 = burned/unreachable
--   validated_at:    when the last validation ran
--   validation_note: short human note (e.g. "probe: reachable", "canary: 92% clients")
-- Set by ServerPool::probeReachability (Tier-1 server-side handshake probe) and
-- the client canary (Tier-2). Failover prefers validated_clean = 1 members.
-- Idempotent (guarded).
-- =====================================================================

SET @has_vc := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'validated_clean');
SET @sql := IF(@has_vc = 0,
    'ALTER TABLE vpn_servers ADD COLUMN validated_clean TINYINT NULL DEFAULT NULL',
    'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @has_va := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'validated_at');
SET @sql := IF(@has_va = 0,
    'ALTER TABLE vpn_servers ADD COLUMN validated_at DATETIME NULL DEFAULT NULL',
    'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @has_vn := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'validation_note');
SET @sql := IF(@has_vn = 0,
    'ALTER TABLE vpn_servers ADD COLUMN validation_note VARCHAR(255) NULL DEFAULT NULL',
    'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
