-- =====================================================================
-- Migration 118: port for the front -> member leg
-- =====================================================================
-- 2026-10-27 the front's network (RU hosting) started dropping new UDP
-- flows to foreign IPs on 443 (and 8443), whatever the payload — clients
-- reached the front, but nothing got through to the member. Clients keep
-- connecting to the front on the pool port; only the relayed leg moves to
-- backend_port, which each member DNATs back to its awg container's port.
-- NULL = same as the pool port (old behaviour). Idempotent.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'pool_fronts' AND column_name = 'backend_port');
SET @s := IF(@c = 0,
    'ALTER TABLE pool_fronts ADD COLUMN backend_port INT NULL DEFAULT NULL',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
