-- =====================================================================
-- Migration 117: "members accept the VPN port only from the front"
-- =====================================================================
-- pool_fronts.members_front_only = 1: while the pool domain points at the
-- front, every member drops VPN-port packets that don't come from the
-- front (or another member, for the reachability probe). Clients that kept
-- a pre-front address lose the direct path and, once they reconnect, go
-- through the front. Lifted automatically whenever the domain moves to a
-- member (front down / manual), re-applied when it returns. Idempotent.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'pool_fronts' AND column_name = 'members_front_only');
SET @s := IF(@c = 0,
    'ALTER TABLE pool_fronts ADD COLUMN members_front_only TINYINT(1) NOT NULL DEFAULT 0',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
