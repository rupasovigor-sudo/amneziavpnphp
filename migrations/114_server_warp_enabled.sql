-- =====================================================================
-- Migration 114: per-server WARP egress switch
-- =====================================================================
-- warp_enabled = 0 turns Cloudflare WARP egress off on that server (client
-- traffic leaves directly from the server IP). Pushed to the server as
-- WARP_ENABLED in /etc/default/awg2-warp-egress by
-- ServerUpdateManager::applyWarpSettings(); monitoring treats "off" as
-- intended, so the auto-repair doesn't turn it back on. Idempotent.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'warp_enabled');
SET @s := IF(@c = 0,
    'ALTER TABLE vpn_servers ADD COLUMN warp_enabled TINYINT(1) NOT NULL DEFAULT 1',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
