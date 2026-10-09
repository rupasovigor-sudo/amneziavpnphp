-- =====================================================================
-- Migration 113: per-pool "Google direct" switch for WARP egress
-- =====================================================================
-- Shared Cloudflare WARP exits are often flagged by Google (search CAPTCHA),
-- so Google's own ranges can egress directly from the member's IP while
-- everything else stays on WARP. Applied to members by
-- ServerUpdateManager::applyWarpSettings(). Default ON.
-- Idempotent.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'server_pools' AND column_name = 'warp_bypass_google');
SET @s := IF(@c = 0,
    'ALTER TABLE server_pools ADD COLUMN warp_bypass_google TINYINT(1) NOT NULL DEFAULT 1',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
