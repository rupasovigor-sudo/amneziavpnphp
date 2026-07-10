-- =====================================================================
-- Migration 079: Reduce supported protocols to AmneziaWG 2.0 + Cloudflare WARP
-- =====================================================================
-- The panel now supports only two protocols: `awg2` and `cf-warp`.
-- All other protocols are removed from the catalog. Dependent rows in
-- protocol_variables / protocol_templates / server_protocols are removed
-- automatically via their ON DELETE CASCADE foreign keys.
--
-- Historical seed migrations (014, 058, 059, 060, 066, ...) are intentionally
-- left untouched (already applied; migration files are immutable). This
-- migration is the authoritative source of the reduced protocol set and is
-- idempotent — re-running it simply deletes nothing.
--
-- Note: vpn_servers.install_protocol is a plain string column (not a FK), so
-- existing servers keep their recorded slug even if the catalog row is gone.
-- Per the agreed scope, servers still running removed protocols are no longer
-- supported.
-- =====================================================================

DELETE FROM protocols
WHERE slug NOT IN ('awg2', 'cf-warp');
