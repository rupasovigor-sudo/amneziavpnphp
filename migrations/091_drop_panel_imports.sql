-- =====================================================================
-- Migration 091: remove the backup/config import feature
-- =====================================================================
-- The "restore/import server configuration from a backup file" family was
-- removed: importing a server or its clients from an Amnezia app backup, a
-- panel backup, or a foreign panel export (wg-easy / 3x-ui). It was unused
-- (panel_imports was empty), targeted the legacy amnezia-awg v1 container or
-- formats/protocols that don't match the current awg2 + pool model, and its
-- restore was destructive/fragile. Redundancy now comes from the failover
-- pool; onboarding is a fresh SSH deploy.
-- Idempotent: DROP TABLE IF EXISTS.
-- =====================================================================

DROP TABLE IF EXISTS panel_imports;
