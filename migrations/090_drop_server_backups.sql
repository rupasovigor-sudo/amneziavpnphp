-- =====================================================================
-- Migration 090: remove the per-server backup feature
-- =====================================================================
-- The panel's per-server backup (createBackup / restoreBackup — a JSON
-- snapshot of one server's config + clients written to disk) was removed:
-- it was unused, wrote client private keys in plaintext to disk, its restore
-- was partial/fragile, and it is superseded by the failover pool (live
-- redundancy) plus whole-DB dumps for disaster recovery. Importing a server
-- from an Amnezia/panel backup FILE is a separate feature and stays.
-- Idempotent: DROP TABLE IF EXISTS.
-- =====================================================================

DROP TABLE IF EXISTS server_backups;
