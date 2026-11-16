-- Remember the kernel boot id that was active before a managed reboot.
-- If the panel itself is hosted on the rebooted front, its worker is killed
-- together with the web container.  After the panel returns, the stored id
-- lets it prove that the reboot really happened and finish the orphaned job.

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'vpn_servers' AND column_name = 'server_update_boot_id');
SET @sql := IF(@c = 0,
    'ALTER TABLE vpn_servers ADD COLUMN server_update_boot_id VARCHAR(64) NULL DEFAULT NULL AFTER server_update_started_at',
    'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
