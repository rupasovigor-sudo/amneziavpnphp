-- =====================================================================
-- Migration 122: parallel AWG 3.1 profile, preserving existing AWG 2.0
-- =====================================================================
-- HeaderProtectionKey is an interface-wide setting.  A 3.1 and a 2.0 client
-- therefore cannot share one interface/port.  Existing rows stay on 2.0;
-- newly created rows are placed on the parallel 3.1 interface by the panel.

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'server_pools'
             AND column_name = 'awg31_port');
SET @s := IF(@c = 0,
    'ALTER TABLE server_pools ADD COLUMN awg31_port INT UNSIGNED NOT NULL DEFAULT 444 AFTER vpn_port',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'server_pools'
             AND column_name = 'awg31_subnet');
SET @s := IF(@c = 0,
    'ALTER TABLE server_pools ADD COLUMN awg31_subnet VARCHAR(64) NOT NULL DEFAULT ''10.8.31.0/24'' AFTER awg31_port',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'server_pools'
             AND column_name = 'awg31_header_key');
SET @s := IF(@c = 0,
    'ALTER TABLE server_pools ADD COLUMN awg31_header_key TEXT NULL AFTER awg31_subnet',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'server_pools'
             AND column_name = 'awg31_params');
SET @s := IF(@c = 0,
    'ALTER TABLE server_pools ADD COLUMN awg31_params JSON NULL AFTER awg31_header_key',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'vpn_clients'
             AND column_name = 'awg_version');
SET @s := IF(@c = 0,
    'ALTER TABLE vpn_clients ADD COLUMN awg_version VARCHAR(8) NOT NULL DEFAULT ''2.0'' AFTER protocol_id, ADD KEY idx_vpn_clients_awg_version (awg_version)',
    'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

UPDATE protocols
SET name = 'AmneziaWG 2.0 / 3.1',
    description = 'Параллельные профили: существующие конфиги остаются на AWG 2.0, новые создаются на AWG 3.1.'
WHERE slug = 'awg2';
