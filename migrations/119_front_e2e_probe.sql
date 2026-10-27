-- =====================================================================
-- Migration 119: end-to-end check of the front from inside Russia
-- =====================================================================
-- bin/front_e2e_probe.php (cron, every 5 min) brings up a real awg2 client
-- in the panel's docker-in-docker (a RU datacenter), connects through the
-- front and downloads a few MB. Two failures in a row -> alert and, with
-- auto_port, the front -> member port is rotated (the 2026-10-27 outage
-- was the front's network blocking that leg's port). Idempotent.
-- =====================================================================

SET @t := 'pool_fronts';
SET @c := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = @t AND column_name = 'e2e_checked_at');
SET @s := IF(@c = 0, 'ALTER TABLE pool_fronts
    ADD COLUMN e2e_checked_at DATETIME NULL,
    ADD COLUMN e2e_ok TINYINT(1) NULL,
    ADD COLUMN e2e_message VARCHAR(300) NULL,
    ADD COLUMN e2e_fail_streak INT NOT NULL DEFAULT 0,
    ADD COLUMN auto_port TINYINT(1) NOT NULL DEFAULT 1,
    ADD COLUMN blocked_ports TEXT NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
