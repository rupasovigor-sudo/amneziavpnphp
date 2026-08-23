-- =====================================================================
-- Migration 110: coordinate unattended-upgrades with the panel
-- =====================================================================
-- Appends a step to the awg2 hardening block that pins
-- Unattended-Upgrade::Automatic-Reboot "false" via a drop-in, so a member
-- never reboots itself mid-service (an active member would drop every
-- client). Security patches still install automatically; the panel's audit
-- cron surfaces reboot_required and the reboot action performs it safely
-- (failover-aware). Mirrors scripts/awg2_hardening.sh. Uses echo (not printf)
-- to stay backslash-free — MySQL string literals eat a backslash escape.
-- Idempotent (guarded on the drop-in filename).
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        '  echo "hardening: ntp enabled"',
        '  echo "hardening: ntp enabled"
  echo ''Unattended-Upgrade::Automatic-Reboot "false";'' > /etc/apt/apt.conf.d/99-amnezia-unattended
  echo "hardening: unattended-upgrades auto-reboot disabled"'
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%hardening: ntp enabled%'
  AND install_script NOT LIKE '%99-amnezia-unattended%';
