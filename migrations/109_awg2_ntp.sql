-- =====================================================================
-- Migration 109: ensure NTP time sync in the awg2 hardening block
-- =====================================================================
-- Appends `timedatectl set-ntp true` to the host-hardening block that
-- migration 106 injected into the awg2 install_script, so fresh members
-- always have time sync on. WireGuard handshake timestamps and correct log
-- timestamps both depend on a roughly correct clock. Mirrors
-- scripts/awg2_hardening.sh. Idempotent (guarded on the set-ntp marker);
-- single-line insert, no backslash-continuation (MySQL string literals eat
-- a trailing backslash-newline).
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        '  echo "hardening: sysctl applied"',
        '  echo "hardening: sysctl applied"
  timedatectl set-ntp true >/dev/null 2>&1 || true
  echo "hardening: ntp enabled"'
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%hardening: sysctl applied%'
  AND install_script NOT LIKE '%set-ntp%';
