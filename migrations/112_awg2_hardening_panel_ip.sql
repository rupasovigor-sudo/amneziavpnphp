-- =====================================================================
-- Migration 112: fail2ban must never ban the panel; key files 0600
-- =====================================================================
-- 1. The sshd jail (banaction=iptables-allports) had no ignoreip: after a
--    credential rotation the per-minute collector fails 5 times in 10 min,
--    the panel gets banned on ALL ports for an hour, every check fails and
--    auto-failover fires. The script runs over the panel's own SSH session,
--    so ${SSH_CLIENT%% *} is exactly the panel's source address.
-- 2. awg key files were written under umask 022 (0644).
-- Mirrors scripts/awg2_hardening.sh. Single-line, quote-free and
-- backslash-free (MySQL string literals eat backslash escapes).
-- Idempotent (guarded on the ignoreip marker).
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        CONCAT('banaction = iptables-allports', CHAR(10), 'F2BEOF'),
        CONCAT('banaction = iptables-allports', CHAR(10), 'ignoreip = 127.0.0.1/8 ::1 ${SSH_CLIENT%% *}', CHAR(10), 'F2BEOF')
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%banaction = iptables-allports%'
  AND install_script NOT LIKE '%ignoreip = 127.0.0.1/8%';

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        '  echo "hardening: sysctl applied"',
        CONCAT('  echo "hardening: sysctl applied"', CHAR(10), '  chmod 600 ${HOST_CONFIG_DIR:-/opt/amnezia/awg2}/*.key >/dev/null 2>&1; echo "hardening: key files 0600"')
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%hardening: sysctl applied%'
  AND install_script NOT LIKE '%hardening: key files 0600%';
