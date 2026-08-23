-- =====================================================================
-- Migration 106: bake cheap host hardening into the awg2 install_script
-- =====================================================================
-- Adds two best-effort steps that run near the end of every awg2 deploy
-- (mirrors scripts/awg2_hardening.sh, applied to existing members too):
--
--   1. fail2ban with an sshd jail (banaction=iptables-allports) — the SSH
--      port was exposed with no brute-force protection. allports avoids
--      needing to detect a custom SSH port and keeps this block quote-free
--      (it is embedded verbatim below).
--   2. /etc/sysctl.d/99-amnezia-awg2.conf raising net.core.rmem_max /
--      wmem_max to 8 MB so the userspace amneziawg-go listener can use its
--      full ~7 MB socket-buffer request instead of being clamped at 4 MB
--      (fewer UDP drops under CPU-bound bursts). Applies on next awg restart.
--
-- The install_script runs under `set -eo pipefail`; the injected body is a
-- `( set +e … ) || true` subshell so a hardening failure never aborts a
-- deploy. Idempotent: injected once (guarded on the amnezia-sshd marker),
-- right before the final success echo.
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        'echo "AmneziaWG 2.0 installed successfully"',
'# --- Host hardening: fail2ban (SSH) + AWG UDP socket buffers (best-effort) ---
( set +e
  echo "hardening: fail2ban + sysctl (best-effort)..."

  if ! command -v fail2ban-server >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban >/dev/null 2>&1; }
  fi

  if command -v fail2ban-server >/dev/null 2>&1; then
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/amnezia-sshd.conf <<F2BEOF
[sshd]
enabled = true
maxretry = 5
findtime = 600
bantime = 3600
banaction = iptables-allports
F2BEOF
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1 || service fail2ban restart >/dev/null 2>&1
    echo "hardening: fail2ban active"
  else
    echo "hardening: fail2ban install failed (ignored)"
  fi

  cat > /etc/sysctl.d/99-amnezia-awg2.conf <<SYSCTLEOF
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
SYSCTLEOF
  sysctl -p /etc/sysctl.d/99-amnezia-awg2.conf >/dev/null 2>&1
  echo "hardening: sysctl applied"
) || true

echo "AmneziaWG 2.0 installed successfully"'
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%AmneziaWG 2.0 installed successfully%'
  AND install_script NOT LIKE '%amnezia-sshd%';
