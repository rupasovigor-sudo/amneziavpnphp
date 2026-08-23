#!/bin/bash
# =====================================================================
# awg2 host hardening — cheap security/resilience wins for a pool member.
# =====================================================================
# Idempotent and STRICTLY best-effort: it is embedded near the end of the
# awg2 install_script (which runs under `set -eo pipefail`), so the whole
# body runs in a `( set +e … ) || true` subshell — a failure here must
# never abort a deploy. The same file is applied to existing members.
#
# 1. fail2ban — the SSH port is exposed with no brute-force protection.
#    banaction=iptables-allports blocks a hitting IP on every port, so no
#    SSH-port detection is needed (also keeps this file quote-free, which
#    matters because it is embedded verbatim into a SQL migration).
# 2. UDP socket buffers — amneziawg-go (userspace) asks for a ~7MB socket
#    buffer but is clamped at the 4MB default, dropping packets under
#    CPU-bound bursts on a 1-vCPU box. Raising the max lets it use the
#    full request. Takes effect on the next awg (container) restart.
# =====================================================================
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
# Larger UDP socket buffers for the userspace amneziawg-go listener.
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
SYSCTLEOF
  sysctl -p /etc/sysctl.d/99-amnezia-awg2.conf >/dev/null 2>&1
  echo "hardening: sysctl applied"

  # Ensure NTP time sync is on: WireGuard handshake timestamps and correct log
  # timestamps both depend on a roughly correct clock. Idempotent no-op if
  # already enabled (chrony/systemd-timesyncd).
  timedatectl set-ntp true >/dev/null 2>&1 || true
  echo "hardening: ntp enabled"

  # Coordinate with the panel's update system: never let unattended-upgrades
  # reboot a member on its own — an active member would drop every client.
  # Security patches still install automatically; the panel surfaces
  # reboot_required (audit cron) and reboots safely (failover-aware).
  echo 'Unattended-Upgrade::Automatic-Reboot "false";' > /etc/apt/apt.conf.d/99-amnezia-unattended
  echo "hardening: unattended-upgrades auto-reboot disabled"
) || true
