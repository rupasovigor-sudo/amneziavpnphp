#!/bin/bash
set -euo pipefail

# AWG2 Cloudflare WARP egress installer v3 (stored in protocols.install_script).
# Deploys the v3 runtime (pool of WARP profiles + rotation), installs systemd
# units, registers the pool, brings egress up, and health-gates the result.
#
# The runtime is embedded base64 (substituted at build time by
# build_cf_warp_awg2_installer_v3.php).

BIN=/usr/local/sbin/awg2-warp-egress
STATE_DIR=/var/lib/cloudflare-warp/awg2-egress
RUNTIME_B64="__RUNTIME_B64__"

export DEBIAN_FRONTEND=noninteractive
mkdir -p "$STATE_DIR" /etc/wireguard

# 1. Write the runtime engine.
printf '%s' "$RUNTIME_B64" | base64 -d > "$BIN"
chmod 0755 "$BIN"

# 2. systemd units: the egress oneshot + a periodic health/rotation timer.
cat > /etc/systemd/system/awg2-warp-egress.service <<UNIT
[Unit]
Description=AWG2 Cloudflare WARP egress (pool + rotation)
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIN start
ExecStop=$BIN stop
TimeoutStartSec=300
Restart=no
[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/awg2-warp-egress-health.service <<UNIT
[Unit]
Description=AWG2 WARP egress health-check & rotation
After=awg2-warp-egress.service
[Service]
Type=oneshot
ExecStart=$BIN health
UNIT

cat > /etc/systemd/system/awg2-warp-egress-health.timer <<UNIT
[Unit]
Description=Run AWG2 WARP egress health-check periodically
[Timer]
OnBootSec=2min
OnUnitInactiveSec=${WARP_HEALTH_INTERVAL:-60s}
AccuracySec=10s
[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload

# 3. Register the profile pool up front (so start is fast and health-gated).
"$BIN" register || true

# 4. Enable + start egress, then the health timer.
systemctl enable awg2-warp-egress.service >/dev/null 2>&1 || true
if ! systemctl restart awg2-warp-egress.service; then
  echo "Variable: warp_status=start_failed"
  journalctl -u awg2-warp-egress.service -n 20 --no-pager 2>/dev/null || true
  exit 20
fi
systemctl enable awg2-warp-egress-health.timer >/dev/null 2>&1 || true
systemctl start awg2-warp-egress-health.timer >/dev/null 2>&1 || true

# 5. Health gate: confirm WARP is actually on before declaring success.
ok=0
for i in $(seq 1 8); do
  trace="$(ip netns exec awg2warp curl -4 -s --max-time 6 --resolve cloudflare.com:443:104.16.132.229 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
  if echo "$trace" | grep -q '^warp=on$'; then ok=1; break; fi
  sleep 3
done

warp_ip="$(ip netns exec awg2warp curl -4 -s --max-time 6 --resolve cloudflare.com:443:104.16.132.229 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '$1=="ip"{print $2; exit}' || true)"
active="$(cat "$STATE_DIR/active" 2>/dev/null || echo '')"
pool="$(find "$STATE_DIR/profiles" -mindepth 2 -maxdepth 2 -name profile.setconf 2>/dev/null | wc -l | tr -d ' ')"

echo "Variable: warp_mode=wireguard_netns_pool_rotating"
echo "Variable: warp_pool_size=$pool"
echo "Variable: warp_active_profile=$active"
echo "Variable: warp_ip=${warp_ip:-unknown}"
if [ "$ok" = "1" ]; then
  echo "Variable: warp_status=on"
  echo "AWG2 WARP egress installed and connected (pool=$pool, active=$active, exit=$warp_ip)"
else
  echo "Variable: warp_status=unhealthy"
  echo "AWG2 WARP egress installed but WARP did not come up healthy"
  exit 21
fi
