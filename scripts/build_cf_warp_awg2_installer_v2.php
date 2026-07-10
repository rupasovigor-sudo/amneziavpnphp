<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$runtime = file_get_contents($root . '/scripts/awg2_warp_egress_runtime_v2.sh');
$uninstall = file_get_contents($root . '/scripts/awg2_warp_egress_uninstall_v2.sh');

if ($runtime === false || $uninstall === false) {
    fwrite(STDERR, "Missing runtime or uninstall script\n");
    exit(1);
}

$runtimeB64 = base64_encode($runtime);

$installer = <<<'SH'
#!/bin/bash
set -euo pipefail

STATE_DIR="/var/lib/cloudflare-warp/awg2-egress"
RUNTIME_B64="__RUNTIME_B64__"

export DEBIAN_FRONTEND=noninteractive

echo "=== Installing Cloudflare WARP health-gated client egress for AmneziaWG2 ==="

if ! docker inspect "${SERVER_CONTAINER:-amnezia-awg2}" >/dev/null 2>&1; then
  echo "ERROR: AWG2 container not found: ${SERVER_CONTAINER:-amnezia-awg2}"
  exit 1
fi

mkdir -p "$STATE_DIR" /etc/wireguard
printf '%s' "$RUNTIME_B64" | base64 -d > "$STATE_DIR/installer-runtime.sh"
chmod +x "$STATE_DIR/installer-runtime.sh"

cat > /usr/local/sbin/awg2-warp-egress <<'SERVICE_SCRIPT'
#!/bin/bash
set -euo pipefail
exec /var/lib/cloudflare-warp/awg2-egress/installer-runtime.sh "${1:-start}"
SERVICE_SCRIPT
chmod +x /usr/local/sbin/awg2-warp-egress

cat > /etc/systemd/system/awg2-warp-egress.service <<'UNIT'
[Unit]
Description=AmneziaWG2 client egress through Cloudflare WARP netns
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/awg2-warp-egress start
ExecStop=/usr/local/sbin/awg2-warp-egress stop
TimeoutStartSec=180
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/awg2-warp-egress-retry.timer <<'UNIT'
[Unit]
Description=Retry AmneziaWG2 WARP egress startup

[Timer]
OnBootSec=5min
OnUnitInactiveSec=15min
RandomizedDelaySec=2min
Persistent=true
Unit=awg2-warp-egress.service

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
if systemctl start awg2-warp-egress.service >/tmp/awg2-warp-egress-install.log 2>&1; then
  systemctl enable awg2-warp-egress.service >/dev/null 2>&1 || true
  systemctl enable awg2-warp-egress-retry.timer >/dev/null 2>&1 || true
  systemctl start awg2-warp-egress-retry.timer >/dev/null 2>&1 || true
  /usr/local/sbin/awg2-warp-egress status >/dev/null 2>&1 || true
  echo "Variable: warp_status=on"
else
  rc=$?
  systemctl disable awg2-warp-egress.service >/dev/null 2>&1 || true
  systemctl disable --now awg2-warp-egress-retry.timer >/dev/null 2>&1 || true
  /usr/local/sbin/awg2-warp-egress cleanup >/dev/null 2>&1 || true
  systemctl reset-failed awg2-warp-egress.service >/dev/null 2>&1 || true
  echo "WARN: WARP health check failed, client egress was left direct"
  sed -n '1,120p' /tmp/awg2-warp-egress-install.log 2>/dev/null || true
  echo "Variable: warp_status=unhealthy_not_routed"
  echo "Variable: warp_start_rc=$rc"
fi

echo "Variable: warp_mode=wireguard_netns_health_gated"
echo "Variable: routing_scope=awg2_client_egress_tcp_udp"
echo "Variable: routed_subnets=none_until_warp_healthy"
echo "Variable: client_configs_unchanged=true"
SH;

$installer = str_replace('__RUNTIME_B64__', $runtimeB64, $installer);

if (in_array('--update-db', $argv, true)) {
    require_once $root . '/inc/Config.php';
    Config::load($root . '/.env');
    require_once $root . '/inc/DB.php';

    $stmt = DB::conn()->prepare(
        "UPDATE protocols
         SET name = 'Cloudflare WARP Egress',
             description = 'Cloudflare WARP client egress for AmneziaWG2. Health-gated netns routing: AWG2 client TCP and UDP egress is routed through WARP only after WARP passes a live trace check; otherwise clients remain direct and configs stay unchanged.',
             install_script = ?,
             uninstall_script = ?,
             output_template = ?,
             definition = JSON_OBJECT(
               'engine', 'shell',
               'metadata', JSON_OBJECT(
                 'container_name', 'amnezia-awg2',
                 'target_protocol', 'awg2',
                 'config_dir', '/opt/amnezia/awg2',
                 'config_file', 'awg0.conf',
                 'routes_client_egress', true,
                 'routing_method', 'warp_wireguard_netns_policy_routing_health_gated',
                 'client_configs_unchanged', true,
                 'routing_scope', 'tcp_udp_client_egress',
                 'route_table', 51888,
                 'mark', '0x2cf2'
               )
             ),
             updated_at = NOW()
         WHERE slug = 'cf-warp'"
    );
    $stmt->execute([
        $installer,
        $uninstall,
        "WARP client egress for AmneziaWG2\nMode: {{warp_mode}}\nRouting: {{routing_scope}}\nStatus: {{warp_status}}\nRouted: {{routed_subnets}}\nClient configs unchanged: {{client_configs_unchanged}}\n",
    ]);
    fwrite(STDERR, "Updated cf-warp protocol install/uninstall scripts\n");
}

echo $installer;
