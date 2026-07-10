<?php
declare(strict_types=1);

// Assemble the cf-warp v3 install/uninstall scripts (wgcf-free WARP profile
// pool + rotation) and emit migration 085 that stores them in the protocols
// table. Scripts are embedded via FROM_BASE64 to stay quoting-safe.
//
// Usage:
//   php scripts/build_cf_warp_awg2_installer_v3.php            # write migration
//   php scripts/build_cf_warp_awg2_installer_v3.php --stdout   # print installer

$root = dirname(__DIR__);
$runtime   = file_get_contents($root . '/scripts/awg2_warp_egress_runtime_v3.sh');
$installTpl = file_get_contents($root . '/scripts/awg2_warp_egress_install_v3.sh');
$uninstall = file_get_contents($root . '/scripts/awg2_warp_egress_uninstall_v3.sh');

if ($runtime === false || $installTpl === false || $uninstall === false) {
    fwrite(STDERR, "Missing runtime/install/uninstall script\n");
    exit(1);
}

$installer = str_replace('__RUNTIME_B64__', base64_encode($runtime), $installTpl);

if (in_array('--stdout', $argv, true)) {
    echo $installer;
    exit(0);
}

$installB64   = base64_encode($installer);
$uninstallB64 = base64_encode($uninstall);

$outputTemplate = "WARP client egress for AmneziaWG2 (pool + rotation)\n"
    . "Mode: {{warp_mode}}\nActive profile: {{warp_active_profile}}\n"
    . "Pool size: {{warp_pool_size}}\nRotations: {{warp_rotations}}\n"
    . "Exit IP: {{warp_ip}}\nStatus: {{warp_status}}\n";
$outputTemplateB64 = base64_encode($outputTemplate);

$description = 'Cloudflare WARP client egress for AmneziaWG2 via a pool of WARP '
    . 'profiles (registered directly against the WARP API, no wgcf binary) with '
    . 'automatic rotation on error/429/traffic. Health-gated netns policy routing: '
    . 'AWG2 client TCP/UDP egress is routed through WARP only after a live trace '
    . 'check passes; the VPN handshake port stays direct and client configs are '
    . 'unchanged.';
$descLiteral = "'" . str_replace("'", "''", $description) . "'";

$sql = <<<SQL
-- =====================================================================
-- Migration 085: cf-warp v3 — WARP profile pool + rotation (no wgcf)
-- =====================================================================
-- Replaces the single-profile wgcf install with a native (PHP/bash) WARP
-- registration that maintains a pool of profiles and rotates the active one
-- on health failure / HTTP 429 / a traffic threshold, to dodge per-device
-- rate limits and blocks. netns/veth/policy-routing (awg2warp, table 51888,
-- mark 0x2cf2, MTU 1280) preserved. Scripts embedded via FROM_BASE64.
-- Idempotent: a plain UPDATE of the cf-warp protocol row.
-- =====================================================================

UPDATE protocols
SET name = 'Cloudflare WARP Egress',
    description = {$descLiteral},
    install_script   = FROM_BASE64('{$installB64}'),
    uninstall_script = FROM_BASE64('{$uninstallB64}'),
    output_template  = FROM_BASE64('{$outputTemplateB64}'),
    definition = JSON_OBJECT(
      'engine', 'shell',
      'metadata', JSON_OBJECT(
        'container_name', 'amnezia-awg2',
        'target_protocol', 'awg2',
        'config_dir', '/opt/amnezia/awg2',
        'config_file', 'awg0.conf',
        'routes_client_egress', true,
        'routing_method', 'warp_wireguard_netns_pool_rotation_health_gated',
        'client_configs_unchanged', true,
        'routing_scope', 'tcp_udp_client_egress',
        'route_table', 51888,
        'mark', '0x2cf2',
        'warp_pool', true
      )
    ),
    updated_at = NOW()
WHERE slug = 'cf-warp';

SQL;

$target = $root . '/migrations/085_cf_warp_wgcf_pool_rotation.sql';
file_put_contents($target, $sql);
fwrite(STDERR, "Wrote {$target} (install " . strlen($installer) . "B, uninstall " . strlen($uninstall) . "B)\n");
