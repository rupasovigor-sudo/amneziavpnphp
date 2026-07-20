<?php
declare(strict_types=1);

// Daily read-only audit of every managed server: refreshes the stored package /
// awg2 / WARP inventory so the UI is current without anyone clicking, and raises
// an alert when a server needs attention (security patches, pending reboot, a
// stale awg2 build). Applies nothing — patching stays a deliberate action.
//
// Usage: php update_audit_cron.php

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
foreach ([
    'Config', 'DB', 'Logger', 'SecretBox', 'VpnServer', 'VpnClient',
    'ServerMonitoring', 'ServerPool', 'ServerUpdateManager', 'AlertManager',
] as $c) {
    @require_once $root . '/inc/' . $c . '.php';
}
Config::load($root . '/.env');

@set_time_limit(0);

$alerts = new AlertManager();
$servers = DB::conn()->query("SELECT id, name FROM vpn_servers WHERE status != 'deleted' ORDER BY id")
    ->fetchAll(PDO::FETCH_ASSOC) ?: [];

echo '[' . date('Y-m-d H:i:s') . '] auditing ' . count($servers) . " server(s)\n";

foreach ($servers as $s) {
    $id = (int) $s['id'];
    $name = (string) $s['name'];
    try {
        $a = ServerUpdateManager::audit($id);
    } catch (Throwable $e) {
        echo "  #{$id} {$name}: audit failed: " . $e->getMessage() . "\n";
        continue;
    }
    if (empty($a['ok'])) {
        echo "  #{$id} {$name}: " . ($a['error'] ?? 'audit failed') . "\n";
        continue;
    }

    $problems = [];
    if (!empty($a['security'])) {
        $problems[] = "security-обновлений: {$a['security']}";
    }
    if (!empty($a['reboot_required'])) {
        $problems[] = 'требуется перезагрузка';
    }
    if (($a['awg2_update_available'] ?? null) === true) {
        $problems[] = 'awg2 отстал от закреплённой версии';
    }
    if (($a['warp_update_available'] ?? null) === true) {
        $problems[] = 'скрипты WARP устарели';
    }

    echo "  #{$id} {$name}: apt={$a['upgradable']} sec={$a['security']}"
        . (!empty($a['reboot_required']) ? ' reboot' : '') . "\n";

    // recordCheck resolves the alert automatically once the problem is gone.
    $alerts->recordCheck(
        $id,
        $name,
        'server_updates_pending',
        empty($problems),
        $problems
            ? implode('; ', $problems) . " (всего пакетов к обновлению: {$a['upgradable']})"
            : "Обновления не требуются (пакетов: {$a['upgradable']})",
        'warning'
    );
}

echo '[' . date('Y-m-d H:i:s') . "] audit done\n";
