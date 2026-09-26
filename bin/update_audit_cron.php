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
    'ServerMonitoring', 'ServerPool', 'ServerUpdateManager', 'AlertManager', 'IpReputation', 'PoolFront',
] as $c) {
    @require_once $root . '/inc/' . $c . '.php';
}
Config::load($root . '/.env');

@set_time_limit(0);

$alerts = new AlertManager();
$servers = DB::conn()->query("SELECT id, name, host FROM vpn_servers WHERE status != 'deleted' ORDER BY id")
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

    // Ingress-IP reputation (best-effort DNSBL/AbuseIPDB proxy; a listing is an
    // early warning that the IP may be getting throttled, not proof of it).
    $host = trim((string) ($s['host'] ?? ''));
    if ($host !== '' && filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        try {
            $rep = IpReputation::check($host);
            IpReputation::store($id, $rep);
            $listed = $rep['listed_on'];
            $score = $rep['abuse_score'];
            $bad = !empty($listed) || ($score !== null && $score >= 50);
            $msg = $bad
                ? ('IP ' . $host . ' в блок-листах: '
                    . (empty($listed) ? '' : implode(', ', $listed))
                    . ($score !== null ? " (AbuseIPDB {$score})" : ''))
                : ('IP ' . $host . ' чист по ' . $rep['lists_checked'] . ' спискам'
                    . ($score !== null ? ", AbuseIPDB {$score}" : ''));
            echo "  #{$id} {$name}: reputation " . ($bad ? 'LISTED' : 'clean') . "\n";
            $alerts->recordCheck($id, $name, 'ip_reputation', !$bad, $msg, 'warning');
        } catch (Throwable $e) {
            echo "  #{$id} {$name}: reputation check failed: " . $e->getMessage() . "\n";
        }
    }
}

// Egress country per pool member (WARP exit follows the server's location but
// can drift) — the RU front groups backends by it, so keep it fresh.
try {
    $poolIds = DB::conn()->query('SELECT pool_id FROM pool_fronts WHERE enabled = 1')->fetchAll(PDO::FETCH_COLUMN) ?: [];
} catch (Throwable $e) {
    $poolIds = [];
}
foreach ($poolIds as $pid) {
    foreach (PoolFront::detectAll((int) $pid) as $sid => $r) {
        echo "  pool {$pid} #{$sid}: egress " . ($r['country'] ?? '?') . ($r['warp'] ? ' (warp)' : '') . "\n";
    }
}

echo '[' . date('Y-m-d H:i:s') . "] audit done\n";
