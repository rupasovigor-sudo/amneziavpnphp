<?php
declare(strict_types=1);

// Background package-update worker. Spawned detached by
// POST /servers/{id}/updates/os so the browser does not block on a multi-minute
// apt run and progress survives a page reload / disconnect.
//
// Usage: php server_update_worker.php --server-id=N [--force=1]

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
foreach ([
    'Config', 'DB', 'Logger', 'SecretBox', 'VpnServer', 'VpnClient',
    'ServerMonitoring', 'ServerPool', 'ServerUpdateManager', 'AlertManager',
] as $c) {
    @require_once $root . '/inc/' . $c . '.php';
}
Config::load($root . '/.env');

$args = getopt('', ['server-id:', 'force::', 'action::', 'pool-id::', 'actions::']);
$serverId = (int) ($args['server-id'] ?? 0);
$force = !empty($args['force']);
$action = (string) ($args['action'] ?? 'os');
$allowed = ['os', 'kernel', 'docker', 'awg2', 'warp', 'reboot'];
$poolId = (int) ($args['pool-id'] ?? 0);

// Pool mode: roll the whole pool instead of one server.
if ($poolId > 0) {
    @set_time_limit(0);
    @ignore_user_abort(true);
    $list = array_values(array_filter(array_map('trim', explode(',', (string) ($args['actions'] ?? 'os')))));
    echo '[' . date('Y-m-d H:i:s') . "] rolling update pool #{$poolId}: " . implode(',', $list) . "\n";
    $res = ServerUpdateManager::rollingPoolUpdate($poolId, $list);
    foreach ($res['steps'] as $st) {
        echo '  ' . ($st['ok'] ? 'ok  ' : 'FAIL') . " #{$st['server']} ({$st['label']}) {$st['action']}: {$st['message']}\n";
    }
    echo '[' . date('Y-m-d H:i:s') . '] ' . ($res['success'] ? 'done' : 'failed') . ': ' . $res['message'] . "\n";
    exit($res['success'] ? 0 : 1);
}

if ($serverId <= 0 || !in_array($action, $allowed, true)) {
    fwrite(STDERR, "usage: --server-id=N [--action=" . implode('|', $allowed) . "] [--force=1]\n");
    exit(2);
}

@set_time_limit(0);
@ignore_user_abort(true);

$name = '#' . $serverId;
try {
    $name = (new VpnServer($serverId))->getData()['name'] ?? $name;
} catch (Throwable $e) {
    // fall through with the numeric label
}

$labels = [
    'os'     => 'Обновление пакетов ОС',
    'kernel' => 'Обновление ядра (full-upgrade)',
    'docker' => 'Обновление Docker',
    'awg2'   => 'Пересборка awg2',
    'warp'   => 'Переустановка WARP',
    'reboot' => 'Перезагрузка сервера',
];
ServerUpdateManager::setState($serverId, 'running', $labels[$action] . ' запущено…');
echo '[' . date('Y-m-d H:i:s') . "] {$action} start: {$name}\n";

try {
    switch ($action) {
        case 'kernel': $res = ServerUpdateManager::updateKernel($serverId, $force); break;
        case 'docker': $res = ServerUpdateManager::updateDocker($serverId, $force); break;
        case 'awg2':   $res = ServerUpdateManager::rebuildAwg2($serverId, $force); break;
        case 'warp':   $res = ServerUpdateManager::reinstallWarp($serverId, $force); break;
        case 'reboot': $res = ServerUpdateManager::reboot($serverId, $force); break;
        default:       $res = ServerUpdateManager::updateOs($serverId, $force); break;
    }
    $state = !empty($res['success']) ? 'done' : 'failed';
    ServerUpdateManager::setState($serverId, $state, (string) ($res['message'] ?? ''));
    ServerUpdateManager::recordHistory($serverId, $action, $state, (string) ($res['message'] ?? ''), $force);
    echo '[' . date('Y-m-d H:i:s') . "] {$state}: " . ($res['message'] ?? '') . "\n";
    exit(!empty($res['success']) ? 0 : 1);
} catch (Throwable $e) {
    ServerUpdateManager::setState($serverId, 'failed', 'Исключение: ' . $e->getMessage());
    ServerUpdateManager::recordHistory($serverId, $action, 'failed', 'Исключение: ' . $e->getMessage(), $force);
    echo '[' . date('Y-m-d H:i:s') . '] failed: ' . $e->getMessage() . "\n";
    exit(1);
}
