<?php
declare(strict_types=1);

// Background pool-join worker. Spawned detached by POST /servers/{id}/pool/join
// so the browser does not block on the multi-minute join (awg2 image rebuild +
// peer sync + WARP install) and the progress survives a page reload/disconnect.
//
// Usage: php pool_join_worker.php --server-id=N --pool-id=M [--priority=P]

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
foreach ([
    'Config', 'DB', 'Logger', 'SecretBox', 'VpnServer', 'VpnClient',
    'InstallProtocolManager', 'DnsManager', 'TimewebDnsService', 'ServerPool', 'AlertManager',
] as $c) {
    @require_once $root . '/inc/' . $c . '.php';
}
Config::load($root . '/.env');

$args = getopt('', ['server-id:', 'pool-id:', 'priority::']);
$serverId = (int) ($args['server-id'] ?? 0);
$poolId = (int) ($args['pool-id'] ?? 0);
$priority = isset($args['priority']) ? (int) $args['priority'] : 100;
if ($serverId <= 0 || $poolId <= 0) {
    fwrite(STDERR, "usage: --server-id=N --pool-id=M [--priority=P]\n");
    exit(2);
}

@set_time_limit(0);
@ignore_user_abort(true);

$setState = static function (string $state, string $msg) use ($serverId): void {
    try {
        DB::conn()->prepare('UPDATE vpn_servers SET pool_join_state = ?, pool_join_message = ? WHERE id = ?')
            ->execute([$state, mb_substr($msg, 0, 480), $serverId]);
    } catch (Throwable $e) {
        // best effort
    }
};

try {
    DB::conn()->prepare('UPDATE vpn_servers SET pool_join_state = ?, pool_join_message = ?, pool_join_started_at = NOW() WHERE id = ?')
        ->execute(['deploying', 'Передеплой awg2 с общими ключами, синк пиров и WARP…', $serverId]);
    Logger::appendInstall($serverId, "pool_join_worker: start (pool={$poolId}, priority={$priority})");

    $res = ServerPool::addMember($poolId, $serverId, $priority);

    if (!empty($res['success'])) {
        $msg = (string) ($res['message'] ?? 'Добавлен в пул.');
        $setState('done', $msg);
        Logger::appendInstall($serverId, 'pool_join_worker: done — ' . $msg);
        exit(0);
    }

    $msg = (string) ($res['message'] ?? 'Не удалось добавить в пул');
    $setState('failed', $msg);
    Logger::appendInstall($serverId, 'pool_join_worker: FAILED — ' . $msg);
    exit(1);
} catch (Throwable $e) {
    $setState('failed', 'Ошибка: ' . $e->getMessage());
    Logger::appendInstall($serverId, 'pool_join_worker: EXCEPTION — ' . $e->getMessage());
    exit(1);
}
