<?php
declare(strict_types=1);

/**
 * End-to-end check of a pool's front from inside Russia.
 *
 * Server-side health can't see censorship: on 2026-10-27 every check was
 * green while the front's network dropped the front -> member leg on UDP
 * 443, and clients could not get any data through. This brings up a REAL
 * awg2 client in the panel's docker-in-docker (the panel runs in a RU
 * datacenter), connects through the front exactly like a user, and
 * downloads a few MB through the tunnel.
 *
 * A temporary probe peer (10.x.x.254, never handed to clients) is added to
 * the backend members' live interface for the duration of the check only.
 * On repeated failure the front -> member port is rotated (auto_port).
 */
class FrontProbe
{
    private const IMAGE = 'amz-front-probe';
    private const DL_BYTES = 3000000;
    private const MIN_OK_BYTES = 1000000;
    private const FAILS_BEFORE_ACTION = 2;
    private const ROTATE_ATTEMPTS = 3;
    private const PROBE_SPORT = 51999;

    /** Cron entry: check every enabled front, act on repeated failures. */
    public static function checkAll(): array
    {
        $out = [];
        try {
            $pools = DB::conn()->query('SELECT pool_id FROM pool_fronts WHERE enabled = 1')->fetchAll(PDO::FETCH_COLUMN) ?: [];
        } catch (Throwable $e) {
            return $out;
        }
        foreach ($pools as $poolId) {
            try {
                $out[] = self::checkPool((int) $poolId);
            } catch (Throwable $e) {
                $out[] = ['pool' => (int) $poolId, 'ok' => false, 'message' => 'probe error: ' . $e->getMessage()];
            }
        }
        return $out;
    }

    /** One check (+ rotation when warranted) for a pool. */
    public static function checkPool(int $poolId, bool $allowRotate = true): array
    {
        $res = self::run($poolId);
        self::record($poolId, $res);
        $front = PoolFront::forPool($poolId);
        if (!$front) {
            return $res;
        }

        $streak = (int) ($front['e2e_fail_streak'] ?? 0);
        $sid = (int) $front['server_id'];
        if (!$res['ok'] && ($res['stage'] ?? '') === 'setup') {
            return $res + ['pool' => $poolId]; // nothing learned about the path
        }
        $alerts = new AlertManager();
        $alerts->recordCheck($sid, (string) $front['server_name'], 'front_e2e', $res['ok'],
            $res['ok'] ? 'Проверка из России через фронт: ' . $res['message'] : 'Через фронт не проходят данные (проверка из России): ' . $res['message'],
            'critical', self::FAILS_BEFORE_ACTION);

        if ($res['ok'] || !$allowRotate || $streak < self::FAILS_BEFORE_ACTION) {
            return $res + ['pool' => $poolId];
        }
        // At most one rotation round an hour while it keeps failing: if new
        // ports didn't help, the block isn't on the port and re-rotating every
        // run would only churn clients and pollute the blocked list.
        $last = strtotime((string) ($front['e2e_rotated_at'] ?? '')) ?: 0;
        if ($last > 0 && time() - $last < 3600) {
            return $res + ['pool' => $poolId];
        }
        if ((int) ($front['auto_port'] ?? 1) !== 1 || $front['dns_mode'] !== 'front' || empty(json_decode((string) $front['backends_json'], true))) {
            return $res + ['pool' => $poolId];
        }
        // Only a data-path failure suggests a blocked leg; if the probe could
        // not even run (no image, no SSH), rotating ports would just churn.
        if (($res['stage'] ?? '') === 'setup') {
            return $res + ['pool' => $poolId];
        }
        DB::conn()->prepare('UPDATE pool_fronts SET e2e_rotated_at = NOW() WHERE id = ?')->execute([(int) $front['id']]);
        return self::rotate($poolId, $res) + ['pool' => $poolId];
    }

    /**
     * Try new front -> member ports until one carries data. The port that
     * failed is remembered as blocked so it is never picked again.
     */
    private static function rotate(int $poolId, array $failed): array
    {
        $front = PoolFront::forPool($poolId);
        $pool = ServerPool::get($poolId);
        $poolPort = (int) ($pool['vpn_port'] ?? 443) ?: 443;
        $blocked = array_map('intval', json_decode((string) ($front['blocked_ports'] ?? ''), true) ?: []);
        $current = (int) ($front['backend_port'] ?? 0) ?: $poolPort;
        $tried = [];

        for ($i = 0; $i < self::ROTATE_ATTEMPTS; $i++) {
            $blocked[] = $current;
            $blocked = array_values(array_unique($blocked));
            DB::conn()->prepare('UPDATE pool_fronts SET blocked_ports = ? WHERE id = ?')->execute([json_encode($blocked), (int) $front['id']]);

            do {
                $next = random_int(20000, 60999);
            } while (in_array($next, $blocked, true) || $next === $poolPort);
            $tried[] = $next;

            $set = PoolFront::setBackendPort($poolId, $next);
            if (empty($set['success'])) {
                self::event($front, 'front_port_rotate_failed', "Не удалось сменить порт фронт → серверы на {$next}: " . $set['message'], 'critical');
                return ['ok' => false, 'message' => 'смена порта не удалась: ' . $set['message']];
            }
            sleep(3);
            $res = self::run($poolId);
            self::record($poolId, $res);
            if ($res['ok']) {
                self::event($front, 'front_port_rotated',
                    "Проверка из России: через фронт перестали проходить данные на порту {$current} ({$failed['message']}). "
                    . "Порт фронт → серверы автоматически сменён на {$next} — связь восстановлена ({$res['message']}).", 'warning');
                return ['ok' => true, 'rotated_to' => $next, 'message' => "порт сменён {$current} → {$next}; " . $res['message']];
            }
            $current = $next;
        }
        $blocked[] = $current;
        DB::conn()->prepare('UPDATE pool_fronts SET blocked_ports = ? WHERE id = ?')
            ->execute([json_encode(array_values(array_unique($blocked))), (int) $front['id']]);
        self::event($front, 'front_port_rotation_exhausted',
            'Проверка из России: через фронт не проходят данные, смена порта фронт → серверы ('
            . implode(', ', $tried) . ') не помогла — похоже, режут не порт (участок клиент → фронт или сам фронт). Нужна ручная проверка.', 'critical');
        return ['ok' => false, 'message' => 'смена порта не помогла (' . implode(', ', $tried) . ')'];
    }

    /**
     * Run one end-to-end probe. Returns ok, stage (setup|handshake|data|ok),
     * a short message, and timings.
     */
    public static function run(int $poolId): array
    {
        $fail = static fn(string $stage, string $m): array => ['ok' => false, 'stage' => $stage, 'message' => $m];
        $front = PoolFront::forPool($poolId);
        $pool = ServerPool::get($poolId);
        if (!$front || !$pool || (int) $front['enabled'] !== 1) {
            return $fail('setup', 'фронт не подключён');
        }
        $backendIds = self::backendMemberIds($poolId, $front);
        if (!$backendIds) {
            return $fail('setup', 'у фронта нет бэкендов');
        }

        $db = DB::conn();
        $lk = $db->prepare('SELECT GET_LOCK(?, 5)');
        $lk->execute(['amnezia_front_probe']);
        if ((int) $lk->fetchColumn() !== 1) {
            return $fail('setup', 'другая проверка уже идёт');
        }
        $pub = '';
        try {
            if (!self::ensureImage($backendIds[0])) {
                return $fail('setup', 'нет образа пробника в docker (dind)');
            }
            $keys = self::docker('run --rm ' . self::IMAGE . ' sh -c ' . escapeshellarg('P=$(awg genkey); echo "$P"; echo "$P" | awg pubkey'));
            $kl = array_values(array_filter(array_map('trim', explode("\n", $keys))));
            if (count($kl) < 2) {
                return $fail('setup', 'не удалось сгенерировать ключ пробника');
            }
            [$priv, $pub] = [$kl[0], $kl[1]];

            $subnet = trim((string) ($pool['vpn_subnet'] ?? '')) ?: '10.8.1.0/24';
            $probeIp = preg_replace('#\.\d+$#', '.254', preg_replace('#/\d+$#', '', $subnet));
            foreach ($backendIds as $mid) {
                $md = (new VpnServer($mid))->getData();
                $c = (string) ($md['container_name'] ?? '') ?: 'amnezia-awg2';
                $o = (string) (new VpnServer($mid))->executeCommand(
                    'docker exec ' . escapeshellarg($c) . ' awg set awg0 peer ' . escapeshellarg($pub)
                    . ' allowed-ips ' . escapeshellarg($probeIp . '/32') . ' 2>&1 && echo OK-ADD', true);
                if (!str_contains($o, 'OK-ADD')) {
                    return $fail('setup', 'не удалось добавить пробный пир на #' . $mid);
                }
            }

            $speedIp = gethostbyname('speed.cloudflare.com');
            if (!filter_var($speedIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $speedIp = '162.159.140.220';
            }
            $p = $pool['awg_params'] ?? [];
            if (is_string($p)) {
                $p = json_decode($p, true) ?: [];
            }
            // MTU 1100: the dind bridge runs at MTU 1200.
            // Fixed source port: makes probe traffic identifiable on the wire.
            $conf = ['[Interface]', "PrivateKey = {$priv}", "Address = {$probeIp}/32", 'MTU = 1100', 'ListenPort = ' . self::PROBE_SPORT];
            foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $k) {
                if (isset($p[$k]) && $p[$k] !== '') {
                    $conf[] = "{$k} = {$p[$k]}";
                }
            }
            $port = (int) ($pool['vpn_port'] ?? 443) ?: 443;
            $conf = array_merge($conf, [
                '', '[Peer]',
                'PublicKey = ' . trim((string) ($pool['server_public_key'] ?? '')),
                'Endpoint = ' . $front['server_host'] . ':' . $port,
                "AllowedIPs = 1.1.1.1/32, {$speedIp}/32",
                'PersistentKeepalive = 25',
            ]);
            $script = 'echo ' . base64_encode(implode("\n", $conf) . "\n") . ' | base64 -d > /p.conf; chmod 600 /p.conf; '
                . 'WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /p.conf >/dev/null 2>&1; '
                . 'T=$(curl -4 -s --max-time 10 https://1.1.1.1/cdn-cgi/trace | grep "^ip=" | cut -d= -f2); '
                . 'D=$(curl -4 -s -o /dev/null --max-time 20 --resolve speed.cloudflare.com:443:' . $speedIp
                . ' -w "%{size_download} %{time_total}" "https://speed.cloudflare.com/__down?bytes=' . self::DL_BYTES . '"); '
                . 'H=$(awg show p latest-handshakes | awk "{print \$2}"); '
                . 'echo "HS=${H:-0} EXIT=${T:-none} DL=${D:-0 0}"';
            $out = self::docker('run --rm --cap-add NET_ADMIN --device /dev/net/tun ' . self::IMAGE . ' sh -c ' . escapeshellarg($script), 70);

            preg_match('/HS=(\d+)/', $out, $mh);
            preg_match('/EXIT=(\S+)/', $out, $me);
            preg_match('/DL=(\d+) ([\d.]+)/', $out, $md);
            $hs = (int) ($mh[1] ?? 0);
            $exit = (string) ($me[1] ?? 'none');
            $bytes = (int) ($md[1] ?? 0);
            $secs = (float) ($md[2] ?? 0);

            if ($hs <= 0) {
                return $fail('handshake', 'handshake через фронт не прошёл');
            }
            if ($bytes < self::MIN_OK_BYTES) {
                return $fail('data', 'handshake есть, но данные не идут (' . round($bytes / 1024) . ' КБ)');
            }
            $mbit = $secs > 0 ? round($bytes * 8 / $secs / 1e6, 1) : 0;
            return [
                'ok' => true, 'stage' => 'ok',
                'message' => sprintf('%.1f МБ за %.1f с (~%s Мбит/с), выход %s', $bytes / 1048576, $secs, $mbit, $exit),
            ];
        } catch (Throwable $e) {
            return $fail('setup', $e->getMessage());
        } finally {
            if ($pub !== '') {
                foreach ($backendIds as $mid) {
                    try {
                        $md = (new VpnServer($mid))->getData();
                        $c = (string) ($md['container_name'] ?? '') ?: 'amnezia-awg2';
                        (new VpnServer($mid))->executeCommand('docker exec ' . escapeshellarg($c) . ' awg set awg0 peer ' . escapeshellarg($pub) . ' remove 2>&1', true);
                    } catch (Throwable $e) {
                        error_log("FrontProbe: probe peer removal failed on #{$mid}: " . $e->getMessage());
                    }
                }
            }
            $db->prepare('SELECT RELEASE_LOCK(?)')->execute(['amnezia_front_probe']);
        }
    }

    /** Members currently receiving the front's traffic. */
    private static function backendMemberIds(int $poolId, array $front): array
    {
        $ips = json_decode((string) ($front['backends_json'] ?? ''), true) ?: [];
        $ids = [];
        foreach (ServerPool::members($poolId) as $m) {
            if (in_array((string) $m['host'], $ips, true) && ($m['status'] ?? '') === 'active') {
                $ids[] = (int) $m['id'];
            }
        }
        return $ids;
    }

    /**
     * The probe image lives in the panel's docker-in-docker: the members'
     * own awg2 image (exact protocol version) plus curl. Built once.
     */
    private static function ensureImage(int $memberId): bool
    {
        if (trim(self::docker('image inspect -f ok ' . self::IMAGE . ' 2>/dev/null')) === 'ok') {
            return true;
        }
        $v = new VpnServer($memberId);
        $b64 = (string) $v->executeCommand('docker save amnezia-awg2 | gzip -1 | base64 -w0', true);
        $tmp = tempnam(sys_get_temp_dir(), 'awg2img');
        file_put_contents($tmp, base64_decode(trim($b64), true) ?: '');
        self::docker('load -i ' . escapeshellarg($tmp) . ' 2>&1', 300);
        @unlink($tmp);
        $dir = sys_get_temp_dir() . '/amz-front-probe-build';
        @mkdir($dir, 0700, true);
        file_put_contents($dir . '/Dockerfile', "FROM amnezia-awg2\nRUN apk add --no-cache curl\n");
        self::docker('build -q -t ' . self::IMAGE . ' ' . escapeshellarg($dir) . ' 2>&1', 300);
        return trim(self::docker('image inspect -f ok ' . self::IMAGE . ' 2>/dev/null')) === 'ok';
    }

    private static function docker(string $args, int $timeout = 60): string
    {
        // The CLI needs a writable config dir; www-data's HOME isn't writable.
        $cfg = sys_get_temp_dir() . '/amz-docker-config';
        @mkdir($cfg, 0700, true);
        // cron doesn't pass the container's environment, so DOCKER_HOST
        // (the docker-in-docker daemon) must be set explicitly.
        $host = getenv('DOCKER_HOST') ?: (string) Config::get('DOCKER_HOST', 'tcp://dind:2375');
        return (string) shell_exec('DOCKER_HOST=' . escapeshellarg($host) . ' DOCKER_CONFIG=' . escapeshellarg($cfg)
            . ' timeout ' . $timeout . ' docker ' . $args);
    }

    private static function record(int $poolId, array $res): void
    {
        // Setup failures (busy lock, no image, SSH to a member) say nothing
        // about the data path: report them, but leave the streak alone.
        if (!$res['ok'] && ($res['stage'] ?? '') === 'setup') {
            DB::conn()->prepare('UPDATE pool_fronts SET e2e_checked_at = NOW(), e2e_message = ? WHERE pool_id = ?')
                ->execute([mb_substr('проверка не выполнена: ' . (string) $res['message'], 0, 300), $poolId]);
            return;
        }
        DB::conn()->prepare(
            'UPDATE pool_fronts SET e2e_checked_at = NOW(), e2e_ok = ?, e2e_message = ?,
                    e2e_fail_streak = IF(? = 1, 0, e2e_fail_streak + 1)
             WHERE pool_id = ?'
        )->execute([$res['ok'] ? 1 : 0, mb_substr((string) $res['message'], 0, 300), $res['ok'] ? 1 : 0, $poolId]);
    }

    private static function event(array $front, string $name, string $msg, string $severity): void
    {
        try {
            (new AlertManager())->recordEvent((int) $front['server_id'], (string) $front['server_name'], $name, $msg, $severity,
                'front:' . (int) $front['id'] . ':' . $name . ':' . (int) floor(time() / 600));
        } catch (Throwable $e) {
            error_log('FrontProbe event failed: ' . $e->getMessage());
        }
    }
}
