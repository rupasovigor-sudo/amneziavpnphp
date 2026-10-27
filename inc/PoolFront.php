<?php

/**
 * Pool front — an entry relay for a failover pool.
 *
 * Clients connect to the front (e.g. a server in Russia, reachable from
 * domestic networks); the front relays their UDP to the pool members with a
 * transparent nftables DNAT + masquerade. No tunnel is terminated on the front,
 * so it holds no keys. This works because every pool member shares one awg2
 * identity: any member accepts any client, so the front may send a client to
 * whichever member it likes.
 *
 * Backend selection keeps a client's exit country predictable: members are
 * grouped by their detected egress country (their WARP exit — it follows the
 * member's location). Members of the front's primary country are balanced
 * (sticky per client source IP); the rest are a reserve used only when no
 * primary member is healthy. Per-member overrides: relay_group
 * primary|reserve|off (NULL = auto).
 *
 * Health: member failures are handled by recomputing the backend set every
 * monitoring cycle (dead members drop out, their conntrack flows are flushed so
 * those clients re-handshake on a live member at once). If the front itself is
 * down while the pool domain points at it, the domain falls back to a healthy
 * member (no automatic return — an operator switches back, same no-failback
 * policy as the pool).
 */
class PoolFront
{
    /** Checks that make a front "down" (recorded by ServerMonitoring). */
    public const CRITICAL_CHECKS = ['ssh', 'front_relay'];

    /** Member checks that disqualify it as a backend. */
    private const MEMBER_DOWN_CHECKS = ['ssh', 'container_running', 'wireguard_interface', 'wireguard_port'];

    private const GROUPS = ['primary', 'reserve', 'off'];

    // ------------------------------------------------------------------ lookup

    public static function forPool(int $poolId): ?array
    {
        try {
            $st = DB::conn()->prepare(
                'SELECT f.*, s.name AS server_name, s.host AS server_host, s.port AS server_port, s.status AS server_status
                 FROM pool_fronts f JOIN vpn_servers s ON s.id = f.server_id
                 WHERE f.pool_id = ? LIMIT 1'
            );
            $st->execute([$poolId]);
            $r = $st->fetch(PDO::FETCH_ASSOC);
            return $r ?: null;
        } catch (Throwable $e) {
            return null; // pool_fronts not migrated yet
        }
    }

    public static function forServer(int $serverId): ?array
    {
        try {
            $st = DB::conn()->prepare('SELECT pool_id FROM pool_fronts WHERE server_id = ? LIMIT 1');
            $st->execute([$serverId]);
            $poolId = (int) $st->fetchColumn();
            return $poolId > 0 ? self::forPool($poolId) : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    /** True when the pool domain currently points at an enabled front. */
    public static function domainOnFront(int $poolId): bool
    {
        $f = self::forPool($poolId);
        return $f !== null && (int) $f['enabled'] === 1 && $f['dns_mode'] === 'front';
    }

    public static function isFrontServer(?array $serverData): bool
    {
        return is_array($serverData) && ($serverData['role'] ?? 'vpn') === 'front';
    }

    // ------------------------------------------------------------ registration

    /**
     * Register a plain Ubuntu host as the pool's front: create the server row
     * (role=front, credentials encrypted), install the relay, detect member
     * egress countries and push the first backend set. The pool domain is NOT
     * moved — that is a separate, deliberate step (pointDomainToFront).
     */
    public static function register(int $poolId, int $userId, array $in): array
    {
        $pool = ServerPool::get($poolId);
        if (!$pool) {
            return ['success' => false, 'message' => "Пул {$poolId} не найден"];
        }
        if (self::forPool($poolId)) {
            return ['success' => false, 'message' => 'У пула уже есть фронт'];
        }
        $host = trim((string) ($in['host'] ?? ''));
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return ['success' => false, 'message' => 'Нужен IPv4-адрес фронта (relay и A-запись работают по IPv4)'];
        }
        $port = (int) ($in['port'] ?? 22) ?: 22;
        $username = trim((string) ($in['username'] ?? 'root')) ?: 'root';
        $password = (string) ($in['password'] ?? '');
        $sshKey = trim((string) ($in['ssh_key'] ?? ''));
        if (!Ssh::isValidUsername($username) || $port < 1 || $port > 65535) {
            return ['success' => false, 'message' => 'Неверный SSH-пользователь или порт'];
        }
        if ($password === '' && $sshKey === '') {
            return ['success' => false, 'message' => 'Нужен пароль или SSH-ключ'];
        }
        $country = strtoupper(trim((string) ($in['primary_country'] ?? '')));
        if (!preg_match('/^[A-Z]{2}$/', $country)) {
            return ['success' => false, 'message' => 'Основная страна выхода — двухбуквенный код (например DE)'];
        }
        $name = trim((string) ($in['name'] ?? '')) ?: ('front-' . $host);

        $dup = DB::conn()->prepare("SELECT id FROM vpn_servers WHERE host = ? AND COALESCE(status,'') <> 'deleted' LIMIT 1");
        $dup->execute([$host]);
        if ($dup->fetchColumn()) {
            return ['success' => false, 'message' => "Сервер {$host} уже есть в панели"];
        }

        DB::conn()->prepare(
            "INSERT INTO vpn_servers (user_id, name, host, port, username, password, ssh_key,
                                      container_name, install_protocol, role, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, '', 'pool-front', 'front', 'deploying')"
        )->execute([
            $userId, $name, $host, $port, $username,
            VpnServer::encryptSecret($password !== '' ? $password : null),
            VpnServer::encryptSecret($sshKey !== '' ? VpnServer::normalizeSshKey($sshKey) : null),
        ]);
        $serverId = (int) DB::conn()->lastInsertId();

        $inst = self::install($serverId);
        if (empty($inst['success'])) {
            // Nothing references the row yet — drop it so a retry starts clean.
            DB::conn()->prepare('DELETE FROM vpn_servers WHERE id = ?')->execute([$serverId]);
            return ['success' => false, 'message' => 'Установка relay на фронт не удалась: ' . ($inst['message'] ?? '')];
        }
        DB::conn()->prepare("UPDATE vpn_servers SET status = 'active' WHERE id = ?")->execute([$serverId]);
        DB::conn()->prepare(
            "INSERT INTO pool_fronts (pool_id, server_id, primary_country, dns_mode) VALUES (?, ?, ?, 'member')"
        )->execute([$poolId, $serverId, $country]);

        self::detectAll($poolId);
        $sync = self::sync($poolId, true);

        return [
            'success' => true,
            'server_id' => $serverId,
            'message' => "Фронт {$name} ({$host}) подключён. " . ($sync['message'] ?? '')
                . ' Домен пула пока указывает на активный сервер — переключите его на фронт, когда будете готовы.',
        ];
    }

    /** Run the idempotent installer (scripts/pool_front_install.sh) on the front. */
    public static function install(int $serverId): array
    {
        $script = @file_get_contents(dirname(__DIR__) . '/scripts/pool_front_install.sh');
        if (!is_string($script) || $script === '') {
            return ['success' => false, 'message' => 'scripts/pool_front_install.sh не найден'];
        }
        try {
            $server = new VpnServer($serverId);
            $server->uploadContent('/tmp/amnezia_front_install.sh', $script, 0700);
            $out = (string) $server->executeCommand(
                'bash /tmp/amnezia_front_install.sh 2>&1; rm -f /tmp/amnezia_front_install.sh',
                true
            );
            $ok = str_contains($out, 'FRONT_OK');
            if ($ok) {
                // A front sits on a public IP with password SSH, and brute force
                // against it (thousands of tries a day) made sshd drop the
                // panel's checks -> false "front down" -> domain fallback. Same
                // best-effort hardening as members: fail2ban with the panel's
                // address ignored, NTP, no unattended reboots.
                $hardening = @file_get_contents(dirname(__DIR__) . '/scripts/awg2_hardening.sh');
                if (is_string($hardening) && $hardening !== '') {
                    try {
                        $server->uploadContent('/tmp/amnezia_hardening.sh', $hardening, 0700);
                        $server->executeCommand('bash /tmp/amnezia_hardening.sh >/dev/null 2>&1; rm -f /tmp/amnezia_hardening.sh; echo done', true);
                    } catch (Throwable $e) {
                        error_log('PoolFront::install: hardening failed: ' . $e->getMessage());
                    }
                }
            }
            return ['success' => $ok, 'message' => trim(substr($out, -400))];
        } catch (Throwable $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    // --------------------------------------------------------- egress country

    /**
     * Detect where a member's client traffic exits: its WARP egress if present
     * (that is the client-visible IP), else the host's own address.
     *
     * @return array{country:?string, ip:?string, warp:bool}
     */
    public static function detectEgress(int $serverId): array
    {
        $cmd = <<<'SH'
T=$(ip netns exec awg2warp curl -s --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null)
[ -z "$T" ] && T=$(curl -s --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null)
echo "$T" | grep -E '^(ip|loc|warp)='
SH;
        $res = ['country' => null, 'ip' => null, 'warp' => false];
        try {
            $out = (string) (new VpnServer($serverId))->executeCommand($cmd, true);
        } catch (Throwable $e) {
            return $res;
        }
        if (preg_match('/^loc=([A-Z]{2})$/m', $out, $m)) {
            $res['country'] = $m[1];
        }
        if (preg_match('/^ip=(\S+)$/m', $out, $m)) {
            $res['ip'] = $m[1];
        }
        $res['warp'] = (bool) preg_match('/^warp=(on|plus)$/m', $out);
        if ($res['country'] !== null) {
            DB::conn()->prepare(
                'UPDATE vpn_servers SET egress_country = ?, egress_ip = ?, egress_checked_at = NOW() WHERE id = ?'
            )->execute([$res['country'], $res['ip'], $serverId]);
        }
        return $res;
    }

    /** Refresh the egress country of every active pool member. */
    public static function detectAll(int $poolId): array
    {
        $out = [];
        $st = DB::conn()->prepare("SELECT id FROM vpn_servers WHERE pool_id = ? AND status = 'active'");
        $st->execute([$poolId]);
        foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $id) {
            $out[(int) $id] = self::detectEgress((int) $id);
        }
        return $out;
    }

    // --------------------------------------------------------- backend choice

    /** True if any of $checks is open for the server with fail_count >= $threshold. */
    private static function checksOpen(int $serverId, array $checks, int $threshold): bool
    {
        if (!$checks) {
            return false;
        }
        $keys = array_map(static fn($c) => "server:{$serverId}:{$c}", $checks);
        $in = implode(',', array_fill(0, count($keys), '?'));
        $st = DB::conn()->prepare(
            "SELECT COUNT(*) FROM alert_states WHERE status = 'open' AND alert_key IN ($in) AND fail_count >= ?"
        );
        $st->execute(array_merge($keys, [$threshold]));
        return (int) $st->fetchColumn() > 0;
    }

    public static function frontDown(int $frontServerId, int $threshold): bool
    {
        return self::checksOpen($frontServerId, self::CRITICAL_CHECKS, $threshold);
    }

    /**
     * Compute the backend set for a pool's front.
     *
     * @return array{tier:string, backends:string[], members:array<int,array<string,mixed>>}
     */
    public static function computeBackends(int $poolId, array $front): array
    {
        $st = DB::conn()->prepare(
            'SELECT id, name, host, status, pool_sync_pending, egress_country, egress_ip, egress_checked_at, relay_group
             FROM vpn_servers WHERE pool_id = ? ORDER BY id ASC'
        );
        $st->execute([$poolId]);
        $primaryCountry = strtoupper((string) ($front['primary_country'] ?? ''));

        $rows = [];
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $m) {
            $id = (int) $m['id'];
            $override = in_array($m['relay_group'], self::GROUPS, true) ? $m['relay_group'] : null;
            $country = $m['egress_country'] ? strtoupper((string) $m['egress_country']) : null;
            $group = $override ?? (($country !== null && $country === $primaryCountry) ? 'primary' : 'reserve');

            $reason = '';
            if (($m['status'] ?? '') !== 'active') {
                $reason = 'сервер не active';
            } elseif (filter_var((string) $m['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                $reason = 'нет IPv4';
            } elseif ((int) ($m['pool_sync_pending'] ?? 0) === 1) {
                $reason = 'ждёт ре-синка пиров';
            } elseif (self::checksOpen($id, self::MEMBER_DOWN_CHECKS, 2)) {
                $reason = 'health-проверки падают';
            } elseif (self::checksOpen($id, ['pool_peers'], 2)) {
                // 2, not 1: client create writes the DB row before pushing the
                // peer member by member, so one short count is a benign race.
                $reason = 'неполный набор пиров';
            }

            $rows[] = [
                'id' => $id,
                'name' => $m['name'],
                'host' => $m['host'],
                'egress_country' => $country,
                'egress_ip' => $m['egress_ip'],
                'egress_checked_at' => $m['egress_checked_at'],
                'relay_group' => $override,
                'group' => $group,
                'eligible' => $reason === '' && $group !== 'off',
                'reason' => $group === 'off' && $reason === '' ? 'выключен из relay' : $reason,
                'in_rotation' => false,
            ];
        }

        $pick = static fn(string $g) => array_values(array_filter($rows, static fn($r) => $r['eligible'] && $r['group'] === $g));
        $tier = 'none';
        $chosen = $pick('primary');
        if ($chosen) {
            $tier = 'primary';
        } else {
            $chosen = $pick('reserve');
            if ($chosen) {
                $tier = 'reserve';
            }
        }
        $backends = array_map(static fn($r) => (string) $r['host'], $chosen);
        foreach ($rows as &$r) {
            $r['in_rotation'] = in_array((string) $r['host'], $backends, true);
        }
        unset($r);

        return ['tier' => $tier, 'backends' => $backends, 'members' => $rows];
    }

    /** nftables ruleset for the relay (sticky per client source IP). */
    public static function renderRuleset(array $backends, int $port, ?int $backendPort = null): string
    {
        $port = $port > 0 ? $port : 443;
        // The leg to the members may use another port than the clients' one
        // (see migration 118); members DNAT it back to their awg port.
        $bport = ($backendPort !== null && $backendPort > 0) ? $backendPort : $port;
        $lines = [
            'add table ip amnezia_relay',
            'delete table ip amnezia_relay',
            'table ip amnezia_relay {',
            '    chain prerouting {',
            '        type nat hook prerouting priority dstnat; policy accept;',
        ];
        if ($backends) {
            $map = [];
            foreach (array_values($backends) as $i => $ip) {
                $map[] = $bport === $port ? "{$i} : {$ip}" : "{$i} : {$ip} . {$bport}";
            }
            $lines[] = $bport === $port
                ? sprintf(
                    '        fib daddr type local udp dport %d counter dnat to jhash ip saddr mod %d map { %s }',
                    $port, count($backends), implode(', ', $map)
                )
                : sprintf(
                    '        fib daddr type local udp dport %d counter dnat ip addr . port to jhash ip saddr mod %d map { %s }',
                    $port, count($backends), implode(', ', $map)
                );
        }
        $lines[] = '    }';
        $lines[] = '    chain postrouting {';
        $lines[] = '        type nat hook postrouting priority srcnat; policy accept;';
        if ($backends) {
            $lines[] = sprintf('        ip daddr { %s } udp dport %d counter masquerade', implode(', ', $backends), $bport);
        }
        $lines[] = '    }';
        $lines[] = '}';
        return implode("\n", $lines) . "\n";
    }

    /**
     * Apply a backend set on the front atomically, then drop conntrack flows
     * that were pinned to backends leaving the set (so those clients
     * re-handshake on a live member instead of timing out).
     */
    public static function push(int $poolId, array $front, array $calc, bool $flushAll = false): array
    {
        $pool = ServerPool::get($poolId);
        $port = (int) ($pool['vpn_port'] ?? 443) ?: 443;
        $new = $calc['backends'];
        $old = json_decode((string) ($front['backends_json'] ?? ''), true) ?: [];
        $removed = array_values(array_diff($old, $new));

        $bport = (int) ($front['backend_port'] ?? 0) ?: null;
        $b64 = base64_encode(self::renderRuleset($new, $port, $bport));
        $flush = '';
        foreach ($removed as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $flush .= 'conntrack -D -p udp --reply-src ' . $ip . ' >/dev/null 2>&1; ';
            }
        }
        if ($flushAll || (!$old && $new)) {
            // While there were no backends, client retries created un-NATed
            // flows to the front itself; NAT only applies to a flow's first
            // packet and the ~5s retries keep those entries alive, so without
            // this the clients stay blackholed after members come back.
            $flush .= 'conntrack -D -p udp --orig-port-dst ' . $port . ' >/dev/null 2>&1; ';
        }
        // mktemp: the web "sync" button and the collector may push concurrently.
        $cmd = 'set -e; mkdir -p /etc/amnezia; T=$(mktemp /etc/amnezia/relay.nft.XXXXXX); '
            . 'echo ' . $b64 . ' | base64 -d > "$T"; '
            . 'nft -c -f "$T"; mv "$T" /etc/amnezia/relay.nft; chmod 644 /etc/amnezia/relay.nft; '
            . 'nft -f /etc/amnezia/relay.nft; set +e; ' . $flush . 'echo PUSH_OK';

        try {
            $out = (string) (new VpnServer((int) $front['server_id']))->executeCommand($cmd, true);
            $ok = str_contains($out, 'PUSH_OK');
        } catch (Throwable $e) {
            $ok = false;
            $out = $e->getMessage();
        }

        $msg = $ok
            ? ($new
                ? sprintf('Relay: %d бэкенд(а), группа %s (%s)', count($new), $calc['tier'] === 'primary' ? 'основная' : 'резерв', implode(', ', $new))
                : 'Relay: нет здоровых бэкендов — фронт никого не пропускает')
            : ('Push на фронт не удался: ' . trim(substr($out, -300)));

        if ($ok) {
            DB::conn()->prepare(
                'UPDATE pool_fronts SET backends_json = ?, tier = ?, last_push_at = NOW(), last_push_msg = ? WHERE id = ?'
            )->execute([json_encode(array_values($new)), $calc['tier'], $msg, (int) $front['id']]);
        } else {
            DB::conn()->prepare('UPDATE pool_fronts SET last_push_msg = ? WHERE id = ?')->execute([$msg, (int) $front['id']]);
        }
        return ['success' => $ok, 'message' => $msg, 'changed' => true, 'removed' => $removed];
    }

    /** Recompute backends and push if they changed (or $force). */
    public static function sync(int $poolId, bool $force = false): array
    {
        $front = self::forPool($poolId);
        if (!$front || (int) $front['enabled'] !== 1) {
            return ['success' => false, 'message' => 'Фронт не подключён или выключен'];
        }
        $calc = self::computeBackends($poolId, $front);
        $old = json_decode((string) ($front['backends_json'] ?? ''), true) ?: [];
        $changed = $old !== $calc['backends'] || (string) ($front['tier'] ?? '') !== $calc['tier'];
        if (!$force && !$changed) {
            return ['success' => true, 'message' => 'Без изменений', 'changed' => false, 'calc' => $calc];
        }
        $res = self::push($poolId, $front, $calc);
        $res['calc'] = $calc;
        return $res;
    }

    /**
     * Monitoring-cycle pass for every front: keep the backend set current, and
     * fall the pool domain back to a healthy member when the front is down.
     */
    public static function syncAll(int $threshold = 2, bool $autoFallback = true): array
    {
        $results = [];
        try {
            $fronts = DB::conn()->query('SELECT pool_id FROM pool_fronts WHERE enabled = 1')->fetchAll(PDO::FETCH_COLUMN);
        } catch (Throwable $e) {
            return $results;
        }
        foreach ($fronts as $poolId) {
            // One pool's failure (SSH throw, DB hiccup) must not skip the rest.
            try {
                $r = self::syncOne((int) $poolId, $threshold, $autoFallback);
                if ($r !== null) {
                    $results[] = $r;
                }
            } catch (Throwable $e) {
                $results[] = ['pool' => (int) $poolId, 'action' => 'front_error', 'ok' => false, 'message' => $e->getMessage()];
            }
        }
        return $results;
    }

    /** One front's monitoring pass; returns a log row when something happened. */
    private static function syncOne(int $poolId, int $threshold, bool $autoFallback): ?array
    {
        $front = self::forPool($poolId);
        if (!$front) {
            return null;
        }
        if (self::frontDown((int) $front['server_id'], $threshold)) {
            if ($front['dns_mode'] !== 'front') {
                return null;
            }
            // The health checks are SSH-based, but the relay is kernel NAT and
            // keeps forwarding while sshd is busy (brute force, MaxStartups,
            // per-source penalties). Moving the domain off a working front
            // pushes every client onto the member's foreign IP — so only fall
            // back when the relay itself shows no sign of life.
            $sshFailing = self::checksOpen((int) $front['server_id'], ['ssh'], 1);
            $alive = self::relayEvidentlyAlive($poolId, $front, $sshFailing);
            if ($alive !== null) {
                self::event($front, 'pool_front_ssh_degraded', "RU-фронт {$front['server_name']}: панель не может зайти по SSH, но relay работает ({$alive}) — домен не переключаю.", 'warning');
                return ['pool' => $poolId, 'action' => 'front_ssh_degraded', 'ok' => true, 'message' => $alive];
            }
            if (!$autoFallback) {
                self::event($front, 'pool_front_down', "RU-фронт {$front['server_name']} недоступен, а авто-failover выключен — домен остаётся на фронте, переключите вручную.", 'critical');
                return ['pool' => $poolId, 'action' => 'front_down', 'ok' => false, 'message' => 'auto-failover disabled'];
            }
            $fb = self::pointDomainToMember($poolId, 'auto_front_down');
            self::event($front, 'pool_front_fallback', $fb['success']
                ? "RU-фронт {$front['server_name']} недоступен — домен пула переключён напрямую на сервер: " . ($fb['message'] ?? '')
                : "RU-фронт {$front['server_name']} недоступен, и переключить домен на сервер не удалось: " . ($fb['message'] ?? ''), 'critical');
            return ['pool' => $poolId, 'action' => 'front_fallback', 'ok' => $fb['success'], 'message' => $fb['message'] ?? ''];
        }
        // Keep the backend-port DNAT on members current (new member, container
        // recreated with another IP, reboot).
        if ((int) ($front['backend_port'] ?? 0) > 0
            && function_exists('shouldRunPeriodicTask') && shouldRunPeriodicTask('front_backend_port', $poolId, 600)) {
            self::applyBackendPort($poolId);
        }
        // Keep "front only" in step with membership (new member, changed IPs).
        if ($front['dns_mode'] === 'front' && (int) ($front['members_front_only'] ?? 0) === 1
            && function_exists('shouldRunPeriodicTask') && shouldRunPeriodicTask('front_only_enforce', $poolId, 600)) {
            self::applyFrontOnly($poolId, true);
        }
        $res = self::sync($poolId);
        if (empty($res['changed'])) {
            return null;
        }
        if (($res['calc']['tier'] ?? '') === 'none' && $front['dns_mode'] === 'front') {
            self::event($front, 'pool_front_no_backends',
                "RU-фронт {$front['server_name']}: нет ни одного здорового сервера пула — клиенты не подключатся.", 'critical');
        } elseif (($res['calc']['tier'] ?? '') === 'reserve') {
            self::event($front, 'pool_front_reserve',
                "RU-фронт {$front['server_name']}: серверов основной страны {$front['primary_country']} нет в строю — клиенты идут через резерв (другая страна выхода).", 'warning');
        }
        return ['pool' => $poolId, 'action' => 'front_push', 'ok' => $res['success'], 'message' => $res['message']];
    }

    // ------------------------------------------------------------ DNS target

    /** Point the pool domain at the front (after a fresh push). */
    public static function pointDomainToFront(int $poolId): array
    {
        $pool = ServerPool::get($poolId);
        $front = self::forPool($poolId);
        if (!$pool || !$front || (int) $front['enabled'] !== 1) {
            return ['success' => false, 'message' => 'Фронт не подключён или выключен'];
        }
        $domain = trim((string) ($pool['domain'] ?? ''));
        if ($domain === '') {
            return ['success' => false, 'message' => 'У пула не задан домен'];
        }
        if (!DnsManager::isConfigured()) {
            return ['success' => false, 'message' => 'DNS-провайдер не настроен (Настройки → API)'];
        }
        if (self::frontDown((int) $front['server_id'], 1)) {
            return ['success' => false, 'message' => 'Фронт сейчас не проходит health-проверки — сначала почините его'];
        }
        $sync = self::sync($poolId, true);
        if (empty($sync['success']) || empty($sync['calc']['backends'])) {
            return ['success' => false, 'message' => 'Нет здоровых бэкендов для фронта: ' . ($sync['message'] ?? '')];
        }
        // Same per-pool lock as ServerPool::setActive(): a concurrent failover
        // must not repoint DNS to a member between our upsert and the mode flip.
        $db = DB::conn();
        $lockName = 'amnezia_pool_active_' . $poolId;
        $lk = $db->prepare('SELECT GET_LOCK(?, 10)');
        $lk->execute([$lockName]);
        if ((int) $lk->fetchColumn() !== 1) {
            return ['success' => false, 'message' => 'Пул занят другим переключением — повторите через несколько секунд'];
        }
        try {
            $dns = DnsManager::upsertARecord($domain, (string) $front['server_host']);
            if (empty($dns['success'])) {
                return ['success' => false, 'message' => 'DNS не обновился: ' . ($dns['message'] ?? '')];
            }
            $db->prepare("UPDATE pool_fronts SET dns_mode = 'front' WHERE id = ?")->execute([(int) $front['id']]);
        } finally {
            $db->prepare('SELECT RELEASE_LOCK(?)')->execute([$lockName]);
        }
        self::event($front, 'pool_domain_front', "Домен {$domain} переключён на RU-фронт {$front['server_name']} ({$front['server_host']}). " . $sync['message'], 'warning');
        if ((int) ($front['members_front_only'] ?? 0) === 1) {
            self::applyFrontOnly($poolId, true);
        }
        return ['success' => true, 'message' => "Домен {$domain} → фронт {$front['server_host']}. " . $sync['message'] . ' Клиенты переедут при переподключении.'];
    }

    /**
     * Point the pool domain back at a member (the active one if healthy, else
     * the best healthy standby). Used manually and as the front-down fallback.
     */
    public static function pointDomainToMember(int $poolId, string $reason = 'manual'): array
    {
        $front = self::forPool($poolId);
        if (!$front) {
            return ['success' => false, 'message' => 'Фронт не подключён'];
        }
        $target = ServerPool::healthyTarget($poolId);
        if ($target === null) {
            return ['success' => false, 'message' => 'Нет здорового сервера пула для переключения домена'];
        }
        // Clients are about to reach a member directly: reopen the VPN port
        // first (the setting is kept and re-applied when the domain returns).
        // Best-effort — with the front down, staying locked helps nobody.
        if ((int) ($front['members_front_only'] ?? 0) === 1) {
            $lift = self::applyFrontOnly($poolId, false);
            if (empty($lift['success'])) {
                self::event($front, 'pool_front_only_lift_failed', 'Не удалось снять ограничение «только через фронт» перед переключением домена на сервер: ' . $lift['message'], 'critical');
            }
        }
        // Flip first so setActive() repoints DNS (it skips DNS while on the front).
        // On ANY failure — including an exception from SSH inside setActive —
        // restore the previous mode: "member" with DNS still on a dead front
        // would never be retried by the collector.
        $db = DB::conn();
        $db->prepare("UPDATE pool_fronts SET dns_mode = 'member' WHERE id = ?")->execute([(int) $front['id']]);
        try {
            $res = ServerPool::setActive($poolId, $target, $reason);
        } catch (Throwable $e) {
            $res = ['success' => false, 'message' => $e->getMessage()];
        }
        $dnsOk = !empty($res['success']) && (($res['dns']['action'] ?? '') !== 'skipped');
        if (!$dnsOk) {
            $db->prepare("UPDATE pool_fronts SET dns_mode = ? WHERE id = ?")->execute([$front['dns_mode'], (int) $front['id']]);
            return ['success' => false, 'message' => $res['message'] ?? 'setActive failed'];
        }
        return ['success' => true, 'message' => $res['message'] ?? 'ok'];
    }

    // --------------------------------------------------------------- settings

    public static function setRelayGroup(int $serverId, string $group): array
    {
        $group = strtolower(trim($group));
        if ($group !== 'auto' && !in_array($group, self::GROUPS, true)) {
            return ['success' => false, 'message' => 'Группа: auto | primary | reserve | off'];
        }
        $st = DB::conn()->prepare('SELECT pool_id FROM vpn_servers WHERE id = ?');
        $st->execute([$serverId]);
        $poolId = (int) $st->fetchColumn();
        if ($poolId <= 0) {
            return ['success' => false, 'message' => 'Сервер не в пуле'];
        }
        DB::conn()->prepare('UPDATE vpn_servers SET relay_group = ? WHERE id = ?')
            ->execute([$group === 'auto' ? null : $group, $serverId]);
        $sync = self::sync($poolId, true);
        return ['success' => true, 'message' => 'Группа сохранена. ' . ($sync['message'] ?? '')];
    }

    public static function setPrimaryCountry(int $poolId, string $country): array
    {
        $country = strtoupper(trim($country));
        if (!preg_match('/^[A-Z]{2}$/', $country)) {
            return ['success' => false, 'message' => 'Код страны — две буквы (например DE)'];
        }
        $front = self::forPool($poolId);
        if (!$front) {
            return ['success' => false, 'message' => 'Фронт не подключён'];
        }
        DB::conn()->prepare('UPDATE pool_fronts SET primary_country = ? WHERE id = ?')->execute([$country, (int) $front['id']]);
        $sync = self::sync($poolId, true);
        return ['success' => true, 'message' => "Основная страна: {$country}. " . ($sync['message'] ?? '')];
    }

    /** Detach the front from the pool (domain must already point at a member). */
    public static function remove(int $poolId): array
    {
        $front = self::forPool($poolId);
        if (!$front) {
            return ['success' => false, 'message' => 'Фронт не подключён'];
        }
        if ($front['dns_mode'] === 'front') {
            return ['success' => false, 'message' => 'Сначала верните домен пула на сервер — иначе клиенты останутся без входа'];
        }
        self::applyFrontOnly($poolId, false);
        try {
            (new VpnServer((int) $front['server_id']))->executeCommand(
                'nft delete table ip amnezia_relay 2>/dev/null; printf "add table ip amnezia_relay\ndelete table ip amnezia_relay\ntable ip amnezia_relay {\n}\n" > /etc/amnezia/relay.nft; echo ok',
                true
            );
        } catch (Throwable $e) {
            error_log('PoolFront::remove: relay flush failed: ' . $e->getMessage());
        }
        DB::conn()->prepare('DELETE FROM pool_fronts WHERE id = ?')->execute([(int) $front['id']]);
        return ['success' => true, 'message' => "Фронт {$front['server_name']} отвязан от пула. Сам сервер остаётся в списке — удалите его там, если больше не нужен."];
    }

    /**
     * Evidence that the front still relays even though SSH checks fail:
     * a client handshake on a member arriving from the front's IP within the
     * last 3 minutes (the relay demonstrably works), else the front's sshd
     * at least completing a TCP handshake (host and its network are up).
     * Returns a short description, or null when there's no sign of life.
     */
    private static function relayEvidentlyAlive(int $poolId, array $front, bool $sshFailing, int $freshSeconds = 180): ?string
    {
        $frontIp = (string) $front['server_host'];
        foreach (ServerPool::members($poolId) as $m) {
            if (($m['status'] ?? '') !== 'active') {
                continue;
            }
            try {
                $peers = (new VpnServer((int) $m['id']))->liveClientPeers(0);
            } catch (Throwable $e) {
                continue;
            }
            foreach ($peers as $p) {
                if (($p['endpoint_ip'] ?? null) === $frontIp && ($p['handshake_age'] ?? null) !== null && $p['handshake_age'] <= $freshSeconds) {
                    return "свежий handshake клиента через фронт на {$m['name']} ({$p['handshake_age']} с назад)";
                }
            }
        }
        // TCP only speaks for the host when SSH is what's failing; with SSH
        // fine and the relay check failing, the relay itself is broken.
        if (!$sshFailing) {
            return null;
        }
        $port = (int) ($front['server_port'] ?? 22) ?: 22;
        $sock = @fsockopen($frontIp, $port, $errno, $errstr, 4.0);
        if ($sock) {
            fclose($sock);
            return "хост отвечает на TCP {$port}";
        }
        return null;
    }

    // ------------------------------------------------- members: front only

    /**
     * Enforce (or lift) "VPN port only from the front" on every active member.
     * An nft table drops VPN-port packets whose source isn't the front or a
     * pool member (the reachability probe runs member→member), before docker's
     * DNAT; a oneshot unit reloads /etc/amnezia/front-only.nft at boot. Lifting
     * writes an empty ruleset. Enforced only while the domain is on the front.
     */
    public static function applyFrontOnly(int $poolId, bool $on): array
    {
        $pool = ServerPool::get($poolId);
        $front = self::forPool($poolId);
        $port = (int) ($pool['vpn_port'] ?? 443) ?: 443;
        $members = array_values(array_filter(ServerPool::members($poolId), static fn($m) => ($m['status'] ?? '') === 'active'));

        $allowed = [];
        if ($front && filter_var((string) $front['server_host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $allowed[] = (string) $front['server_host'];
        }
        foreach ($members as $m) {
            if (filter_var((string) $m['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $allowed[] = (string) $m['host'];
            }
        }
        $allowed = array_values(array_unique($allowed));
        // Never lock everyone out: without the front's IP there is nothing to allow.
        if ($on && ($front === null || !in_array((string) $front['server_host'], $allowed, true))) {
            return ['success' => false, 'message' => 'Не удалось определить IP фронта — ограничение не включено'];
        }

        $lines = ['table inet amnezia_frontonly {}', 'delete table inet amnezia_frontonly'];
        if ($on) {
            $lines[] = 'table inet amnezia_frontonly {';
            $lines[] = '  set allowed { type ipv4_addr; elements = { ' . implode(', ', $allowed) . ' } }';
            $lines[] = '  chain pre {';
            $lines[] = '    type filter hook prerouting priority -200; policy accept;';
            // fib daddr type local: only packets addressed to THIS host's VPN
            // port. Without it the rule also hit the clients' own outbound
            // UDP/443 (QUIC, HTTP/3) leaving the awg2 container via docker0.
            $lines[] = '    fib daddr type local udp dport ' . $port . ' ip saddr != @allowed counter drop';
            $lines[] = '    meta nfproto ipv6 fib daddr type local udp dport ' . $port . ' counter drop';
            $lines[] = '  }';
            $lines[] = '}';
        }
        $rules = implode("\n", $lines) . "\n";
        $unit = "[Unit]\nDescription=Amnezia: VPN port only via the pool front\nAfter=network-online.target docker.service\n"
            . "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f /etc/amnezia/front-only.nft\n"
            . "[Install]\nWantedBy=multi-user.target\n";
        $script = "set -e\nmkdir -p /etc/amnezia\n"
            . 'T=$(mktemp /etc/amnezia/front-only.XXXXXX)' . "\n"
            . 'echo ' . base64_encode($rules) . ' | base64 -d > "$T"' . "\n"
            . 'nft -c -f "$T"' . "\n"
            . 'mv "$T" /etc/amnezia/front-only.nft; chmod 644 /etc/amnezia/front-only.nft' . "\n"
            . 'echo ' . base64_encode($unit) . ' | base64 -d > /etc/systemd/system/amnezia-front-only.service' . "\n"
            . "systemctl daemon-reload\nsystemctl enable amnezia-front-only.service >/dev/null 2>&1\n"
            . "nft -f /etc/amnezia/front-only.nft\necho FRONTONLY_OK\n";
        $cmd = 'echo ' . base64_encode($script) . ' | base64 -d | bash';

        $ok = true;
        $lines = [];
        foreach ($members as $m) {
            try {
                $out = (string) (new VpnServer((int) $m['id']))->executeCommand($cmd, true);
                $mok = str_contains($out, 'FRONTONLY_OK');
            } catch (Throwable $e) {
                $mok = false;
                $out = $e->getMessage();
            }
            $ok = $ok && $mok;
            $lines[] = $m['name'] . ': ' . ($mok ? 'ok' : ('ошибка — ' . trim(substr($out, -200))));
        }
        return [
            'success' => $ok,
            'message' => ($on ? 'Только через фронт: ' : 'Прямой доступ к серверам открыт: ') . implode('; ', $lines),
        ];
    }

    /**
     * Member side of the front's backend port: DNAT front-sourced UDP on
     * backend_port to the awg container's pool port (only from the fronts'
     * IPs, so it is not a second public entrance). Persisted in
     * /etc/amnezia/front-port.nft + amnezia-front-port.service. With no
     * backend port (or equal to the pool port) the table is removed.
     */
    public static function applyBackendPort(int $poolId): array
    {
        $pool = ServerPool::get($poolId);
        $front = self::forPool($poolId);
        $port = (int) ($pool['vpn_port'] ?? 443) ?: 443;
        $bport = (int) ($front['backend_port'] ?? 0);
        $on = $front && $bport > 0 && $bport !== $port
            && filter_var((string) $front['server_host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;

        $ok = true;
        $out = [];
        foreach (ServerPool::members($poolId) as $m) {
            if (($m['status'] ?? '') !== 'active') {
                continue;
            }
            $md = (new VpnServer((int) $m['id']))->getData();
            $container = (string) ($md['container_name'] ?? '') ?: 'amnezia-awg2';
            // The container IP is resolved on the member at apply time.
            $script = "set -e\nmkdir -p /etc/amnezia\n";
            if ($on) {
                $script .= 'CIP=$(docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" ' . escapeshellarg($container) . ' | head -c 15)' . "\n"
                    . 'case "$CIP" in ""|*[!0-9.]*) echo "FRONTPORT_FAIL no container ip"; exit 1;; esac' . "\n"
                    . 'printf "%s\\n" "table ip amnezia_frontport {}" "delete table ip amnezia_frontport" "table ip amnezia_frontport {" '
                    . '"  chain pre {" "    type nat hook prerouting priority -110; policy accept;" '
                    . '"    ip saddr { ' . $front['server_host'] . ' } udp dport ' . $bport . ' counter dnat to $CIP:' . $port . '" "  }" "}" > /etc/amnezia/front-port.nft.new' . "\n";
            } else {
                $script .= 'printf "%s\\n" "table ip amnezia_frontport {}" "delete table ip amnezia_frontport" > /etc/amnezia/front-port.nft.new' . "\n";
            }
            $unit = "[Unit]\nDescription=Amnezia: front backend port DNAT\nAfter=network-online.target docker.service\n"
                . "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f /etc/amnezia/front-port.nft\n"
                . "[Install]\nWantedBy=multi-user.target\n";
            $script .= "nft -c -f /etc/amnezia/front-port.nft.new\n"
                . "mv /etc/amnezia/front-port.nft.new /etc/amnezia/front-port.nft\n"
                . 'echo ' . base64_encode($unit) . ' | base64 -d > /etc/systemd/system/amnezia-front-port.service' . "\n"
                . "systemctl daemon-reload\nsystemctl enable amnezia-front-port.service >/dev/null 2>&1\n"
                . "nft -f /etc/amnezia/front-port.nft\necho FRONTPORT_OK\n";
            try {
                $o = (string) (new VpnServer((int) $m['id']))->executeCommand('echo ' . base64_encode($script) . ' | base64 -d | bash', true);
                $mok = str_contains($o, 'FRONTPORT_OK');
            } catch (Throwable $e) {
                $mok = false;
                $o = $e->getMessage();
            }
            $ok = $ok && $mok;
            $out[] = $m['name'] . ': ' . ($mok ? 'ok' : ('ошибка — ' . trim(substr($o, -200))));
        }
        return ['success' => $ok, 'message' => implode('; ', $out)];
    }

    /**
     * Change the port of the front -> member leg (null = pool port). Members
     * first (so they accept the new port), then the front, flushing all
     * relayed flows so every client re-handshakes on the new path at once.
     */
    public static function setBackendPort(int $poolId, ?int $bport): array
    {
        $front = self::forPool($poolId);
        $pool = ServerPool::get($poolId);
        if (!$front || !$pool) {
            return ['success' => false, 'message' => 'Фронт не подключён'];
        }
        $port = (int) ($pool['vpn_port'] ?? 443) ?: 443;
        if ($bport !== null && ($bport < 1024 || $bport > 65535)) {
            return ['success' => false, 'message' => 'Порт — от 1024 до 65535'];
        }
        if ($bport === $port) {
            $bport = null;
        }
        $prev = $front['backend_port'];
        $db = DB::conn();
        $db->prepare('UPDATE pool_fronts SET backend_port = ? WHERE id = ?')->execute([$bport, (int) $front['id']]);
        $members = self::applyBackendPort($poolId);
        if (empty($members['success'])) {
            $db->prepare('UPDATE pool_fronts SET backend_port = ? WHERE id = ?')->execute([$prev, (int) $front['id']]);
            self::applyBackendPort($poolId);
            return ['success' => false, 'message' => 'Серверы не приняли порт, откатил: ' . $members['message']];
        }
        $front = self::forPool($poolId);
        $res = self::push($poolId, $front, self::computeBackends($poolId, $front), true);
        return [
            'success' => !empty($res['success']),
            'message' => ($bport ? "Фронт → серверы теперь на порту {$bport}. " : "Фронт → серверы на порту пула {$port}. ")
                . $res['message'] . ' Серверы: ' . $members['message'],
        ];
    }

    /** UI switch: store the setting and enforce it if the domain is on the front. */
    public static function setFrontOnly(int $poolId, bool $on): array
    {
        $front = self::forPool($poolId);
        if (!$front) {
            return ['success' => false, 'message' => 'Фронт не подключён'];
        }
        if ($on && $front['dns_mode'] !== 'front') {
            return ['success' => false, 'message' => 'Сначала направьте домен пула на фронт — иначе клиентам некуда переехать'];
        }
        $res = self::applyFrontOnly($poolId, $on);
        if ($on && empty($res['success'])) {
            // Partial apply: roll back so no member is left half-locked.
            self::applyFrontOnly($poolId, false);
            return ['success' => false, 'message' => 'Не удалось включить, изменения откатены. ' . $res['message']];
        }
        DB::conn()->prepare('UPDATE pool_fronts SET members_front_only = ? WHERE id = ?')->execute([$on ? 1 : 0, (int) $front['id']]);
        return $res;
    }

    // ---------------------------------------------------------- client paths

    /**
     * Stamp live peers with via_front: true when the client's packets arrive
     * from the front's IP, false when it reaches the member directly (it kept
     * an address resolved before the domain moved to the front — the first to
     * break when the member's foreign IP is throttled). Untouched (no key)
     * unless the pool domain currently points at the front.
     */
    public static function stampViaFront(int $poolId, array $peers): array
    {
        $front = self::forPool($poolId);
        if (!$front || (int) $front['enabled'] !== 1 || $front['dns_mode'] !== 'front') {
            return $peers;
        }
        $frontIp = (string) $front['server_host'];
        foreach ($peers as $pk => $info) {
            $ip = $info['endpoint_ip'] ?? null;
            if ($ip !== null && $ip !== '') {
                $peers[$pk]['via_front'] = ($ip === $frontIp);
            }
        }
        return $peers;
    }

    /**
     * Live clients of the pool split by path (front vs direct), for the front
     * card. A client counts as live with a handshake in the last 3 minutes.
     */
    public static function clientPaths(int $poolId, int $liveSeconds = 180): array
    {
        $front = self::forPool($poolId);
        $frontMode = $front && (int) $front['enabled'] === 1 && $front['dns_mode'] === 'front';
        $peers = [];
        foreach (ServerPool::members($poolId) as $m) {
            try {
                $mp = (new VpnServer((int) $m['id']))->liveClientPeers();
            } catch (Throwable $e) {
                continue;
            }
            foreach ($mp as $pk => $info) {
                $age = $info['handshake_age'] ?? null;
                if ($age === null || $age > $liveSeconds) {
                    continue;
                }
                if (!isset($peers[$pk]) || $age < $peers[$pk]['handshake_age']) {
                    $peers[$pk] = $info + ['server_name' => (string) $m['name']];
                }
            }
        }
        $peers = self::stampViaFront($poolId, $peers);

        $names = [];
        $st = DB::conn()->query('SELECT public_key, name FROM vpn_clients');
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $names[(string) $r['public_key']] = (string) $r['name'];
        }
        $via = [];
        $direct = [];
        foreach ($peers as $pk => $info) {
            $row = [
                'name' => $names[(string) $pk] ?? ('…' . substr((string) $pk, 0, 8)),
                'server' => $info['server_name'],
                'ip' => $info['endpoint_ip'] ?? null,
            ];
            if (($info['via_front'] ?? null) === false) {
                $direct[] = $row;
            } else {
                $via[] = $row;
            }
        }
        usort($direct, static fn($a, $b) => strcmp($a['name'], $b['name']));
        usort($via, static fn($a, $b) => strcmp($a['name'], $b['name']));
        return ['front_mode' => $frontMode, 'via_front' => $via, 'direct' => $direct];
    }

    // -------------------------------------------------------------------- UI

    /** Everything the pools page needs to render the front card. */
    public static function uiStatus(int $poolId): ?array
    {
        $front = self::forPool($poolId);
        if (!$front) {
            return null;
        }
        $sid = (int) $front['server_id'];
        $health = [];
        foreach (self::CRITICAL_CHECKS as $c) {
            $health[$c] = !self::checksOpen($sid, [$c], 1);
        }
        return [
            'front' => $front,
            'health' => $health,
            'down' => self::frontDown($sid, 1),
            'calc' => self::computeBackends($poolId, $front),
            'backends' => json_decode((string) ($front['backends_json'] ?? ''), true) ?: [],
            'blocked_ports' => array_map('intval', json_decode((string) ($front['blocked_ports'] ?? ''), true) ?: []),
        ];
    }

    private static function event(array $front, string $name, string $msg, string $severity): void
    {
        try {
            (new AlertManager())->recordEvent(
                (int) $front['server_id'],
                (string) ($front['server_name'] ?? 'front'),
                $name,
                $msg,
                $severity,
                'front:' . $front['id'] . ':' . $name . ':' . floor(time() / 600)
            );
        } catch (Throwable $e) {
            error_log('PoolFront event failed: ' . $e->getMessage());
        }
    }
}
