<?php

/**
 * ServerPool — a set of VPN servers that share ONE awg2 server identity
 * (keypair + preshared key + AmneziaWG obfuscation params + subnet + port +
 * domain) and every client peer, so a single client config works against any
 * member. The pool's domain A-record points at the active member; on failure
 * monitoring repoints it to a healthy member (DNS failover).
 *
 * Secrets (server_private_key, preshared_key) are stored encrypted via
 * SecretBox and only decrypted when deploying a member.
 */
class ServerPool
{
    /** Return a pool row with secrets decrypted, or null. */
    public static function get(int $poolId): ?array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM server_pools WHERE id = ? LIMIT 1');
        $stmt->execute([$poolId]);
        $pool = $stmt->fetch(PDO::FETCH_ASSOC);
        return $pool ? self::decryptPool($pool) : null;
    }

    /** The pool a server belongs to, or null. */
    public static function getForServer(int $serverId): ?array
    {
        $stmt = DB::conn()->prepare('SELECT pool_id FROM vpn_servers WHERE id = ? LIMIT 1');
        $stmt->execute([$serverId]);
        $poolId = (int) $stmt->fetchColumn();
        return $poolId > 0 ? self::get($poolId) : null;
    }

    /** Member servers of a pool, ordered by failover priority then id. */
    public static function members(int $poolId): array
    {
        $stmt = DB::conn()->prepare(
            'SELECT id, name, host, domain, status, pool_priority, pool_sync_pending, last_check_at,
                    validated_clean, validated_at, validation_note
             FROM vpn_servers WHERE pool_id = ? ORDER BY pool_priority ASC, id ASC'
        );
        $stmt->execute([$poolId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Build a full-tunnel "AllowedIPs" list (0.0.0.0/0 minus exclusions) that
     * carves out EVERY pool member's ingress IP, not just the active one.
     *
     * A router/full-tunnel peer must not route the encrypted tunnel packets back
     * into the tunnel, so the current endpoint IP is normally excluded. In a
     * failover pool the active IP rotates via DNS, so excluding only the active
     * one breaks after failover. Excluding all member IPs makes the config
     * survive any in-pool failover; it only needs regenerating when a NEW member
     * is added to the pool.
     *
     * @param string[] $extraExcludes Router-local CIDRs to also carve out
     *                                (own address, LAN, docker bridges).
     * @return array{allowed_ips:string,member_ips:string[],excluded:string[]}
     */
    public static function allowedIpsExcludingPool(int $poolId, array $extraExcludes = []): array
    {
        $memberIps = [];
        foreach (self::members($poolId) as $m) {
            $host = trim((string) ($m['host'] ?? ''));
            if ($host !== '' && filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $memberIps[] = $host . '/32';
            }
        }
        $memberIps = array_values(array_unique($memberIps));

        $extra = [];
        foreach ($extraExcludes as $e) {
            $e = trim((string) $e);
            if ($e !== '') {
                $extra[] = $e;
            }
        }

        $excluded = array_merge($memberIps, $extra);
        $allowed = CidrMath::complement($excluded);

        return [
            'allowed_ips' => implode(', ', $allowed),
            'member_ips'  => $memberIps,
            'excluded'    => $excluded,
        ];
    }

    public static function list(): array
    {
        return DB::conn()->query('SELECT * FROM server_pools ORDER BY name')->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * The pool whose shared domain equals $domain, or null. Used to stop a
     * non-active node (even a standalone server that carries the same domain,
     * e.g. right after provisioning) from hijacking a pool's shared A-record.
     */
    public static function findByDomain(string $domain): ?array
    {
        $domain = trim($domain);
        if ($domain === '') {
            return null;
        }
        $stmt = DB::conn()->prepare('SELECT * FROM server_pools WHERE domain = ? LIMIT 1');
        $stmt->execute([$domain]);
        $pool = $stmt->fetch(PDO::FETCH_ASSOC);
        return $pool ? self::decryptPool($pool) : null;
    }

    /**
     * UI-facing pool status: members with their role (active = domain points
     * here / standby) and where the domain's A-record actually resolves right
     * now. Fast (one DNS lookup, no per-member SSH).
     */
    public static function status(int $poolId): ?array
    {
        $pool = self::get($poolId);
        if (!$pool) {
            return null;
        }
        $activeId = (int) ($pool['active_server_id'] ?? 0);
        $domain = trim((string) ($pool['domain'] ?? ''));

        // Use the provider's authoritative record, not the local resolver cache
        // (which can lag by the record TTL and show a stale IP after failover).
        $resolved = [];
        if ($domain !== '') {
            $resolved = DnsManager::currentARecordIps($domain);
            if (empty($resolved)) {
                foreach (@dns_get_record($domain, DNS_A) ?: [] as $rec) {
                    if (!empty($rec['ip'])) {
                        $resolved[] = $rec['ip'];
                    }
                }
            }
        }

        $members = [];
        foreach (self::members($poolId) as $m) {
            $members[] = [
                'id' => (int) $m['id'],
                'name' => $m['name'],
                'host' => $m['host'],
                'priority' => (int) $m['pool_priority'],
                'status' => $m['status'],
                'role' => ((int) $m['id'] === $activeId) ? 'active' : 'standby',
                'dns_points_here' => in_array($m['host'], $resolved, true),
                'sync_pending' => (int) ($m['pool_sync_pending'] ?? 0) === 1,
                'validated_clean' => is_null($m['validated_clean'] ?? null) ? null : (int) $m['validated_clean'],
                'validation_note' => $m['validation_note'] ?? null,
            ];
        }

        return [
            'pool' => [
                'id' => (int) $pool['id'],
                'name' => $pool['name'],
                'domain' => $domain,
                'vpn_port' => (int) ($pool['vpn_port'] ?? 443),
                'vpn_subnet' => $pool['vpn_subnet'],
                'active_server_id' => $activeId,
            ],
            'members' => $members,
            'resolved_ips' => $resolved,
            'provider_configured' => DnsManager::isConfigured(),
        ];
    }

    /**
     * Create a pool by ADOPTING an existing deployed server: its awg2 identity
     * (keys/PSK/params/subnet/port/domain) becomes the pool identity. The
     * private key is read from the server's awg0.conf (it is not stored in the
     * DB). The server becomes the first, active member.
     *
     * @return array{success: bool, pool_id?: int, message: string}
     */
    public static function createFromServer(int $serverId, string $poolName): array
    {
        $server = new VpnServer($serverId);
        $data = $server->getData();
        if (!$data) {
            return ['success' => false, 'message' => "Server {$serverId} not found"];
        }
        if (!empty($data['pool_id'])) {
            return ['success' => false, 'message' => 'Server is already in a pool'];
        }

        $pub = trim((string) ($data['server_public_key'] ?? ''));
        $psk = trim((string) ($data['preshared_key'] ?? ''));
        if ($pub === '' || $psk === '') {
            return ['success' => false, 'message' => 'Server has no awg2 identity yet (deploy it first)'];
        }

        $priv = self::readServerPrivateKey($server);
        if ($priv === '') {
            return ['success' => false, 'message' => 'Could not read server private key from awg0.conf'];
        }

        $awgParams = $data['awg_params'] ?? null;
        if (is_array($awgParams)) {
            $awgParams = json_encode($awgParams);
        }

        $pdo = DB::conn();
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare(
                'INSERT INTO server_pools
                 (name, domain, server_public_key, server_private_key, preshared_key, awg_params, vpn_subnet, vpn_port, active_server_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );
            $stmt->execute([
                $poolName,
                trim((string) ($data['domain'] ?? '')) ?: null,
                $pub,
                SecretBox::encryptNullable($priv),
                SecretBox::encryptNullable($psk),
                $awgParams,
                $data['vpn_subnet'] ?? null,
                (int) ($data['vpn_port'] ?? 443) ?: 443,
                $serverId,
            ]);
            $poolId = (int) $pdo->lastInsertId();

            $pdo->prepare('UPDATE vpn_servers SET pool_id = ?, pool_priority = 0 WHERE id = ?')
                ->execute([$poolId, $serverId]);

            $pdo->commit();
        } catch (Throwable $e) {
            $pdo->rollBack();
            return ['success' => false, 'message' => 'Failed to create pool: ' . $e->getMessage()];
        }

        // Point the pool domain at the founding (active) member so the pool is
        // usable at once — otherwise clients/the badge see "домен ≠ активный".
        $domain = trim((string) ($data['domain'] ?? ''));
        $dnsMsg = '';
        if ($domain !== '' && DnsManager::isConfigured()) {
            try {
                $dns = DnsManager::upsertARecord($domain, (string) ($data['host'] ?? ''));
                $dnsMsg = !empty($dns['success'])
                    ? ' Домен указан на этот сервер.'
                    : ' ВНИМАНИЕ: домен не обновлён — ' . ($dns['message'] ?? '?');
            } catch (Throwable $e) {
                $dnsMsg = ' DNS-репойнт не удался: ' . $e->getMessage();
            }
        }
        return ['success' => true, 'pool_id' => $poolId, 'message' => "Pool '{$poolName}' created from server {$serverId}." . $dnsMsg];
    }

    /**
     * Point the pool's domain A-record at $serverId and mark it active.
     * Used by manual "make active" and by automatic failover.
     *
     * @return array{success: bool, message: string, dns?: array}
     */
    public static function setActive(int $poolId, int $serverId, string $reason = 'manual'): array
    {
        $pool = self::get($poolId);
        if (!$pool) {
            return ['success' => false, 'message' => "Pool {$poolId} not found"];
        }
        $target = null;
        foreach (self::members($poolId) as $m) {
            if ((int) $m['id'] === $serverId) {
                $target = $m;
                break;
            }
        }
        if (!$target) {
            return ['success' => false, 'message' => "Server {$serverId} is not a member of this pool"];
        }

        // Safety: never repoint to a member that isn't actually serving the pool's
        // clients on its LIVE awg0 interface. Peers can be absent even when
        // pool_sync_pending = 0 (they live in clientsTable/`awg set`, not awg0.conf,
        // so a container restart drops them). Activating a peer-less member
        // black-holes every client — this exact gap caused a full outage.
        $memberIds = array_map(static fn($m) => (int) $m['id'], self::members($poolId));
        $expectedPeers = 0;
        if (!empty($memberIds)) {
            $in = implode(',', array_fill(0, count($memberIds), '?'));
            $stmtC = DB::conn()->prepare(
                // Must mirror reconcilePeers() exactly: it skips rows with an
                // empty client_ip, so counting them here would make expectedPeers
                // permanently exceed the live peer count and silently block both
                // manual switching and auto-failover.
                "SELECT COUNT(DISTINCT public_key) FROM vpn_clients
                 WHERE server_id IN ($in) AND status = 'active' AND public_key <> '' AND client_ip <> ''"
            );
            $stmtC->execute($memberIds);
            $expectedPeers = (int) $stmtC->fetchColumn();
        }
        if ($expectedPeers > 0) {
            $targetData = (new VpnServer($serverId))->getData();
            $tc = (string) ($targetData['container_name'] ?? '') ?: 'amnezia-awg2';
            $livePeers = (int) trim((string) (new VpnServer($serverId))->executeCommand(
                'docker exec ' . escapeshellarg($tc) . ' awg show awg0 allowed-ips 2>/dev/null | grep -c "/32"',
                true
            ));
            if ($livePeers < $expectedPeers) {
                error_log("ServerPool::setActive REFUSED #{$serverId}: {$livePeers}/{$expectedPeers} live peers");
                return [
                    'success' => false,
                    'message' => "Отказ активировать #{$serverId} ({$target['name']}): на живом интерфейсе {$livePeers}/{$expectedPeers} клиентских пиров — сначала «Ре-синк» (иначе клиенты не подключатся).",
                    'live_peers' => $livePeers,
                    'expected_peers' => $expectedPeers,
                ];
            }
        }

        $oldActive = (int) ($pool['active_server_id'] ?? 0);
        $host = (string) $target['host'];
        $domain = trim((string) ($pool['domain'] ?? ''));
        $response = ['success' => true, 'message' => "Active server set to {$target['name']} (#{$serverId})"];

        // A domain is the whole point of the pool: if we can't repoint it, the
        // clients still resolve to the OLD active member. Do NOT flip
        // active_server_id in that case — leave it so the next failover cycle
        // (or a manual retry after fixing the token) tries the repoint again.
        $dnsOk = true;
        if ($domain !== '') {
            if (!DnsManager::isConfigured()) {
                $response['dns'] = ['success' => false, 'message' => 'DNS provider token not configured — A-record not updated'];
                $dnsOk = false;
            } else {
                $dns = DnsManager::upsertARecord($domain, $host);
                $response['dns'] = $dns;
                $dnsOk = !empty($dns['success']);
            }
        }

        if (!$dnsOk) {
            $response['success'] = false;
            $response['message'] = 'DNS repoint failed; active member left unchanged: ' . ($response['dns']['message'] ?? 'unknown');
            error_log("ServerPool: pool {$poolId} DNS repoint to #{$serverId} ({$host}) FAILED — active unchanged");
            return $response;
        }

        DB::conn()->prepare('UPDATE server_pools SET active_server_id = ? WHERE id = ?')
            ->execute([$serverId, $poolId]);
        error_log("ServerPool: pool {$poolId} active -> server {$serverId} ({$host}), reason={$reason}");

        // Notify on an actual change of the active member (manual or failover).
        if ($oldActive !== $serverId) {
            self::notifyActiveChange($pool, $oldActive, $target, $reason, $response['dns'] ?? null);
        }

        return $response;
    }

    /** Send an alert (Telegram/email) when a pool's active member changes. */
    private static function notifyActiveChange(array $pool, int $oldActive, array $target, string $reason, ?array $dns): void
    {
        try {
            $poolId = (int) $pool['id'];
            $newId = (int) $target['id'];
            $oldName = '';
            if ($oldActive > 0) {
                $stmt = DB::conn()->prepare('SELECT name FROM vpn_servers WHERE id = ?');
                $stmt->execute([$oldActive]);
                $oldName = (string) $stmt->fetchColumn();
            }
            $domain = trim((string) ($pool['domain'] ?? ''));
            $dnsNote = $dns ? (empty($dns['success']) ? ' [DNS: ' . ($dns['message'] ?? 'ошибка') . ']' : '') : '';
            $msg = sprintf(
                "Пул «%s»: активный сервер → %s (#%d)%s. %sПричина: %s.%s",
                $pool['name'],
                $target['name'],
                $newId,
                $oldActive > 0 ? sprintf(' (был %s #%d)', $oldName !== '' ? $oldName : '?', $oldActive) : '',
                $domain !== '' ? "Домен {$domain} → {$target['host']}. " : '',
                $reason,
                $dnsNote
            );
            // Short (≈2 min) flap window in the dedupe key: rapid flapping is
            // suppressed, but genuine active-server changes minutes apart each
            // notify (a long cooldown would hide a real re-failover).
            (new AlertManager())->recordEvent(
                $newId,
                (string) $target['name'],
                'pool_active_changed',
                $msg,
                strpos($reason, 'failover') !== false ? 'critical' : 'warning',
                'pool:' . $poolId . ':active:' . $newId . ':' . floor(time() / 120)
            );
        } catch (Throwable $e) {
            error_log('ServerPool::notifyActiveChange failed: ' . $e->getMessage());
        }
    }

    // Health checks that indicate a member can no longer serve clients.
    private const CRITICAL_CHECKS = ['ssh', 'container_running', 'wireguard_interface'];

    /**
     * Choose the best healthy failover target (lowest priority, healthy,
     * excluding the current active/failed server) and switch to it.
     *
     * @return array{success: bool, message: string}
     */
    public static function failover(int $poolId, ?int $excludeServerId = null): array
    {
        $pool = self::get($poolId);
        if (!$pool) {
            return ['success' => false, 'message' => "Pool {$poolId} not found"];
        }
        $exclude = $excludeServerId ?? (int) ($pool['active_server_id'] ?? 0);
        $candidate = self::pickHealthyStandby($poolId, $exclude, 1);
        if ($candidate === null) {
            return ['success' => false, 'message' => 'No healthy failover candidate available in pool'];
        }
        return self::setActive($poolId, $candidate, 'failover');
    }

    /**
     * Auto-heal + failover pass (run each monitoring cycle): for every pool whose
     * active member has been failing critical health checks for >= $threshold
     * cycles, FIRST try to self-heal (restart the awg2 container) for up to
     * $maxRepairs attempts; only when repair is exhausted (or SSH itself is down,
     * so we can't heal) repoint the domain to a healthy standby.
     *
     * Deliberately uses the panel's own health checks (ssh/container/interface),
     * NOT a server-to-server UDP probe (that gives false negatives). No
     * auto-failback.
     *
     * @return array<int, array{pool:int, action:string, from?:int, to?:int, server?:int, attempt?:int, max?:int, ok?:bool, reason?:string}>
     */
    public static function checkAndFailover(int $threshold = 3, int $maxRepairs = 2): array
    {
        $maxRepairs = max(0, $maxRepairs);
        $results = [];
        foreach (self::list() as $pool) {
            $poolId = (int) $pool['id'];
            $activeId = (int) ($pool['active_server_id'] ?? 0);
            if ($activeId <= 0) {
                continue;
            }
            if (!self::memberCriticalDown($activeId, $threshold)) {
                // Active is healthy. If we'd been repairing it and it recovered,
                // announce the self-heal, then clear the counter.
                $prior = self::repairAttempts($poolId, $activeId);
                if ($prior > 0) {
                    error_log("ServerPool: pool {$poolId} active #{$activeId} recovered after {$prior} self-heal attempt(s)");
                    self::notifySelfHeal($poolId, $activeId, $prior);
                }
                self::clearRepairState($poolId, $activeId);
                continue;
            }

            // Active member is DOWN. Decide: self-heal first, or fail over.
            $sshDown = self::checkOpen($activeId, 'ssh', $threshold);
            $attempts = self::repairAttempts($poolId, $activeId);

            // If SSH is reachable and we still have repair budget, try to fix it
            // in place before disturbing clients with a failover. We only ISSUE
            // the restart here and count the attempt — whether it worked is
            // judged by the NEXT monitoring cycle's health checks (authoritative),
            // not by an inline probe (SSH to a struggling host can time out and
            // give a false "still down").
            if (!$sshDown && $attempts < $maxRepairs) {
                $issued = self::attemptRepair($activeId);
                self::recordRepairAttempt($poolId, $activeId);
                error_log(sprintf(
                    "ServerPool: pool %d active #%d DOWN — self-heal attempt %d/%d (%s); awaiting next health cycle",
                    $poolId, $activeId, $attempts + 1, $maxRepairs, $issued ? 'restart issued' : 'restart command failed'
                ));
                $results[] = [
                    'pool' => $poolId, 'action' => 'repair_attempt',
                    'server' => $activeId, 'attempt' => $attempts + 1, 'max' => $maxRepairs, 'ok' => $issued,
                ];
                continue; // give the next monitoring cycle a chance to confirm health
            }

            // Repair budget exhausted (or SSH is down and we can't heal) — fail over.
            $candidate = self::pickHealthyStandby($poolId, $activeId, $threshold);
            if ($candidate === null) {
                error_log("ServerPool: pool {$poolId} active #{$activeId} is DOWN but no healthy standby available");
                $results[] = ['pool' => $poolId, 'action' => 'no_candidate', 'from' => $activeId];
                continue;
            }
            $reason = $sshDown ? 'auto_failover (ssh down, self-heal impossible)' : 'auto_failover (self-heal exhausted)';
            error_log("ServerPool: pool {$poolId} {$reason} #{$activeId} -> #{$candidate}");
            $res = self::setActive($poolId, $candidate, $reason);
            if (empty($res['success'])) {
                // DNS repoint failed — active stayed on the dead member. Keep the
                // repair state and retry next cycle instead of pretending we
                // failed over.
                error_log("ServerPool: pool {$poolId} failover #{$activeId} -> #{$candidate} did NOT take (DNS): " . ($res['message'] ?? ''));
                $results[] = ['pool' => $poolId, 'action' => 'failover_failed', 'from' => $activeId, 'to' => $candidate, 'reason' => $res['message'] ?? 'dns'];
                continue;
            }
            self::clearRepairState($poolId, $activeId);
            $results[] = ['pool' => $poolId, 'action' => 'failover', 'from' => $activeId, 'to' => $candidate, 'reason' => $reason];
        }
        return $results;
    }

    /**
     * Issue a best-effort restart of a member's awg2 service: start the container
     * if it's stopped, otherwise restart it. Returns true if the restart command
     * was sent without an SSH-layer error (NOT a health verdict — the next
     * monitoring cycle confirms whether the member actually recovered).
     */
    private static function attemptRepair(int $serverId): bool
    {
        try {
            $server = new VpnServer($serverId);
            $data = $server->getData();
            if (!$data) {
                return false;
            }
            $container = trim((string) ($data['container_name'] ?? 'amnezia-awg2')) ?: 'amnezia-awg2';
            $server->executeCommand(
                "docker start {$container} 2>/dev/null || docker restart {$container} 2>/dev/null || true",
                true
            );
            return true;
        } catch (Throwable $e) {
            error_log("ServerPool::attemptRepair(#{$serverId}) failed: " . $e->getMessage());
            return false;
        }
    }

    /** How many self-heal attempts have been made for this active member. */
    private static function repairAttempts(int $poolId, int $serverId): int
    {
        $stmt = DB::conn()->prepare('SELECT repair_attempts FROM pool_repair_state WHERE pool_id = ? AND server_id = ?');
        $stmt->execute([$poolId, $serverId]);
        $v = $stmt->fetchColumn();
        return $v === false ? 0 : (int) $v;
    }

    /** Record one self-heal attempt (upsert, bump the counter). */
    private static function recordRepairAttempt(int $poolId, int $serverId): void
    {
        $stmt = DB::conn()->prepare(
            'INSERT INTO pool_repair_state (pool_id, server_id, repair_attempts, last_repair_at)
             VALUES (?, ?, 1, NOW())
             ON DUPLICATE KEY UPDATE repair_attempts = repair_attempts + 1, last_repair_at = NOW()'
        );
        $stmt->execute([$poolId, $serverId]);
    }

    /** Reset the self-heal counter (member recovered or we failed over). */
    private static function clearRepairState(int $poolId, int $serverId): void
    {
        $stmt = DB::conn()->prepare('DELETE FROM pool_repair_state WHERE pool_id = ? AND server_id = ?');
        $stmt->execute([$poolId, $serverId]);
    }

    /** True if a specific check is open with fail_count >= threshold. */
    private static function checkOpen(int $serverId, string $check, int $threshold): bool
    {
        $stmt = DB::conn()->prepare(
            "SELECT fail_count FROM alert_states WHERE alert_key = ? AND status = 'open' LIMIT 1"
        );
        $stmt->execute(["server:{$serverId}:{$check}"]);
        $fc = $stmt->fetchColumn();
        return $fc !== false && (int) $fc >= $threshold;
    }

    /** Notify that a member recovered by self-heal (no failover needed). */
    private static function notifySelfHeal(int $poolId, int $serverId, int $attempt): void
    {
        try {
            $stmt = DB::conn()->prepare('SELECT name FROM vpn_servers WHERE id = ?');
            $stmt->execute([$serverId]);
            $name = (string) $stmt->fetchColumn();
            $msg = sprintf(
                'Пул #%d: сервис на активном сервере %s (#%d) упал и был автоматически восстановлен (рестарт контейнера, попытка %d). Переключение не потребовалось.',
                $poolId, $name !== '' ? $name : '?', $serverId, $attempt
            );
            (new AlertManager())->recordEvent(
                $serverId,
                $name !== '' ? $name : ('server#' . $serverId),
                'pool_self_healed',
                $msg,
                'warning',
                'pool:' . $poolId . ':selfheal:' . $serverId . ':' . floor(time() / 120)
            );
        } catch (Throwable $e) {
            error_log('ServerPool::notifySelfHeal failed: ' . $e->getMessage());
        }
    }

    /** A member is "down" if any critical check is open with fail_count >= threshold. */
    private static function memberCriticalDown(int $serverId, int $threshold): bool
    {
        $like = implode(' OR ', array_fill(0, count(self::CRITICAL_CHECKS), "alert_key = ?"));
        $params = array_map(static fn($c) => "server:{$serverId}:{$c}", self::CRITICAL_CHECKS);
        $params[] = $threshold;
        $stmt = DB::conn()->prepare(
            "SELECT COUNT(*) FROM alert_states
             WHERE status = 'open' AND ({$like}) AND fail_count >= ?"
        );
        $stmt->execute($params);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** Lowest-priority member (excluding $excludeId) that is active and not down. */
    private static function pickHealthyStandby(int $poolId, int $excludeId, int $threshold): ?int
    {
        foreach (self::members($poolId) as $m) {
            $id = (int) $m['id'];
            if ($id === $excludeId) {
                continue;
            }
            if (($m['status'] ?? '') !== 'active') {
                continue;
            }
            if ((int) ($m['pool_sync_pending'] ?? 0) === 1) {
                continue; // client peers incomplete — those clients couldn't connect here
            }
            if ((int) ($m['validated_clean'] ?? 0) !== 1) {
                continue; // only auto-fail-over to a member proven clean for censored networks
            }
            if (self::memberCriticalDown($id, $threshold)) {
                continue;
            }
            return $id; // members() is ordered by pool_priority ASC
        }
        return null;
    }

    /** Derive the awg2 interface address (host .1) from the pool subnet. */
    private static function serverAddress(string $subnet): string
    {
        $subnet = trim($subnet);
        if ($subnet === '') {
            return '10.8.1.1/24';
        }
        // 10.8.1.0/24 -> 10.8.1.1/24
        return preg_replace('#\.0(/\d+)$#', '.1$1', $subnet) ?: $subnet;
    }

    /** Build the pool_identity option block for a scripted awg2 deploy. */
    private static function identityOptions(array $pool): array
    {
        $params = $pool['awg_params'] ?? null;
        if (is_string($params)) {
            $params = json_decode($params, true);
        }
        return [
            'private_key' => (string) ($pool['server_private_key'] ?? ''),
            'public_key' => (string) ($pool['server_public_key'] ?? ''),
            'preshared_key' => (string) ($pool['preshared_key'] ?? ''),
            'server_address' => self::serverAddress((string) ($pool['vpn_subnet'] ?? '')),
            'awg_params' => is_array($params) ? $params : [],
        ];
    }

    /**
     * Rebuild an existing member's awg2 in place, keeping the pool identity.
     *
     * Used to pick up a newer amneziawg-go build. Safe because the identity
     * (keys, PSK, obfuscation params, subnet, port) is authoritative in the
     * pool row: the local files are wiped so the installer regenerates from the
     * pool, producing byte-identical identity — existing client configs keep
     * working. Peers are then restored from the DB.
     *
     * Only valid for pool members: a standalone server's awg2 identity would be
     * regenerated from scratch and every client config would break.
     *
     * @return array{success:bool,message:string,synced?:int}
     */
    /**
     * True if awg2 is actually serving on this server: container running and
     * awg0 listening on the expected port. Used to catch a rebuild that aborted
     * but which activate() reported as success.
     */
    private static function awg2Healthy(VpnServer $server, int $port): bool
    {
        // Retry: after a fresh deploy the container needs a few seconds to run
        // awg-quick and bind the port, so a single early probe would wrongly
        // report failure (and trigger a needless rollback).
        $out = (string) $server->executeCommand(
            'for i in $(seq 1 10); do '
            . 'R=$(docker inspect -f "{{.State.Running}}" amnezia-awg2 2>/dev/null); '
            . 'P=$(docker exec amnezia-awg2 awg show awg0 listen-port 2>/dev/null); '
            . 'if [ "$R" = "true" ] && [ -n "$P" ]; then echo "running=$R port=$P"; exit 0; fi; '
            . 'sleep 2; done; echo "running=$R port=$P"',
            true
        );
        return strpos($out, 'running=true') !== false
            && preg_match('/port=' . preg_quote((string) $port, '/') . '\b/', $out) === 1;
    }

    /**
     * Restore awg2 from the pre-rebuild snapshot and start a container from the
     * existing image, mirroring how the installer mounts it (host
     * /opt/amnezia/awg2 -> container /opt/amnezia/awg). Returns true if the
     * restored container is healthy.
     */
    private static function restoreAwg2Snapshot(VpnServer $server, int $port): bool
    {
        $server->executeCommand(
            'D=/opt/amnezia/awg2; B="$D/.rebuild-snapshot"; '
            . '[ -f "$B/awg0.conf" ] || { echo no-snapshot; exit 0; }; '
            . 'for f in awg0.conf wireguard_server_private_key.key wireguard_server_public_key.key wireguard_psk.key clientsTable; do '
            . '[ -f "$B/$f" ] && cp -a "$B/$f" "$D/$f"; done; '
            . 'docker rm -f amnezia-awg2 >/dev/null 2>&1; '
            . 'docker run -d --name amnezia-awg2 --restart always --cap-add=NET_ADMIN --device /dev/net/tun '
            . '-p ' . escapeshellarg($port . ':' . $port . '/udp') . ' -v /opt/amnezia/awg2:/opt/amnezia/awg amnezia-awg2 '
            . 'sh -c "while [ ! -f /opt/amnezia/awg/awg0.conf ]; do sleep 1; done; '
            . 'WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /opt/amnezia/awg/awg0.conf && sleep infinity" >/dev/null 2>&1; '
            . 'sleep 6; echo restore-done',
            true
        );
        return self::awg2Healthy($server, $port);
    }

    public static function redeployMember(int $serverId): array
    {
        $pool = self::getForServer($serverId);
        if (!$pool) {
            return ['success' => false, 'message' => 'Сервер не состоит в пуле — пересборка awg2 доступна только для членов пула (иначе слетит идентичность и все клиентские конфиги).'];
        }
        $poolId = (int) $pool['id'];

        $server = new VpnServer($serverId);
        $port = (int) ($pool['vpn_port'] ?? 443) ?: 443;

        // 1. Snapshot the CURRENT working config + keys before touching anything.
        //    The old code wiped first and rebuilt second, so any failure in the
        //    rebuild (a docker build abort under set -e, a transient network
        //    error) left the member destroyed — and activate() defaults
        //    success=true, so it even reported OK. A rebuild must be atomic:
        //    upgrade, or leave the server exactly as it was.
        $server->executeCommand(
            'D=/opt/amnezia/awg2; B="$D/.rebuild-snapshot"; rm -rf "$B"; mkdir -p "$B"; '
            . 'for f in awg0.conf wireguard_server_private_key.key wireguard_server_public_key.key wireguard_psk.key clientsTable; do '
            . '[ -f "$D/$f" ] && cp -a "$D/$f" "$B/$f"; done; echo snap-done',
            true
        );

        // 2. Wipe the local identity so the installer regenerates it from the pool.
        $server->executeCommand(
            'docker rm -f amnezia-awg2 >/dev/null 2>&1; rm -f /opt/amnezia/awg2/awg0.conf '
            . '/opt/amnezia/awg2/wireguard_server_private_key.key /opt/amnezia/awg2/wireguard_server_public_key.key '
            . '/opt/amnezia/awg2/wireguard_psk.key /opt/amnezia/awg2/clientsTable; echo reset-done',
            true
        );

        // 3. Rebuild.
        $protocol = InstallProtocolManager::getBySlug('awg2');
        $deploy = InstallProtocolManager::activate(new VpnServer($serverId), $protocol, [
            'pool_identity' => self::identityOptions($pool),
            'server_port' => $port,
        ]);

        // 4. Verify REAL success: a running container with awg0 listening on the
        //    port. Do NOT trust $deploy['success'] alone — activate() returns
        //    success=true by default even when the install aborted.
        if (empty($deploy['success']) || !self::awg2Healthy($server, $port)) {
            // 5. Roll back to the snapshot: restore config+keys and bring the
            //    container back from the (still-present) image, so the member is
            //    left running its previous identity instead of destroyed.
            $restored = self::restoreAwg2Snapshot($server, $port);
            DB::conn()->prepare(
                'UPDATE vpn_servers SET pool_sync_pending = 1, validated_clean = NULL, validation_note = ? WHERE id = ?'
            )->execute([
                $restored
                    ? 'пересборка awg2 не удалась — восстановлена прежняя версия из снапшота; перепроверьте'
                    : 'пересборка awg2 не удалась И откат не сработал — требуется ручное вмешательство',
                $serverId,
            ]);
            return [
                'success' => false,
                'message' => $restored
                    ? 'Пересборка awg2 не удалась — сервер восстановлен из снапшота (прежняя версия работает). Снят с failover, перепроверьте.'
                    : 'Пересборка awg2 не удалась, и автоматический откат не сработал. Сервер не обслуживает клиентов — нужно ручное восстановление.',
            ];
        }

        // Success — the rebuilt container is healthy, drop the snapshot.
        $server->executeCommand('rm -rf /opt/amnezia/awg2/.rebuild-snapshot; echo cleaned', true);

        $failed = 0;
        $synced = self::syncClientsToServer($poolId, $serverId, $failed);
        if ($failed > 0) {
            return [
                'success' => false,
                'message' => "awg2 пересобран, но {$failed} пиров не синхронизировались (перенесено {$synced}). Сделайте ре-синк.",
                'synced' => $synced,
            ];
        }

        return ['success' => true, 'message' => "awg2 пересобран с идентичностью пула, пиров восстановлено: {$synced}", 'synced' => $synced];
    }

    /**
     * Add a server to the pool: adopt the pool's shared awg2 identity, redeploy
     * the member with it (wiping any standalone identity), then sync every
     * existing client peer onto it. The member is NOT made active — failover /
     * "make active" repoints DNS separately.
     *
     * @return array{success: bool, message: string, deploy?: array, synced?: int}
     */
    public static function addMember(int $poolId, int $serverId, int $priority = 100): array
    {
        $pool = self::get($poolId);
        if (!$pool) {
            return ['success' => false, 'message' => "Pool {$poolId} not found"];
        }
        $server = new VpnServer($serverId);
        $data = $server->getData();
        if (!$data) {
            return ['success' => false, 'message' => "Server {$serverId} not found"];
        }
        if (!empty($data['pool_id']) && (int) $data['pool_id'] !== $poolId) {
            return ['success' => false, 'message' => 'Server already belongs to another pool'];
        }

        // Snapshot the exact stored (encrypted) column values we're about to
        // overwrite, so a failed deploy can roll the DB back instead of leaving a
        // half-joined, bricked "member".
        $snap = DB::conn()->prepare(
            'SELECT pool_id, pool_priority, server_public_key, preshared_key, awg_params, vpn_subnet, vpn_port, domain
             FROM vpn_servers WHERE id = ?'
        );
        $snap->execute([$serverId]);
        $prev = $snap->fetch();

        // 1. Adopt the pool identity in the DB so client-config building and
        //    peer-add use the shared keys, and record membership.
        DB::conn()->prepare(
            // pool_sync_pending=1 / validated_clean=NULL from the very first write:
            // between here and a successful sync the member has NO working awg2
            // (step 2 wipes it). Leaving stale flags from a previous membership
            // let pickHealthyStandby route every client onto a server with no VPN
            // at all if the deploy then failed.
            'UPDATE vpn_servers
             SET pool_id = ?, pool_priority = ?, server_public_key = ?, preshared_key = ?,
                 awg_params = ?, vpn_subnet = ?, vpn_port = ?, domain = ?,
                 pool_sync_pending = 1, validated_clean = NULL
             WHERE id = ?'
        )->execute([
            $poolId,
            $priority,
            $pool['server_public_key'],
            $pool['preshared_key'],
            is_array($pool['awg_params']) ? json_encode($pool['awg_params']) : $pool['awg_params'],
            $pool['vpn_subnet'],
            (int) ($pool['vpn_port'] ?? 443) ?: 443,
            trim((string) ($pool['domain'] ?? '')) ?: null,
            $serverId,
        ]);

        // 2. Wipe any standalone awg2 identity so the install regenerates with
        //    the pool identity (the install reuses an existing awg0.conf otherwise).
        $server = new VpnServer($serverId);
        $server->executeCommand(
            'docker rm -f amnezia-awg2 >/dev/null 2>&1; rm -f /opt/amnezia/awg2/awg0.conf '
            . '/opt/amnezia/awg2/wireguard_server_private_key.key /opt/amnezia/awg2/wireguard_server_public_key.key '
            . '/opt/amnezia/awg2/wireguard_psk.key /opt/amnezia/awg2/clientsTable; echo reset-done',
            true
        );

        // 3. Deploy awg2 with the shared identity.
        // activate() can THROW rather than return success=false; without this
        // catch the rollback below was skipped entirely, leaving the server
        // recorded as a pool member with its awg2 wiped.
        $protocol = InstallProtocolManager::getBySlug('awg2');
        try {
            $deploy = InstallProtocolManager::activate($server, $protocol, [
                'pool_identity' => self::identityOptions($pool),
                'server_port' => (int) ($pool['vpn_port'] ?? 443) ?: 443,
            ]);
        } catch (Throwable $e) {
            error_log("ServerPool::addMember: deploy threw on {$serverId}: " . $e->getMessage());
            $deploy = ['success' => false, 'error' => $e->getMessage()];
        }
        if (empty($deploy['success'])) {
            // Roll the DB membership/identity back to its pre-join state. The
            // remote awg2 identity was already wiped in step 2, so the server now
            // needs a standalone redeploy — but at least it isn't recorded as a
            // (broken) pool member.
            if ($prev) {
                DB::conn()->prepare(
                    'UPDATE vpn_servers
                     SET pool_id = ?, pool_priority = ?, server_public_key = ?, preshared_key = ?,
                         awg_params = ?, vpn_subnet = ?, vpn_port = ?, domain = ?
                     WHERE id = ?'
                )->execute([
                    $prev['pool_id'], $prev['pool_priority'], $prev['server_public_key'], $prev['preshared_key'],
                    $prev['awg_params'], $prev['vpn_subnet'], $prev['vpn_port'], $prev['domain'], $serverId,
                ]);
            }
            return [
                'success' => false,
                'message' => 'Member deploy failed; membership rolled back. The server\'s awg2 identity was reset — redeploy it standalone before retrying.',
                'deploy' => ['success' => !empty($deploy['success'])],
            ];
        }

        // 4. Sync every existing pool client peer onto the new member.
        $failed = 0;
        $synced = self::syncClientsToServer($poolId, $serverId, $failed);

        // 5. Install Cloudflare WARP egress so EVERY member is identical (client
        //    traffic exits via WARP, real server IP not exposed on egress).
        //    Best-effort: a WARP failure does not fail the join (the member still
        //    serves clients), but it is surfaced so the operator can retry.
        $warpStatus = 'skipped';
        try {
            $warpProto = InstallProtocolManager::getBySlug('cf-warp');
            if ($warpProto) {
                $warpRes = InstallProtocolManager::activate(new VpnServer($serverId), $warpProto, []);
                $warpStatus = !empty($warpRes['success']) ? 'installed' : 'failed';
                if ($warpStatus === 'failed') {
                    error_log("ServerPool::addMember: WARP egress install returned failure on {$serverId}");
                }
            }
        } catch (Throwable $e) {
            $warpStatus = 'failed';
            error_log("ServerPool::addMember: WARP egress install failed on {$serverId}: " . $e->getMessage());
        }
        $warpNote = $warpStatus === 'installed'
            ? ' WARP egress включён.'
            : ($warpStatus === 'failed' ? ' ВНИМАНИЕ: WARP egress не установился — переустановите вручную (серверы неидентичны).' : '');

        // A member that is missing some peers must NOT silently become a valid
        // failover target — those clients would be unable to connect after a
        // failover to it. Report partial success so the caller/UI can react.
        if ($failed > 0) {
            return [
                'success' => true,
                'partial' => true,
                'message' => "Server {$serverId} joined pool but {$failed} of " . ($synced + $failed) . " client peers failed to sync — re-sync before relying on it for failover." . $warpNote,
                'deploy' => ['success' => !empty($deploy['success'])],
                'synced' => $synced,
                'failed' => $failed,
                'warp' => $warpStatus,
            ];
        }

        return [
            'success' => true,
            'message' => "Server {$serverId} joined pool (synced {$synced} clients)." . $warpNote,
            'deploy' => ['success' => !empty($deploy['success'])],
            'synced' => $synced,
            'warp' => $warpStatus,
        ];
    }

    /**
     * Push every active client peer in the pool onto one member's awg0.
     * Returns the number of peers synced; sets $failed to the number that
     * could not be pushed (so the caller can refuse to trust an incomplete member).
     */
    public static function syncClientsToServer(int $poolId, int $serverId, &$failed = 0): int
    {
        // Delegate to the authoritative rebuild: it rewrites awg0.conf's [Peer]
        // set from the DB (so peers survive a container restart) and applies it
        // live with `awg syncconf` (connected clients are not dropped). This
        // replaces the old append-per-peer loop, which duplicated peers and could
        // miss awg0.conf when the freshly-deployed conf wasn't ready yet — the
        // exact bug that left a joined member with zero live peers.
        // reconcilePeers already sets pool_sync_pending based on the result.
        $res = self::reconcilePeers($serverId);
        $failed = $res['success'] ? 0 : max(0, (int) $res['peers'] - (int) $res['live']);
        return (int) $res['live'];
    }

    /**
     * Authoritatively rebuild a member's peer set from the DB (source of truth),
     * so peers survive an awg2 container restart and drift is corrected.
     *
     * awg0.conf's [Peer] sections are replaced with exactly the pool's active
     * client peers (no duplicates, none missing); the [Interface] block is kept
     * verbatim. The live interface is then updated with `awg syncconf`, which
     * applies only the delta — connected clients are NOT dropped. Because the
     * peers now live in awg0.conf, `awg-quick up` restores them on restart.
     *
     * @return array{success:bool, peers:int, live:int, message:string}
     */
    public static function reconcilePeers(int $serverId): array
    {
        $server = new VpnServer($serverId);
        $data = $server->getData();
        if (!$data) {
            return ['success' => false, 'peers' => 0, 'live' => 0, 'message' => "Server {$serverId} not found"];
        }
        $poolId = (int) ($data['pool_id'] ?? 0);
        if ($poolId <= 0) {
            return ['success' => false, 'peers' => 0, 'live' => 0, 'message' => 'Server is not in a pool'];
        }
        $pool = self::get($poolId);
        $psk = trim((string) ($pool['preshared_key'] ?? ''));
        $container = (string) ($data['container_name'] ?? '') ?: 'amnezia-awg2';

        // Authoritative peer list = every active client across all pool members.
        $memberIds = array_map(static fn($m) => (int) $m['id'], self::members($poolId));
        $peerRows = [];
        if (!empty($memberIds)) {
            $in = implode(',', array_fill(0, count($memberIds), '?'));
            $stmt = DB::conn()->prepare(
                "SELECT DISTINCT public_key, client_ip FROM vpn_clients
                 WHERE server_id IN ($in) AND status = 'active' AND public_key <> '' AND client_ip <> ''"
            );
            $stmt->execute($memberIds);
            $peerRows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
        $peers = '';
        foreach ($peerRows as $r) {
            $peers .= "\n[Peer]\nPublicKey = " . trim((string) $r['public_key']) . "\n";
            if ($psk !== '') {
                $peers .= 'PresharedKey = ' . $psk . "\n";
            }
            $peers .= 'AllowedIPs = ' . trim((string) $r['client_ip']) . "/32\n";
        }

        // Read the current conf (into a var, never echoed — it holds the private key),
        // keep everything before the first [Peer] (the [Interface] block).
        $conf = (string) $server->executeCommand('cat /opt/amnezia/awg2/awg0.conf 2>/dev/null', true);
        if (strpos($conf, '[Interface]') === false) {
            return ['success' => false, 'peers' => count($peerRows), 'live' => 0, 'message' => 'awg0.conf missing/invalid on server'];
        }
        $head = preg_split('/^\s*\[Peer\]/m', $conf, 2)[0];
        $newConf = rtrim($head, "\n") . "\n" . $peers;
        $b64 = base64_encode($newConf);

        // Write awg0.conf on the host (bind-mounted into the container), then
        // apply live non-disruptively with syncconf.
        $script = 'cp /opt/amnezia/awg2/awg0.conf /opt/amnezia/awg2/awg0.conf.bak-reconcile 2>/dev/null; '
            . 'echo ' . $b64 . ' | base64 -d > /opt/amnezia/awg2/awg0.conf && '
            . 'docker exec ' . escapeshellarg($container) . ' sh -c '
            . escapeshellarg(
                'awg-quick strip /opt/amnezia/awg/awg0.conf > /tmp/awg0.strip 2>/dev/null; '
                . 'awg syncconf awg0 /tmp/awg0.strip 2>&1 || wg syncconf awg0 /tmp/awg0.strip 2>&1; '
                . 'rm -f /tmp/awg0.strip; '
                . 'echo "LIVE=$(awg show awg0 allowed-ips 2>/dev/null | grep -c /32)"'
            );
        $out = (string) $server->executeCommand($script, true);
        $live = 0;
        if (preg_match('/LIVE=(\d+)/', $out, $m)) {
            $live = (int) $m[1];
        }
        $expected = count($peerRows);
        $ok = $live === $expected;
        // Keep the failover-eligibility flag honest.
        DB::conn()->prepare('UPDATE vpn_servers SET pool_sync_pending = ? WHERE id = ?')
            ->execute([$ok ? 0 : 1, $serverId]);

        return [
            'success' => $ok,
            'peers' => $expected,
            'live' => $live,
            'message' => $ok
                ? "Пиры пересобраны из БД: {$live} на живом интерфейсе и в awg0.conf (переживут рестарт)."
                : "Рассинхрон: ожидалось {$expected}, на интерфейсе {$live}. Проверьте контейнер {$container}.",
        ];
    }

    /**
     * Add one client peer to every pool member except $exceptServerId.
     * Called from VpnClient::create so a new client lands on all members.
     */
    public static function pushPeerToMembers(int $poolId, string $publicKey, string $clientIp, int $exceptServerId): void
    {
        foreach (self::members($poolId) as $m) {
            if ((int) $m['id'] === $exceptServerId) {
                continue;
            }
            try {
                $memberData = (new VpnServer((int) $m['id']))->getData();
                VpnClient::addClientToServer($memberData, $publicKey, $clientIp);
            } catch (Throwable $e) {
                error_log("ServerPool::pushPeerToMembers: failed on server {$m['id']}: " . $e->getMessage());
                // Member is now missing this client's peer — mark it incomplete so
                // it isn't chosen for failover until re-synced.
                try {
                    DB::conn()->prepare('UPDATE vpn_servers SET pool_sync_pending = 1 WHERE id = ?')->execute([(int) $m['id']]);
                } catch (Throwable $e2) {
                    // best effort
                }
            }
        }
    }

    /**
     * Tier-1 server-side reachability probe. From an external vantage member
     * (the active member by default), stand up a throwaway amneziawg client that
     * targets the candidate member's PUBLIC ip:port and check whether it completes
     * a handshake. Confirms the candidate's ingress is UP and routed across the
     * datacenter backbone — it does NOT prove the IP is "clean" for censored client
     * networks (that is the Tier-2 client canary's job).
     *
     * Unreachable => member flagged validated_clean = 0 (unusable). Reachable =>
     * validated_clean left untouched (infra OK, cleanliness still unknown).
     *
     * @return array{success:bool, reachable:bool, handshake_age:?int, vantage:int, message:string}
     */
    public static function probeReachability(int $poolId, int $targetServerId, ?int $vantageServerId = null): array
    {
        $fail = static fn(string $m, int $v = 0): array => [
            'success' => false, 'reachable' => false, 'handshake_age' => null, 'vantage' => $v, 'message' => $m,
        ];

        $pool = self::get($poolId);
        if (!$pool) {
            return $fail("Pool {$poolId} not found");
        }
        $target = (new VpnServer($targetServerId))->getData();
        if (!$target || empty($target['host'])) {
            return $fail("Target server {$targetServerId} not found");
        }

        // Vantage = an external member (never the target itself). Prefer the active.
        if ($vantageServerId === null) {
            $vantageServerId = (int) ($pool['active_server_id'] ?? 0);
        }
        if ($vantageServerId <= 0 || $vantageServerId === $targetServerId) {
            foreach (self::members($poolId) as $m) {
                if ((int) $m['id'] !== $targetServerId) {
                    $vantageServerId = (int) $m['id'];
                    break;
                }
            }
        }
        if ($vantageServerId <= 0 || $vantageServerId === $targetServerId) {
            return $fail('No external vantage member available (need another pool member to probe from).');
        }
        $vantage = new VpnServer($vantageServerId);

        $subnet = trim((string) ($pool['vpn_subnet'] ?? '')) ?: '10.8.1.0/24';
        $probeIp = preg_replace('#\.\d+(/\d+)?$#', '.254', preg_replace('#/\d+$#', '', $subnet)) ?: '10.8.1.254';
        $port = (int) ($pool['vpn_port'] ?? 443) ?: 443;

        // 1. Ephemeral probe keypair, generated on the vantage (has the awg image).
        $keys = (string) $vantage->executeCommand(
            'P=$(docker run --rm amnezia-awg2 awg genkey 2>/dev/null); echo "PRIV=$P"; '
            . 'echo "PUB=$(printf %s "$P" | docker run --rm -i amnezia-awg2 awg pubkey 2>/dev/null)"',
            true
        );
        preg_match('/PRIV=(\S+)/', $keys, $mp);
        preg_match('/PUB=(\S+)/', $keys, $mpub);
        $priv = $mp[1] ?? '';
        $pub = $mpub[1] ?? '';
        if ($priv === '' || $pub === '') {
            return $fail('Could not generate probe key on vantage (amnezia-awg2 image missing?)', $vantageServerId);
        }

        // 2. Register the probe peer directly on the TARGET's live interface
        //    (no PSK, no persistence — throwaway). Direct `awg set` avoids the
        //    config-path assumptions of the generic client-add helper.
        $targetServer = new VpnServer($targetServerId);
        $tContainer = (string) ($target['container_name'] ?? '') ?: 'amnezia-awg2';
        $addOut = (string) $targetServer->executeCommand(
            'docker exec ' . escapeshellarg($tContainer) . ' awg set awg0 peer ' . escapeshellarg($pub)
            . ' allowed-ips ' . escapeshellarg($probeIp . '/32') . ' 2>&1 && echo OK-ADD',
            true
        );
        if (strpos($addOut, 'OK-ADD') === false) {
            return $fail('Could not register probe peer on target: ' . trim($addOut), $vantageServerId);
        }

        $reachable = false;
        $hsTs = 0;
        try {
            // 3. Build the probe client conf (pool identity + target endpoint).
            $p = $pool['awg_params'] ?? [];
            if (is_string($p)) {
                $p = json_decode($p, true) ?: [];
            }
            $lines = ['[Interface]', "PrivateKey = {$priv}", "Address = {$probeIp}/32", 'MTU = 1280'];
            foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $k) {
                if (isset($p[$k]) && $p[$k] !== '') {
                    $lines[] = "{$k} = {$p[$k]}";
                }
            }
            $lines[] = '';
            $lines[] = '[Peer]';
            $lines[] = 'PublicKey = ' . trim((string) ($pool['server_public_key'] ?? ''));
            // No PresharedKey: the throwaway probe peer is registered on the target
            // without a PSK, so the client must not present one either.
            $lines[] = 'Endpoint = ' . $target['host'] . ':' . $port;
            $lines[] = 'AllowedIPs = ' . $subnet;
            $lines[] = 'PersistentKeepalive = 25';
            $b64 = base64_encode(implode("\n", $lines) . "\n");

            // 4. Throwaway client on the vantage; read the peer's latest-handshake.
            $name = 'awgprobe_' . $targetServerId;
            $script = 'docker rm -f ' . $name . ' >/dev/null 2>&1; '
                . 'D=$(mktemp -d); echo ' . $b64 . ' | base64 -d > "$D/awgprobe.conf"; '
                . 'docker run -d --rm --name ' . $name . ' --cap-add NET_ADMIN --device /dev/net/tun '
                . '-v "$D/awgprobe.conf":/awgprobe.conf:ro amnezia-awg2 sh -c '
                . '"WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /awgprobe.conf >/dev/null 2>&1; sleep 18" >/dev/null 2>&1; '
                . 'HS=0; for i in $(seq 1 14); do sleep 1; '
                . 'H=$(docker exec ' . $name . ' awg show awgprobe latest-handshakes 2>/dev/null | head -1 | awk "{print \$2}"); '
                . 'if [ -n "$H" ] && [ "$H" != "0" ]; then HS=$H; break; fi; done; '
                . 'docker rm -f ' . $name . ' >/dev/null 2>&1; rm -rf "$D"; echo "HS=$HS"';
            $out = (string) $vantage->executeCommand($script, true);
            if (preg_match('/HS=(\d+)/', $out, $mh)) {
                $hsTs = (int) $mh[1];
            }
            $reachable = $hsTs > 0;
        } finally {
            // 5. Always remove the throwaway probe peer from the target's live interface.
            try {
                $targetServer->executeCommand(
                    'docker exec ' . escapeshellarg($tContainer) . ' awg set awg0 peer ' . escapeshellarg($pub) . ' remove 2>/dev/null; echo cleaned',
                    true
                );
            } catch (Throwable $e) {
                error_log("ServerPool::probeReachability: probe-peer cleanup failed on {$targetServerId}: " . $e->getMessage());
            }
        }

        $age = $reachable ? max(0, time() - $hsTs) : null;
        $note = $reachable
            ? "probe: reachable from #{$vantageServerId}"
            : "probe: UNREACHABLE from #{$vantageServerId}";
        if ($reachable) {
            DB::conn()->prepare('UPDATE vpn_servers SET validated_at = NOW(), validation_note = ? WHERE id = ?')
                ->execute([$note, $targetServerId]);
        } else {
            DB::conn()->prepare('UPDATE vpn_servers SET validated_clean = 0, validated_at = NOW(), validation_note = ? WHERE id = ?')
                ->execute([$note, $targetServerId]);
        }

        return [
            'success' => true,
            'reachable' => $reachable,
            'handshake_age' => $age,
            'vantage' => $vantageServerId,
            'message' => $reachable
                ? "Reachable: handshake completed from member #{$vantageServerId} (age {$age}s). Infra OK — run the client canary to confirm the IP is clean for censored networks."
                : "Unreachable from member #{$vantageServerId}: no handshake (IP not routed / server down / firewall). Marked unusable.",
        ];
    }

    /** Read PrivateKey from the server's host awg0.conf. */
    private static function readServerPrivateKey(VpnServer $server): string
    {
        $out = (string) $server->executeCommand(
            "grep -E '^\\s*PrivateKey' /opt/amnezia/awg2/awg0.conf 2>/dev/null | head -1 | cut -d= -f2- | tr -d '[:space:]'",
            true
        );
        return trim($out);
    }

    private static function decryptPool(array $pool): array
    {
        $pool['server_private_key'] = SecretBox::decryptNullable($pool['server_private_key'] ?? null);
        $pool['preshared_key'] = SecretBox::decryptNullable($pool['preshared_key'] ?? null);
        return $pool;
    }
}
