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
            'SELECT id, name, host, domain, status, pool_priority, last_check_at
             FROM vpn_servers WHERE pool_id = ? ORDER BY pool_priority ASC, id ASC'
        );
        $stmt->execute([$poolId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public static function list(): array
    {
        return DB::conn()->query('SELECT * FROM server_pools ORDER BY name')->fetchAll(PDO::FETCH_ASSOC);
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

        return ['success' => true, 'pool_id' => $poolId, 'message' => "Pool '{$poolName}' created from server {$serverId}"];
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

        $oldActive = (int) ($pool['active_server_id'] ?? 0);
        $host = (string) $target['host'];
        $domain = trim((string) ($pool['domain'] ?? ''));
        $response = ['success' => true, 'message' => "Active server set to {$target['name']} (#{$serverId})"];

        if ($domain !== '') {
            if (!DnsManager::isConfigured()) {
                $response['dns'] = ['success' => false, 'message' => 'DNS provider token not configured — A-record not updated'];
                $response['success'] = false;
                $response['message'] = 'Active server recorded, but DNS repoint failed (no token)';
            } else {
                $dns = DnsManager::upsertARecord($domain, $host);
                $response['dns'] = $dns;
                if (empty($dns['success'])) {
                    $response['success'] = false;
                    $response['message'] = 'DNS repoint failed: ' . ($dns['message'] ?? 'unknown');
                }
            }
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
     * Auto-failover pass (run each monitoring cycle): for every pool whose active
     * member has been failing critical health checks for >= $threshold cycles,
     * repoint the domain to a healthy standby. Deliberately uses the panel's own
     * health checks (ssh/container/interface), NOT a server-to-server UDP probe
     * (that gives false negatives). No auto-failback.
     *
     * @return array<int, array{pool:int, action:string, from?:int, to?:int}>
     */
    public static function checkAndFailover(int $threshold = 3): array
    {
        $results = [];
        foreach (self::list() as $pool) {
            $poolId = (int) $pool['id'];
            $activeId = (int) ($pool['active_server_id'] ?? 0);
            if ($activeId <= 0) {
                continue;
            }
            if (!self::memberCriticalDown($activeId, $threshold)) {
                continue; // active is healthy — nothing to do
            }
            $candidate = self::pickHealthyStandby($poolId, $activeId, $threshold);
            if ($candidate === null) {
                error_log("ServerPool: pool {$poolId} active #{$activeId} is DOWN but no healthy standby available");
                $results[] = ['pool' => $poolId, 'action' => 'no_candidate', 'from' => $activeId];
                continue;
            }
            error_log("ServerPool: pool {$poolId} auto-failover #{$activeId} -> #{$candidate}");
            self::setActive($poolId, $candidate, 'auto_failover');
            $results[] = ['pool' => $poolId, 'action' => 'failover', 'from' => $activeId, 'to' => $candidate];
        }
        return $results;
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

        // 1. Adopt the pool identity in the DB so client-config building and
        //    peer-add use the shared keys, and record membership.
        DB::conn()->prepare(
            'UPDATE vpn_servers
             SET pool_id = ?, pool_priority = ?, server_public_key = ?, preshared_key = ?,
                 awg_params = ?, vpn_subnet = ?, vpn_port = ?, domain = ?
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
        $protocol = InstallProtocolManager::getBySlug('awg2');
        $deploy = InstallProtocolManager::activate($server, $protocol, [
            'pool_identity' => self::identityOptions($pool),
            'server_port' => (int) ($pool['vpn_port'] ?? 443) ?: 443,
        ]);
        if (empty($deploy['success'])) {
            return ['success' => false, 'message' => 'Member deploy failed', 'deploy' => $deploy];
        }

        // 4. Sync every existing pool client peer onto the new member.
        $synced = self::syncClientsToServer($poolId, $serverId);

        return [
            'success' => true,
            'message' => "Server {$serverId} joined pool (synced {$synced} clients)",
            'deploy' => $deploy,
            'synced' => $synced,
        ];
    }

    /**
     * Push every active client peer in the pool onto one member's awg0.
     * Returns the number of peers synced.
     */
    public static function syncClientsToServer(int $poolId, int $serverId): int
    {
        $memberIds = array_map(static fn($m) => (int) $m['id'], self::members($poolId));
        if (empty($memberIds)) {
            return 0;
        }
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        $in = implode(',', array_fill(0, count($memberIds), '?'));
        $stmt = DB::conn()->prepare(
            "SELECT DISTINCT public_key, client_ip FROM vpn_clients
             WHERE server_id IN ($in) AND status = 'active' AND public_key <> ''"
        );
        $stmt->execute($memberIds);

        $count = 0;
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $client) {
            try {
                VpnClient::addClientToServer($serverData, (string) $client['public_key'], (string) $client['client_ip']);
                $count++;
            } catch (Throwable $e) {
                error_log("ServerPool::syncClientsToServer: failed peer {$client['public_key']} on server {$serverId}: " . $e->getMessage());
            }
        }
        return $count;
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
            }
        }
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
