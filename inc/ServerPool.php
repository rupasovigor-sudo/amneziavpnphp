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
                'deploy' => $deploy,
            ];
        }

        // 4. Sync every existing pool client peer onto the new member.
        $synced = self::syncClientsToServer($poolId, $serverId, $failed);

        // A member that is missing some peers must NOT silently become a valid
        // failover target — those clients would be unable to connect after a
        // failover to it. Report partial success so the caller/UI can react.
        if ($failed > 0) {
            return [
                'success' => true,
                'partial' => true,
                'message' => "Server {$serverId} joined pool but {$failed} of " . ($synced + $failed) . " client peers failed to sync — re-sync before relying on it for failover.",
                'deploy' => $deploy,
                'synced' => $synced,
                'failed' => $failed,
            ];
        }

        return [
            'success' => true,
            'message' => "Server {$serverId} joined pool (synced {$synced} clients)",
            'deploy' => $deploy,
            'synced' => $synced,
        ];
    }

    /**
     * Push every active client peer in the pool onto one member's awg0.
     * Returns the number of peers synced; sets $failed to the number that
     * could not be pushed (so the caller can refuse to trust an incomplete member).
     */
    public static function syncClientsToServer(int $poolId, int $serverId, int &$failed = 0): int
    {
        $failed = 0;
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
                $failed++;
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
