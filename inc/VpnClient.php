<?php
/**
 * VPN Client Management Class
 * Handles creation and management of VPN client configurations
 * Based on amnezia_client_config_v2.php
 */
class VpnClient
{
    private $clientId;
    private $data;
    private const DEFAULT_TIMING_THRESHOLD_MS = 300;
    private const DEFAULT_KEY_SYNC_TTL_SECONDS = 0;
    private static ?bool $hasLastKeySyncColumn = null;

    public function __construct(?int $clientId = null)
    {
        $this->clientId = $clientId;
        if ($clientId) {
            $this->load();
        }
    }

    /**
     * Load client data from database
     */
    private function load(): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_clients WHERE id = ?');
        $stmt->execute([$this->clientId]);
        $this->data = $stmt->fetch();
        if (!$this->data) {
            throw new Exception('Client not found');
        }
    }

    private static function timingThresholdMs(): int
    {
        $raw = getenv('AMNEZIA_TIMING_THRESHOLD_MS');
        if ($raw !== false && is_numeric($raw)) {
            return max(0, (int) $raw);
        }

        return self::DEFAULT_TIMING_THRESHOLD_MS;
    }

    private static function timed(string $stage, array $context, callable $callback): mixed
    {
        $startedAt = microtime(true);

        try {
            return $callback();
        } finally {
            $durationMs = (microtime(true) - $startedAt) * 1000;
            self::logTiming($stage, $durationMs, $context, str_starts_with($stage, 'create.'));
        }
    }

    private static function logTiming(string $stage, float $durationMs, array $context = [], bool $force = false): void
    {
        if (!$force && $durationMs < self::timingThresholdMs()) {
            return;
        }

        $parts = [
            'stage=' . $stage,
            'duration_ms=' . number_format($durationMs, 1, '.', ''),
        ];
        foreach ($context as $key => $value) {
            if ($value === null || $value === '') {
                continue;
            }
            if (is_bool($value)) {
                $value = $value ? 'true' : 'false';
            }
            if (is_scalar($value)) {
                $parts[] = $key . '=' . (string) $value;
            }
        }
        error_log('VpnClient timing: ' . implode(' ', $parts));
    }

    private static function keySyncTtlSeconds(): int
    {
        $raw = getenv('AMNEZIA_KEY_SYNC_TTL_SECONDS');
        if ($raw !== false && is_numeric($raw)) {
            return max(0, (int) $raw);
        }

        return self::DEFAULT_KEY_SYNC_TTL_SECONDS;
    }

    private static function hasLastKeySyncColumn(): bool
    {
        if (self::$hasLastKeySyncColumn !== null) {
            return self::$hasLastKeySyncColumn;
        }

        try {
            $pdo = DB::conn();
            $stmt = $pdo->query("SHOW COLUMNS FROM vpn_servers LIKE 'last_key_sync_at'");
            self::$hasLastKeySyncColumn = (bool) $stmt->fetch();
        } catch (Throwable $e) {
            self::$hasLastKeySyncColumn = false;
        }

        return self::$hasLastKeySyncColumn;
    }

    private static function shouldSyncServerKeys(array $serverData, string $protocolSlug): bool
    {
        $required = ['server_public_key', 'preshared_key', 'vpn_port'];
        if (in_array($protocolSlug, ['awg2'], true)) {
            $required[] = 'awg_params';
        }

        foreach ($required as $key) {
            if (!isset($serverData[$key]) || $serverData[$key] === '' || $serverData[$key] === null) {
                return true;
            }
        }

        $ttl = self::keySyncTtlSeconds();
        if ($ttl <= 0) {
            return false;
        }

        if (!self::hasLastKeySyncColumn()) {
            return true;
        }

        if (empty($serverData['id'])) {
            return true;
        }

        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT TIMESTAMPDIFF(SECOND, last_key_sync_at, NOW()) FROM vpn_servers WHERE id = ? AND last_key_sync_at IS NOT NULL');
            $stmt->execute([(int) $serverData['id']]);
            $ageSeconds = $stmt->fetchColumn();
            if ($ageSeconds === false || $ageSeconds === null || $ageSeconds === '') {
                return true;
            }

            return (int) $ageSeconds >= $ttl;
        } catch (Throwable $e) {
            return true;
        }
    }

    /**
     * Create new VPN client
     * 
     * @param int $serverId Server ID
     * @param int $userId User ID
     * @param string $name Client name
     * @param int|null $expiresInDays Days until expiration (null = never expires)
     * @return int Client ID
     */
    public static function create(int $serverId, int $userId, string $name, ?int $expiresInDays = null, ?int $protocolId = null, ?string $username = null, ?string $login = null): int
    {
        $createStartedAt = microtime(true);
        $pdo = DB::conn();

        $name = trim($name);

        // Get server data
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (!$serverData || $serverData['status'] !== 'active') {
            throw new Exception('Server is not active');
        }

        // Determine protocol before sync
        $protoRow = null;
        if ($protocolId === null) {
            $stmtProto = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
            $stmtProto->execute([$serverData['install_protocol'] ?? '']);
            $protocolId = (int) $stmtProto->fetchColumn();
        }
        if ($protocolId) {
            $stmtProto2 = $pdo->prepare('SELECT * FROM protocols WHERE id = ?');
            $stmtProto2->execute([$protocolId]);
            $protoRow = $stmtProto2->fetch();
        }
        $slug = $protoRow['slug'] ?? ($serverData['install_protocol'] ?? 'amnezia-wg');
        $protoMetadata = [];
        if ($protoRow && !empty($protoRow['definition']) && is_string($protoRow['definition'])) {
            $decodedDef = json_decode($protoRow['definition'], true);
            if (is_array($decodedDef)) {
                $protoMetadata = $decodedDef['metadata'] ?? [];
            }
        }
        $isWireguard = in_array($slug, ['awg2'], true);

        // Auto-sync server keys from container EVERY TIME for WireGuard protocols
        // This ensures we always use current container configuration even if it was recreated
        if ($isWireguard) {
            try {
                // For multi-protocol servers use selected protocol metadata instead of default server row.
                if (!empty($protoMetadata['container_name']) && is_string($protoMetadata['container_name'])) {
                    $serverData['container_name'] = trim($protoMetadata['container_name']);
                }
                $serverData['install_protocol'] = $slug;

                $didSyncServerKeys = false;
                if (self::shouldSyncServerKeys($serverData, $slug)) {
                    self::timed('create.sync_server_keys', [
                        'server_id' => $serverId,
                        'protocol' => $slug,
                    ], fn() => self::syncServerKeysFromContainer($server, $serverData));
                    $didSyncServerKeys = true;
                }
                if ($didSyncServerKeys) {
                    // Reload server data after sync (VpnServer caches DB row in-memory)
                    $server->refresh();
                    $serverData = $server->getData();
                }
                if (!empty($protoMetadata['container_name']) && is_string($protoMetadata['container_name'])) {
                    $serverData['container_name'] = trim($protoMetadata['container_name']);
                }
                $serverData['install_protocol'] = $slug;
            } catch (Exception $e) {
                error_log('Failed to auto-sync server keys: ' . $e->getMessage());
                // Continue anyway - might fail later but let's try
            }
        }

        // For multi-protocol setups, override server data with protocol-specific settings
        // (subnet, keys, port, AWG params) from server_protocols.config_data or protocol metadata
        if ($protocolId) {
            try {
                $spConfigRaw = self::timed('create.load_protocol_config', [
                    'server_id' => $serverId,
                    'protocol' => $slug,
                ], function () use ($pdo, $serverId, $protocolId) {
                    $stmtSp = $pdo->prepare('SELECT config_data FROM server_protocols WHERE server_id = ? AND protocol_id = ? LIMIT 1');
                    $stmtSp->execute([$serverId, $protocolId]);
                    return $stmtSp->fetchColumn();
                });
                if ($spConfigRaw) {
                    $spConfig = is_string($spConfigRaw) ? json_decode($spConfigRaw, true) : $spConfigRaw;
                    if (is_array($spConfig)) {
                        $spExtras = $spConfig['extras'] ?? [];
                        // If extras has 'result' subarray, merge it
                        if (isset($spExtras['result']) && is_array($spExtras['result'])) {
                            $spExtras = array_merge($spExtras, $spExtras['result']);
                        }
                        // Override server data with protocol-specific values
                        if (!empty($spExtras['server_public_key'])) {
                            $serverData['server_public_key'] = $spExtras['server_public_key'];
                        }
                        if (!empty($spExtras['preshared_key'])) {
                            $serverData['preshared_key'] = $spExtras['preshared_key'];
                        }
                        if (!empty($spExtras['vpn_port'])) {
                            $serverData['vpn_port'] = $spExtras['vpn_port'];
                        }
                        if (!empty($spConfig['server_port'])) {
                            $serverData['vpn_port'] = $spConfig['server_port'];
                        }
                        // Override AWG params from protocol config
                        // AWG params can be at extras level (Jc, S1, etc.) or nested in extras.awg_params
                        $awgOverride = [];
                        $awgSource = $spExtras;
                        if (isset($spExtras['awg_params']) && is_array($spExtras['awg_params'])) {
                            $awgSource = array_merge($awgSource, $spExtras['awg_params']);
                        }
                        foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $ak) {
                            if (isset($awgSource[$ak]) && $awgSource[$ak] !== '' && $awgSource[$ak] !== null) {
                                $awgOverride[$ak] = $awgSource[$ak];
                            }
                        }
                        if (!empty($awgOverride)) {
                            $serverData['awg_params'] = json_encode($awgOverride);
                        }
                    }
                }
            } catch (Exception $e) {
                error_log('Failed to load protocol config_data: ' . $e->getMessage());
            }

            // Override vpn_subnet from protocol definition metadata (e.g. AWG2 uses 10.8.1.0/24)
            if (!empty($protoMetadata['vpn_subnet'])) {
                $serverData['vpn_subnet'] = $protoMetadata['vpn_subnet'];
            }
        }

        $strictIpSync = in_array(strtolower((string) getenv('AMNEZIA_STRICT_IP_SYNC')), ['1', 'true', 'yes'], true);
        $clientIP = self::timed('create.get_next_client_ip', [
            'server_id' => $serverId,
            'protocol' => $slug,
            'strict_ip_sync' => $strictIpSync,
        ], fn() => self::getNextClientIP($serverData, $strictIpSync));
        $loginBase = $login !== null && $login !== '' ? $login : $name;
        $loginBase = str_replace(' ', '_', trim($loginBase));
        $loginFinal = $loginBase;
        $loginFinal = self::timed('create.ensure_unique_login', [
            'server_id' => $serverId,
            'protocol' => $slug,
        ], function () use ($pdo, $serverId, $loginBase) {
            $loginFinal = $loginBase;
            $suffix = 2;
            while (true) {
                $stmtChk = $pdo->prepare('SELECT COUNT(*) FROM vpn_clients WHERE server_id = ? AND name = ?');
                $stmtChk->execute([$serverId, $loginFinal]);
                if ((int) $stmtChk->fetchColumn() === 0) {
                    return $loginFinal;
                }
                $loginFinal = $loginBase . '-' . $suffix;
                $suffix++;
            }
        });

        if ($isWireguard) {
            $containerName = $serverData['container_name'];
            $keys = self::timed('create.generate_client_keys', [
                'server_id' => $serverId,
                'protocol' => $slug,
            ], fn() => self::generateClientKeys($serverData, $name));

            [$awgParams, $vars] = self::timed('create.wireguard_prepare_config', [
                'server_id' => $serverId,
                'protocol' => $slug,
            ], function () use ($serverData, $slug, $server, $serverId, $pdo, $keys, $clientIP) {
                // Re-fetch awg_params after possible auto-sync
                $awgParams = json_decode($serverData['awg_params'] ?? '{}', true) ?? [];
                if (!is_array($awgParams)) {
                    $awgParams = [];
                }

                foreach ($awgParams as $k => $v) {
                    $uk = strtoupper((string) $k);
                    if (in_array($uk, ['JC', 'JMIN', 'JMAX', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'], true) && !isset($awgParams[$uk])) {
                        $awgParams[$uk] = $v;
                    }
                }

                if ($slug === 'awg2') {
                    $requiredAwg2Params = ['JC', 'JMIN', 'JMAX', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'];
                    $missingAwg2Params = false;
                    foreach ($requiredAwg2Params as $requiredKey) {
                        if (!isset($awgParams[$requiredKey]) || $awgParams[$requiredKey] === '') {
                            $missingAwg2Params = true;
                            break;
                        }
                    }

                    if ($missingAwg2Params) {
                        $directAwgParams = self::timed('create.awg2_param_recovery', [
                            'server_id' => $serverId,
                            'protocol' => $slug,
                        ], function () use ($server, $serverData) {
                            $directAwgParams = self::extractAwgParamsFromWg0Conf($server, $serverData['container_name'] ?? 'amnezia-awg2', '/opt/amnezia/awg/awg0.conf');
                            if (empty($directAwgParams)) {
                                $directAwgParams = self::extractAwgParamsFromWg0Conf($server, $serverData['container_name'] ?? 'amnezia-awg2', '/opt/amnezia/awg/wg0.conf');
                            }
                            return $directAwgParams;
                        });
                        if (!empty($directAwgParams)) {
                            foreach ($directAwgParams as $k => $v) {
                                $awgParams[strtoupper((string) $k)] = $v;
                            }
                            try {
                                $stmtPersistAwg = $pdo->prepare('UPDATE vpn_servers SET awg_params = ? WHERE id = ?');
                                $stmtPersistAwg->execute([json_encode($awgParams), $serverData['id']]);
                            } catch (Exception $e) {
                                error_log('Failed to persist AWG2 params from config: ' . $e->getMessage());
                            }
                        }
                    }

                    foreach ($requiredAwg2Params as $requiredKey) {
                        if (!isset($awgParams[$requiredKey]) || $awgParams[$requiredKey] === '') {
                            throw new Exception('AWG2 server parameters are missing; refusing to generate a client config from defaults');
                        }
                    }
                }

                // Build variables for template
                $vars = [
                    'private_key' => $keys['private'],
                    'client_ip' => $clientIP,
                    'server_public_key' => $serverData['server_public_key'],
                    'preshared_key' => $serverData['preshared_key'],
                    'server_host' => self::endpointHost($serverData),
                    'server_port' => $serverData['vpn_port'],
                    'dns_servers' => $serverData['dns_servers'] ?? '1.1.1.1, 1.0.0.1',
                ];

                // Normalize AWG params keys case-insensitively.
                $cleanAwgParams = [];
                if (is_array($awgParams)) {
                    foreach ($awgParams as $k => $v) {
                        $cleanAwgParams[strtoupper($k)] = $v;
                    }
                }

                $defaultAwgParams = self::getAwgParamDefaults($slug);

                foreach (array_keys($defaultAwgParams) as $key) {
                    if (isset($cleanAwgParams[$key])) {
                        $vars[$key] = $cleanAwgParams[$key];
                    } else {
                        $vars[$key] = $defaultAwgParams[$key];
                    }
                }

                // Backward/Template compatibility: the AWG client template uses Jc/Jmin/Jmax (not all-caps).
                if (!isset($vars['Jc']) && isset($vars['JC'])) {
                    $vars['Jc'] = (string) $vars['JC'];
                }
                if (!isset($vars['Jmin']) && isset($vars['JMIN'])) {
                    $vars['Jmin'] = (string) $vars['JMIN'];
                }
                if (!isset($vars['Jmax']) && isset($vars['JMAX'])) {
                    $vars['Jmax'] = (string) $vars['JMAX'];
                }
                foreach (['S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $key) {
                    if (!isset($vars[$key]) && isset($vars[strtoupper($key)])) {
                        $vars[$key] = (string) $vars[strtoupper($key)];
                    }
                }

                return [$awgParams, $vars];
            });

            // Generate config from template
            $config = self::timed('create.generate_config', [
                'server_id' => $serverId,
                'protocol' => $slug,
            ], function () use ($protoRow, $vars, $keys, $clientIP, $serverData, $awgParams, $slug) {
                if ($protoRow && !empty($protoRow['output_template'])) {
                    require_once __DIR__ . '/ProtocolService.php';
                    return ProtocolService::generateProtocolOutput($protoRow, $vars);
                }

                // Fallback to old method if no template
                return self::buildClientConfig(
                    $keys['private'],
                    $clientIP,
                    $serverData['server_public_key'],
                    $serverData['preshared_key'],
                    self::endpointHost($serverData),
                    $serverData['vpn_port'],
                    is_array($awgParams) ? $awgParams : [],
                    $slug
                );
            });

            self::timed('create.add_client_to_server', [
                'server_id' => $serverId,
                'protocol' => $slug,
            ], fn() => self::addClientToServer($serverData, $keys['public'], $clientIP));

            // Failover pool: the peer must exist on every member so the client
            // config (shared identity + domain) works against any of them.
            if (!empty($serverData['pool_id'])) {
                self::timed('create.push_peer_to_pool', [
                    'server_id' => $serverId,
                    'pool_id' => (int) $serverData['pool_id'],
                ], fn() => ServerPool::pushPeerToMembers((int) $serverData['pool_id'], $keys['public'], $clientIP, $serverId));
            }
            $qrCode = self::timed('create.generate_qr_code', [
                'server_id' => $serverId,
                'protocol' => $slug,
            ], fn() => self::generateQRCode($config, $slug));
            $priv = $keys['private'];
            $pub = $keys['public'];
            $psk = $serverData['preshared_key'];
            $pass = null;
        } else {
            $vars = [];
            $vars['private_key'] = '';
            $vars['client_ip'] = $clientIP;
            $vars['server_host'] = self::endpointHost($serverData);
            $vars['server_port'] = $serverData['vpn_port'] ?? '';
            $extras = [];
            if ($protocolId) {
                try {
                    $stmtSp = $pdo->prepare('SELECT config_data FROM server_protocols WHERE server_id = ? AND protocol_id = ? LIMIT 1');
                    $stmtSp->execute([$serverId, $protocolId]);
                    $cfg = $stmtSp->fetchColumn();
                    if ($cfg) {
                        $conf = is_string($cfg) ? json_decode($cfg, true) : $cfg;
                        if (is_array($conf)) {
                            $vars['server_host'] = $conf['server_host'] ?? $vars['server_host'];
                            $vars['server_port'] = $conf['server_port'] ?? $vars['server_port'];
                            $extras = $conf['extras'] ?? [];
                        }
                    }
                } catch (Exception $e) {
                }
            }
            if (is_array($extras)) {
                // If extras has 'result' subarray, merge it into extras for processing
                if (isset($extras['result']) && is_array($extras['result'])) {
                    $extras = array_merge($extras, $extras['result']);
                }

                foreach ($extras as $k => $v) {
                    if (is_scalar($v)) {
                        // Preserve uppercase for AWG obfuscation parameters
                        if (in_array($k, ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4'], true)) {
                            $vars[$k] = (string) $v;
                        } else {
                            $vars[strtolower($k)] = (string) $v;
                        }
                    }
                }

                if (isset($vars['containername']) && empty($vars['container_name'])) {
                    $vars['container_name'] = $vars['containername'];
                }
            }
            $pass = null;
            $pwdCmd = isset($protoRow['password_command']) ? trim((string) $protoRow['password_command']) : '';
            if ($pwdCmd !== '') {
                try {
                    $wrapper = "bash <<'EOS'\nLOGIN=" . escapeshellarg($loginFinal) . "\n" . $pwdCmd . "\nEOS";
                    $out = $server->executeCommand($wrapper, true);
                    $passTrim = trim((string) $out);
                    if ($passTrim !== '')
                        $pass = $passTrim;
                } catch (Exception $e) {
                }
            }
            if ($pass === null) {
                if (!empty($vars['password'])) {
                    $pass = (string) $vars['password'];
                } else {
                    $pass = 'amnezia';
                }
            }
            $vars['login'] = $loginFinal;
            $vars['password'] = $pass;

            // Try to add client to server via universal manager (supports scripts and builtins)
            if ($protoRow) {
                // We pass generic options. InstallProtocolManager will handle specific logic for 'add_client' phase.
                try {
                    require_once __DIR__ . '/InstallProtocolManager.php';
                    $addClientResult = self::timed('create.protocol_add_client', [
                        'server_id' => $serverId,
                        'protocol' => $slug,
                    ], fn() => InstallProtocolManager::addClient($server, $protoRow, $vars));
                    if (is_array($addClientResult)) {
                        foreach ($addClientResult as $rk => $rv) {
                            if (!is_scalar($rv)) {
                                continue;
                            }
                            $key = (string) $rk;
                            $value = trim((string) $rv);
                            if ($value === '') {
                                continue;
                            }
                            $vars[$key] = $value;
                            $vars[strtolower($key)] = $value;
                        }
                    }
                } catch (Exception $e) {
                    error_log("Failed to add client to server: " . $e->getMessage());
                    throw $e;
                }
            }

            if ($protoRow) {
                require_once __DIR__ . '/ProtocolService.php';
                $config = ProtocolService::generateProtocolOutput($protoRow, $vars);
            } else {
                $config = '';
            }

            // Prepare last_config_json for QR code generation if config is JSON (XRay)
            if ($config !== '' && ($decoded = json_decode($config)) !== null) {
                $vars['last_config_json'] = json_encode($decoded, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            }

            $qrCode = self::timed('create.generate_qr_code', [
                'server_id' => $serverId,
                'protocol' => $slug,
            ], fn() => self::generateQRCode($config, $slug));

            $priv = '';
            $pub = '';
            $psk = '';
        }

        // Calculate expiration date
        $expiresAt = $expiresInDays ? date('Y-m-d H:i:s', strtotime("+{$expiresInDays} days")) : null;

        // Insert into database
        $stmt = $pdo->prepare('
            INSERT INTO vpn_clients 
            (server_id, user_id, protocol_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');

        self::timed('create.db_insert', [
            'server_id' => $serverId,
            'protocol' => $slug,
        ], fn() => $stmt->execute([
            $serverId,
            $userId,
            $protocolId ?: null,
            $loginFinal,
            $clientIP,
            $pub,
            $priv,
            $psk,
            $config,
            $qrCode,
            'active',
            $expiresAt
        ]));

        $clientId = (int) $pdo->lastInsertId();
        self::logTiming('create.total', (microtime(true) - $createStartedAt) * 1000, [
            'server_id' => $serverId,
            'client_id' => $clientId,
            'protocol' => $slug,
        ], true);

        return $clientId;
    }

    public static function listByServerAndProtocol(int $serverId, int $protocolId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, p.name as protocol_name 
            FROM vpn_clients c
            LEFT JOIN protocols p ON c.protocol_id = p.id
            WHERE c.server_id = ? AND c.protocol_id = ? 
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$serverId, $protocolId]);
        return $stmt->fetchAll();
    }

    /**
     * Import client data directly from backup without touching remote server.
     */
    public static function importFromBackup(array $serverData, int $userId, array $clientData): ?int
    {
        if (empty($serverData['id'])) {
            throw new Exception('Server must be saved before importing clients');
        }

        $pdo = DB::conn();

        $clientIp = trim($clientData['client_ip'] ?? '');
        $publicKey = trim($clientData['public_key'] ?? '');
        $privateKey = trim($clientData['private_key'] ?? '');

        if ($clientIp === '' || $publicKey === '' || $privateKey === '') {
            throw new Exception('Client backup data is incomplete');
        }

        // Skip if client with same IP already exists
        $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND client_ip = ? LIMIT 1');
        $stmt->execute([$serverData['id'], $clientIp]);
        if ($stmt->fetchColumn()) {
            return null;
        }

        $name = trim($clientData['name'] ?? '');
        if ($name === '') {
            $name = $clientIp;
        }

        $presharedKey = $clientData['preshared_key'] ?? ($serverData['preshared_key'] ?? '');
        $config = $clientData['config'] ?? '';

        if ($config === '' && !empty($serverData['server_public_key']) && !empty($serverData['host']) && !empty($serverData['vpn_port'])) {
            $awgParams = json_decode($serverData['awg_params'] ?? '{}', true);
            if (!is_array($awgParams)) {
                $awgParams = [];
            }
            $config = self::buildClientConfig(
                $privateKey,
                $clientIp,
                $serverData['server_public_key'],
                $presharedKey,
                self::endpointHost($serverData),
                (int) $serverData['vpn_port'],
                $awgParams,
                (string) ($serverData['install_protocol'] ?? '')
            );
        }

        // Try to fetch protocol for QR code generation
        $protocol = null;
        if (!empty($serverData['install_protocol'])) {
            $stmtP = $pdo->prepare('SELECT * FROM protocols WHERE slug = ?');
            $stmtP->execute([$serverData['install_protocol']]);
            $protocol = $stmtP->fetch(PDO::FETCH_ASSOC);
        }

        $vars = [];
        // Prepare last_config_json if config is JSON
        if ($config !== '' && ($decoded = json_decode($config)) !== null) {
            $vars['last_config_json'] = json_encode($decoded, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        }

        $qrCode = $config !== '' ? self::generateQRCode($config, $serverData['install_protocol'] ?? '') : '';
        $status = strtolower($clientData['status'] ?? 'active') === 'disabled' ? 'disabled' : 'active';

        $expiresAt = $clientData['expires_at'] ?? null;
        if ($expiresAt) {
            $timestamp = strtotime($expiresAt);
            $expiresAt = $timestamp ? date('Y-m-d H:i:s', $timestamp) : null;
        }

        $stmt = $pdo->prepare('
            INSERT INTO vpn_clients 
            (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');

        $stmt->execute([
            $serverData['id'],
            $userId,
            $name,
            $clientIp,
            $publicKey,
            $privateKey,
            $presharedKey,
            $config,
            $qrCode,
            $status,
            $expiresAt
        ]);

        return (int) $pdo->lastInsertId();
    }

    /**
     * Generate WireGuard-compatible client keys.
     * Prefer local libsodium to avoid a remote SSH/Docker roundtrip; keep remote fallback.
     */
    private static function generateClientKeys(array $serverData, string $clientName): array
    {
        if (function_exists('sodium_crypto_scalarmult_base')) {
            $privateBytes = random_bytes(32);
            $privateBytes[0] = chr(ord($privateBytes[0]) & 248);
            $privateBytes[31] = chr((ord($privateBytes[31]) & 127) | 64);

            $publicBytes = sodium_crypto_scalarmult_base($privateBytes);

            return [
                'private' => base64_encode($privateBytes),
                'public' => base64_encode($publicBytes),
            ];
        }

        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        $isAwg2 = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2');
        $wgTool = $isAwg2 ? 'awg' : 'wg';

        $cmd = sprintf(
            "docker exec -i %s sh -lc 'set -e; umask 077; priv=\$(%s genkey | tr -d " . '"' . "\\r\\n" . '"' . "); [ -n \"\$priv\" ] || { echo empty_private_key; exit 1; }; pub=\$(printf " . '"' . "%%s\\n" . '"' . " \"\$priv\" | %s pubkey | tr -d " . '"' . "\\r\\n" . '"' . "); [ -n \"\$pub\" ] || { echo empty_public_key; exit 1; }; printf " . '"' . "%%s\\n---\\n%%s\\n" . '"' . " \"\$priv\" \"\$pub\"'",
            escapeshellarg($containerName),
            $wgTool,
            $wgTool
        );

        $out = self::executeServerCommand($serverData, $cmd);
        $parts = explode("---", trim($out));

        if (count($parts) < 2) {
            $head = substr(trim((string) $out), 0, 240);
            throw new Exception("Failed to generate client keys" . ($head !== '' ? (": " . $head) : ''));
        }

        $private = trim((string) $parts[0]);
        $public = trim((string) $parts[1]);
        if ($private === '' || $public === '') {
            throw new Exception('Failed to generate client keys: empty key output');
        }

        return [
            'private' => $private,
            'public' => $public
        ];
    }

    /**
     * Get next available client IP
     */
    public static function getNextClientIP(array $serverData, bool $checkRemoteConfig = false): string
    {
        $pdo = DB::conn();

        // Get used IPs from database
        $stmt = $pdo->prepare('SELECT client_ip FROM vpn_clients WHERE server_id = ?');
        $stmt->execute([$serverData['id']]);
        $usedIPs = $stmt->fetchAll(PDO::FETCH_COLUMN);

        // Reserve network address and server gateway (.1)
        $used = ['10.8.1.0' => true, '10.8.1.1' => true];
        foreach ($usedIPs as $ip) {
            $used[$ip] = true;
        }

        // Remote config checks are intentionally opt-in: they add an SSH/Docker roundtrip
        // to every client creation and are only needed when peers are created outside the panel.
        if ($checkRemoteConfig) {
            try {
                $containerName = $serverData['container_name'] ?? 'amnezia-awg';
                $server = new VpnServer($serverData['id']);
                $cmd = sprintf(
                    "docker exec %s cat /opt/amnezia/awg/wg0.conf 2>/dev/null",
                    escapeshellarg($containerName)
                );
                $serverConfig = $server->executeCommand($cmd, true);

                // Extract AllowedIPs from all peers
                if (preg_match_all('/AllowedIPs\s*=\s*([0-9.]+)\/\d+/i', $serverConfig, $matches)) {
                    foreach ($matches[1] as $ip) {
                        $used[$ip] = true;
                    }
                }
            } catch (Exception $e) {
                error_log('Failed to check server config for used IPs: ' . $e->getMessage());
                // Continue with DB-only check
            }
        }

        // Parse subnet
        $parts = explode('/', $serverData['vpn_subnet']);
        $networkLong = ip2long($parts[0]);

        // Find next free IP starting from .1
        for ($i = 1; $i <= 253; $i++) {
            $candidate = long2ip($networkLong + $i);
            if (!isset($used[$candidate])) {
                return $candidate;
            }
        }

        throw new Exception('No free IP addresses in subnet');
    }

    /**
     * Auto-sync server keys from running container (for externally installed protocols)
     */
    private static function getAwgParamDefaults(string $protocolSlug = ''): array
    {
        if ($protocolSlug === 'awg2') {
            return [
                'JC' => 5,
                'JMIN' => 10,
                'JMAX' => 50,
                'S1' => 51,
                'S2' => 125,
                'S3' => 13,
                'S4' => 9,
                'H1' => '1443912531-1981073285',
                'H2' => '1984025557-2135018048',
                'H3' => '2145217268-2146643749',
                'H4' => '2146790761-2146860793',
                'I1' => '<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>',
                'I2' => '<r 4><b 0x16030100><r 64>',
                'I3' => '<r 8><b 0x17030300><r 48>',
                'I4' => '<r 6><b 0x00000001><r 32>',
                'I5' => '<r 10><b 0x08000000><r 40>',
            ];
        }

        return [
            'JC' => 5,
            'JMIN' => 100,
            'JMAX' => 200,
            'S1' => 50,
            'S2' => 100,
            'S3' => 20,
            'S4' => 10,
            'H1' => 1,
            'H2' => 2,
            'H3' => 3,
            'H4' => 4,
        ];
    }

    private static function extractAwgParamsFromWg0Conf(VpnServer $server, string $containerName, string $confPath): array
    {
        $awgParams = [];

        $awgLinesCmd = sprintf(
            "docker exec %s sh -c \"grep -E '^[[:space:]]*(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|I1|I2|I3|I4|I5)[[:space:]]*=' %s 2>/dev/null || true\"",
            escapeshellarg($containerName),
            escapeshellarg($confPath)
        );
        $awgLines = (string) $server->executeCommand($awgLinesCmd, true);

        foreach (preg_split('/\r?\n/', trim($awgLines)) as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (preg_match('/^(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|I1|I2|I3|I4|I5)\s*=\s*(.*)$/i', $line, $m)) {
                $k = strtoupper($m[1]);
                $value = trim($m[2]);
                $awgParams[$k] = ctype_digit($value) ? (int) $value : $value;
            }
        }

        return $awgParams;
    }

    private static function extractPeerPskFromWgDump(VpnServer $server, string $containerName, string $clientPublicKey, string $protocolSlug = ''): ?string
    {
        $clientPublicKey = trim($clientPublicKey);
        if ($clientPublicKey === '') {
            return null;
        }

        // wg show wg0 dump peer line format:
        // public_key \t preshared_key \t endpoint \t allowed_ips \t latest_handshake \t rx \t tx \t keepalive
        $isAwg2 = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2');
        $wgTool = $isAwg2 ? 'awg' : 'wg';
        $ifaceName = $isAwg2 ? 'awg0' : 'wg0';
        $cmdDump = sprintf('docker exec %s %s show %s dump 2>/dev/null || true', escapeshellarg($containerName), $wgTool, $ifaceName);
        $dump = (string) $server->executeCommand($cmdDump, true);
        if (trim($dump) === '' && $isAwg2) {
            $cmdDump = sprintf('docker exec %s wg show wg0 dump 2>/dev/null || true', escapeshellarg($containerName));
            $dump = (string) $server->executeCommand($cmdDump, true);
        }
        foreach (preg_split('/\r?\n/', trim($dump)) as $line) {
            if ($line === '') {
                continue;
            }
            // Skip interface header line (has many fields but first field is private key)
            if (strpos($line, '\t') === false) {
                continue;
            }
            if (strpos($line, $clientPublicKey . "\t") !== 0) {
                continue;
            }

            $parts = explode("\t", $line);
            if (count($parts) < 2) {
                return null;
            }
            $psk = trim((string) $parts[1]);
            if ($psk === '' || $psk === '(none)') {
                return null;
            }
            return $psk;
        }

        return null;
    }

    private static function syncServerKeysFromContainer(VpnServer $server, array $serverData): void
    {
        $containerName = $serverData['container_name'] ?? 'amnezia-awg';
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        $isAwg2 = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2');
        $primaryConfigDir = '/opt/amnezia/awg';
        $primaryConfigFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';
        $primaryIface = $isAwg2 ? 'awg0' : 'wg0';
        $wgTool = $isAwg2 ? 'awg' : 'wg';

        try {
            // Try to get public key from wg show
            $pubKeyCmd = "docker exec $containerName $wgTool show $primaryIface 2>/dev/null | grep 'public key:' | awk '{print \$3}'";
            $pubKey = trim($server->executeCommand($pubKeyCmd, true));
            if ($pubKey === '' && $isAwg2) {
                $pubKey = trim($server->executeCommand("docker exec $containerName wg show wg0 2>/dev/null | grep 'public key:' | awk '{print \$3}'", true));
            }

            // Get listening port
            $portCmd = "docker exec $containerName $wgTool show $primaryIface 2>/dev/null | grep 'listening port:' | awk '{print \$3}'";
            $port = trim($server->executeCommand($portCmd, true));
            if ($port === '' && $isAwg2) {
                $port = trim($server->executeCommand("docker exec $containerName wg show wg0 2>/dev/null | grep 'listening port:' | awk '{print \$3}'", true));
            }

            // PresharedKey is stored per-peer, and in this project we persist it in wireguard_psk.key.
            // Prefer that file (stable) and fall back to parsing the first peer PSK from wg0.conf.
            $psk = '';

            $pskKeyFileCmd = "docker exec $containerName sh -c \"cat $primaryConfigDir/wireguard_psk.key 2>/dev/null || cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true\"";
            $psk = trim($server->executeCommand($pskKeyFileCmd, true));

            if ($psk === '') {
                $pskFromConfCmd = "docker exec $containerName sh -c \"grep -E '^[[:space:]]*PresharedKey[[:space:]]*=' $primaryConfigDir/$primaryConfigFile 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*//' | tr -d '\\r'\" 2>/dev/null || true";
                $psk = trim($server->executeCommand($pskFromConfCmd, true));
            }

            if ($psk === '' && $primaryConfigDir !== '/opt/amnezia/awg') {
                $pskFromAwgConfCmd = "docker exec $containerName sh -c \"grep -E '^[[:space:]]*PresharedKey[[:space:]]*=' /opt/amnezia/awg/wg0.conf 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*//' | tr -d '\\r'\" 2>/dev/null || true";
                $psk = trim($server->executeCommand($pskFromAwgConfCmd, true));
            }

            if ($psk === '') {
                $pskFromAltConfCmd = "docker exec $containerName sh -c \"grep -E '^[[:space:]]*PresharedKey[[:space:]]*=' /etc/wireguard/wg0.conf 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*//' | tr -d '\\r'\" 2>/dev/null || true";
                $psk = trim($server->executeCommand($pskFromAltConfCmd, true));
            }

            // Extract DNS from config
            $dnsCmd = "docker exec $containerName sh -c \"grep -E '^DNS' $primaryConfigDir/$primaryConfigFile 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]'\" 2>/dev/null || echo ''";
            $dns = trim($server->executeCommand($dnsCmd, true));

            if (empty($dns) && $primaryConfigDir !== '/opt/amnezia/awg') {
                $dnsAwgCmd = "docker exec $containerName sh -c \"grep -E '^DNS' /opt/amnezia/awg/wg0.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]'\" 2>/dev/null || echo ''";
                $dns = trim($server->executeCommand($dnsAwgCmd, true));
            }

            if (empty($dns)) {
                // Try alternative config location
                $dnsCmd2 = "docker exec $containerName sh -c \"grep -E '^DNS' /etc/wireguard/wg0.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]'\" 2>/dev/null || echo ''";
                $dns = trim($server->executeCommand($dnsCmd2, true));
            }

            // Default DNS if not found
            if (empty($dns)) {
                $dns = '1.1.1.1, 1.0.0.1';
            }

            // Extract AWG parameters.
            // NOTE: amnezia-awg does not expose these via `wg show` in many builds,
            // so we primarily read them from /opt/amnezia/awg/wg0.conf.
            $awgParams = [];

            // Legacy attempt: some builds print jc/jmin/... in `wg show` output.
            $wgShowCmd = "docker exec $containerName $wgTool show $primaryIface 2>/dev/null";
            $wgOutput = (string) $server->executeCommand($wgShowCmd, true);
            $paramNames = ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5'];
            foreach ($paramNames as $param) {
                // For H1-H4 parameters, expect format like "1443912531-1981073285" (two values with dash)
                // For other parameters, expect single integer value
                if (in_array($param, ['h1', 'h2', 'h3', 'h4'], true)) {
                    if (preg_match('/^\s*' . preg_quote($param, '/') . ':\s*(\d+-\d+)/mi', $wgOutput, $matches)) {
                        $awgParams[strtoupper($param)] = $matches[1];
                    }
                } else {
                    if (preg_match('/^\s*' . preg_quote($param, '/') . ':\s*(\d+)/mi', $wgOutput, $matches)) {
                        $awgParams[strtoupper($param)] = (int) $matches[1];
                    }
                }
            }

            // Primary source: config file. Merge it even if `awg show` returned a partial set,
            // because AWG2 packet templates (I1-I5) are not reliably exposed by `awg show`.
            $configAwgParams = self::extractAwgParamsFromWg0Conf($server, $containerName, $primaryConfigDir . '/' . $primaryConfigFile);
            if (empty($configAwgParams) && $isAwg2) {
                $configAwgParams = self::extractAwgParamsFromWg0Conf($server, $containerName, '/opt/amnezia/awg/wg0.conf');
            }
            if (empty($configAwgParams)) {
                $configAwgParams = self::extractAwgParamsFromWg0Conf($server, $containerName, '/etc/wireguard/wg0.conf');
            }
            if (!empty($configAwgParams)) {
                $awgParams = array_merge($awgParams, $configAwgParams);
            }

            // Update database if we found keys
            if (!empty($pubKey) && !empty($port)) {
                $pdo = DB::conn();

                $awgParamsJson = !empty($awgParams) ? json_encode($awgParams) : null;

                // Update vpn_servers with all extracted values including DNS
                if (!empty($psk)) {
                    if (self::hasLastKeySyncColumn()) {
                        $stmt = $pdo->prepare('UPDATE vpn_servers SET server_public_key = ?, preshared_key = ?, vpn_port = ?, awg_params = ?, dns_servers = ?, last_key_sync_at = NOW() WHERE id = ?');
                        $stmt->execute([$pubKey, $psk, (int) $port, $awgParamsJson, $dns, $serverData['id']]);
                    } else {
                        $stmt = $pdo->prepare('UPDATE vpn_servers SET server_public_key = ?, preshared_key = ?, vpn_port = ?, awg_params = ?, dns_servers = ? WHERE id = ?');
                        $stmt->execute([$pubKey, $psk, (int) $port, $awgParamsJson, $dns, $serverData['id']]);
                    }
                } else {
                    if (self::hasLastKeySyncColumn()) {
                        $stmt = $pdo->prepare('UPDATE vpn_servers SET server_public_key = ?, vpn_port = ?, awg_params = ?, dns_servers = ?, last_key_sync_at = NOW() WHERE id = ?');
                        $stmt->execute([$pubKey, (int) $port, $awgParamsJson, $dns, $serverData['id']]);
                    } else {
                        $stmt = $pdo->prepare('UPDATE vpn_servers SET server_public_key = ?, vpn_port = ?, awg_params = ?, dns_servers = ? WHERE id = ?');
                        $stmt->execute([$pubKey, (int) $port, $awgParamsJson, $dns, $serverData['id']]);
                    }
                }

                error_log("Auto-synced server keys from container $containerName: port=$port, dns=$dns, awg_params=" . ($awgParamsJson ?? 'none'));
            }
        } catch (Exception $e) {
            error_log('Error syncing keys from container: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Resolve the host used in the client config Endpoint. Prefers the server's
     * configured domain (e.g. awg.gptanalitika.com) so clients connect via the
     * domain and the server can be swapped by repointing DNS; falls back to the
     * raw host IP when no domain is set.
     */
    public static function endpointHost(array $serverData): string
    {
        $domain = trim((string) ($serverData['domain'] ?? ''));
        return $domain !== '' ? $domain : (string) ($serverData['host'] ?? '');
    }

    /**
     * Build client configuration file
     */
    public static function buildClientConfig(
        string $privateKey,
        string $clientIP,
        string $serverPublicKey,
        string $presharedKey,
        string $serverHost,
        int $serverPort,
        array $awgParams,
        string $protocolSlug = ''
    ): string {
        // Get default parameters for the protocol
        $defaultParams = self::getAwgParamDefaults($protocolSlug);
        
        // Normalize $awgParams keys to uppercase for consistency
        $normalizedAwgParams = [];
        foreach ($awgParams as $k => $v) {
            $normalizedAwgParams[strtoupper($k)] = $v;
        }
        
        // Merge: use server params only if they have correct format, otherwise use defaults
        // This is critical for H1-H4 which must have "value1-value2" format
        $finalParams = $defaultParams;
        foreach ($normalizedAwgParams as $key => $value) {
            $upperKey = strtoupper($key);
            
            // For H1-H4 parameters, only use server value if it has the correct "value1-value2" format
            if (in_array($upperKey, ['H1', 'H2', 'H3', 'H4'], true)) {
                if (is_scalar($value) && preg_match('/^\d+(?:-\d+)?$/', (string) $value)) {
                    $finalParams[$upperKey] = (string) $value;
                }
            } else {
                $finalParams[$upperKey] = $value;
            }
        }
        
        $config = "[Interface]\n";
        $config .= "Address = {$clientIP}/32\n";
        $config .= "DNS = 1.1.1.1, 1.0.0.1\n";
        $config .= "PrivateKey = {$privateKey}\n";

        // Add AWG parameters (in the order used by Amnezia app)
        // For awg2 include I1-I5, S3, S4; for regular awg only H1-H4, Jc, Jmin, Jmax, S1, S2
        // Order: Jc, Jmin, Jmax, S1, S2, S3, S4, H1, H2, H3, H4, I1, I2, I3, I4, I5
        $paramKeys = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4'];
        if ($protocolSlug === 'awg2') {
            $paramKeys = array_merge($paramKeys, ['I1', 'I2', 'I3', 'I4', 'I5']);
        }
        
        foreach ($paramKeys as $key) {
            $value = null;
            if (isset($finalParams[$key])) {
                $value = $finalParams[$key];
            } elseif (isset($finalParams[strtoupper($key)])) {
                $value = $finalParams[strtoupper($key)];
            }
            
            // Always add parameter if it's defined (even if empty for I2-I5)
            if ($value !== null) {
                $config .= "{$key} = {$value}\n";
            }
        }

        $config .= "\n[Peer]\n";
        $config .= "PublicKey = {$serverPublicKey}\n";
        $config .= "PresharedKey = {$presharedKey}\n";
        $config .= "Endpoint = {$serverHost}:{$serverPort}\n";
        $config .= "AllowedIPs = 0.0.0.0/0, ::/0\n";
        $config .= "PersistentKeepalive = 25\n\n";

        return $config;
    }

    /**
     * Add client to server using wg set (more reliable than syncconf)
     */
    public static function addClientToServer(array $serverData, string $publicKey, string $clientIP): void
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        $isAwg2 = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2');
        $configDir = '/opt/amnezia/awg';

        $presharedKey = $serverData['preshared_key'];
        $publicKey = trim($publicKey);

        if ($publicKey === '') {
            throw new Exception('Refusing to add client with empty public key');
        }

        $wgTool = $isAwg2 ? 'awg' : 'wg';
        $wgQuickTool = $isAwg2 ? 'awg-quick' : 'wg-quick';
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';
        $reloadInterfaceOnAdd = in_array(strtolower((string) getenv('AMNEZIA_RELOAD_INTERFACE_ON_ADD')), ['1', 'true', 'yes'], true);
        $clientTableEntry = json_encode([
            'clientId' => $publicKey,
            'userData' => [
                // Preserve the historical behavior: addClientToServer used client IP as clientsTable name.
                'clientName' => $clientIP,
                'creationDate' => date('D M j H:i:s Y'),
            ],
        ], JSON_UNESCAPED_SLASHES);

        $script = <<<'BASH'
set -e

CONTAINER_NAME=__CONTAINER_NAME__
CONFIG_DIR=__CONFIG_DIR__
CONFIG_FILE=__CONFIG_FILE__
IS_AWG2=__IS_AWG2__
WG_TOOL=__WG_TOOL__
WG_QUICK_TOOL=__WG_QUICK_TOOL__
RELOAD_INTERFACE_ON_ADD=__RELOAD_INTERFACE_ON_ADD__
PUBLIC_KEY_B64=__PUBLIC_KEY_B64__
PRESHARED_KEY_B64=__PRESHARED_KEY_B64__
CLIENT_IP=__CLIENT_IP__
CLIENT_TABLE_ENTRY_B64=__CLIENT_TABLE_ENTRY_B64__

PUBLIC_KEY=$(printf '%s' "$PUBLIC_KEY_B64" | base64 -d)
PRESHARED_KEY=$(printf '%s' "$PRESHARED_KEY_B64" | base64 -d)
CLIENT_TABLE_ENTRY=$(printf '%s' "$CLIENT_TABLE_ENTRY_B64" | base64 -d)

docker exec -i \
  -e CONFIG_DIR="$CONFIG_DIR" \
  -e CONFIG_FILE="$CONFIG_FILE" \
  -e IS_AWG2="$IS_AWG2" \
  -e WG_TOOL="$WG_TOOL" \
  -e WG_QUICK_TOOL="$WG_QUICK_TOOL" \
  -e RELOAD_INTERFACE_ON_ADD="$RELOAD_INTERFACE_ON_ADD" \
  -e PUBLIC_KEY="$PUBLIC_KEY" \
  -e PRESHARED_KEY="$PRESHARED_KEY" \
  -e CLIENT_IP="$CLIENT_IP" \
  -e CLIENT_TABLE_ENTRY="$CLIENT_TABLE_ENTRY" \
  "$CONTAINER_NAME" sh -s <<'CONTAINER_SH'
set -e

if [ "$IS_AWG2" = "1" ] && { [ ! -f "$CONFIG_DIR/$CONFIG_FILE" ] || ! grep -q '\[Interface\]' "$CONFIG_DIR/$CONFIG_FILE"; }; then
  CONFIG_FILE=wg0.conf
fi

IFACE_NAME=${CONFIG_FILE%.conf}
PSK_FILE="/tmp/amnezia-peer-$$.psk"

cleanup() {
  rm -f "$PSK_FILE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf '%s\n' "$PRESHARED_KEY" > "$PSK_FILE"

"$WG_TOOL" set "$IFACE_NAME" peer "$PUBLIC_KEY" preshared-key "$PSK_FILE" allowed-ips "$CLIENT_IP/32"
cat >> "$CONFIG_DIR/$CONFIG_FILE" <<EOF

[Peer]
PublicKey = $PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_IP/32
EOF

TABLE_JSON=$(cat "$CONFIG_DIR/clientsTable" 2>/dev/null || true)
if ! printf '%s' "$TABLE_JSON" | grep -q '^[[:space:]]*\['; then
  UPDATED_TABLE="[$CLIENT_TABLE_ENTRY]"
else
  TABLE_TRIMMED=$(printf '%s' "$TABLE_JSON" | tr -d '\r\n' | sed -e 's/[[:space:]]*$//')
  TABLE_BODY=$(printf '%s' "$TABLE_TRIMMED" | sed -e 's/[[:space:]]*\][[:space:]]*$//')
  if printf '%s' "$TABLE_BODY" | grep -q '^[[:space:]]*\[[[:space:]]*$'; then
    UPDATED_TABLE="${TABLE_BODY}${CLIENT_TABLE_ENTRY}]"
  else
    UPDATED_TABLE="${TABLE_BODY},${CLIENT_TABLE_ENTRY}]"
  fi
fi

printf '%s\n' "$UPDATED_TABLE" > "$CONFIG_DIR/clientsTable"

if [ "$RELOAD_INTERFACE_ON_ADD" = "1" ]; then
  ip link del "$IFACE_NAME" 2>/dev/null || true
  "$WG_QUICK_TOOL" up "$CONFIG_DIR/$CONFIG_FILE" 2>&1
fi
CONTAINER_SH

echo "__AMNEZIA_ADD_CLIENT_OK__"
BASH;

        $replacements = [
            '__CONTAINER_NAME__' => escapeshellarg($containerName),
            '__CONFIG_DIR__' => escapeshellarg($configDir),
            '__CONFIG_FILE__' => escapeshellarg($configFile),
            '__IS_AWG2__' => $isAwg2 ? '1' : '0',
            '__WG_TOOL__' => escapeshellarg($wgTool),
            '__WG_QUICK_TOOL__' => escapeshellarg($wgQuickTool),
            '__RELOAD_INTERFACE_ON_ADD__' => $reloadInterfaceOnAdd ? '1' : '0',
            '__PUBLIC_KEY_B64__' => escapeshellarg(base64_encode($publicKey)),
            '__PRESHARED_KEY_B64__' => escapeshellarg(base64_encode((string) $presharedKey)),
            '__CLIENT_IP__' => escapeshellarg($clientIP),
            '__CLIENT_TABLE_ENTRY_B64__' => escapeshellarg(base64_encode((string) $clientTableEntry)),
        ];

        $output = self::executeServerCommand($serverData, 'bash -lc ' . escapeshellarg(strtr($script, $replacements)), true);
        if (strpos($output, '__AMNEZIA_ADD_CLIENT_OK__') === false) {
            $tail = trim(substr($output, -500));
            throw new Exception('Failed to add client to server' . ($tail !== '' ? ': ' . $tail : ''));
        }
    }

    /**
     * Update clientsTable on server
     */
    private static function updateClientsTable(array $serverData, string $publicKey, string $name): void
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        // Для AWG2 конфигурация внутри контейнера находится в /opt/amnezia/awg/
        $configDir = '/opt/amnezia/awg'; // Внутри контейнера всегда /opt/amnezia/awg

        // Read current table
        $cmd = sprintf("docker exec -i %s cat %s/clientsTable 2>/dev/null", escapeshellarg($containerName), $configDir);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);

        if (!is_array($table)) {
            $table = [];
        }

        // Add new client
        $table[] = [
            'clientId' => $publicKey,
            'userData' => [
                'clientName' => $name,
                'creationDate' => date('D M j H:i:s Y')
            ]
        ];

        self::writeClientsTable($serverData, $containerName, $configDir, $table);
    }

    /**
     * Safely write clientsTable inside the container.
     *
     * The JSON is base64-encoded and decoded on the server, so client-controlled
     * values (e.g. client name) can never break out of the shell command. Do NOT
     * revert to interpolating JSON into `echo "..."` — addslashes does not escape
     * `$`/backticks and allows command injection (see WireGuard add-peer path).
     */
    private static function writeClientsTable(array $serverData, string $containerName, string $configDir, array $table): void
    {
        $payloadB64 = base64_encode((string) json_encode($table, JSON_PRETTY_PRINT));
        // base64 output contains only [A-Za-z0-9+/=], so it is safe inside single quotes.
        $innerScript = sprintf("printf '%%s' '%s' | base64 -d > %s/clientsTable", $payloadB64, $configDir);
        $updateCmd = sprintf('docker exec -i %s sh -c %s', escapeshellarg($containerName), escapeshellarg($innerScript));
        self::executeServerCommand($serverData, $updateCmd, true);
    }

    /**
     * Execute command on server
     */
    private static function executeServerCommand(array $serverData, string $command, bool $sudo = false): string
    {
        $baseCommand = $command;
        $needsSudo = $sudo && strtolower((string) ($serverData['username'] ?? '')) !== 'root';
        $prepared = $needsSudo ? Ssh::wrapSudo($serverData, $command) : $command;

        $output = Ssh::exec($serverData, $prepared, ['timeout' => 300])->output;

        // If sudo auth fails but docker is available without sudo (docker group), retry without sudo.
        if (
            $needsSudo
            && preg_match('/(^|\\n)docker(\\s|$)/', ltrim($baseCommand))
            && Ssh::isSudoAuthFailure($output)
        ) {
            $output = Ssh::exec($serverData, $baseCommand, ['timeout' => 300])->output;
        }

        return $output;
    }

    /**
     * Generate QR code for configuration using Amnezia format
     * Uses working QrUtil from /Users/oleg/Documents/amnezia
     */
    public static function generateQRCode(string $config, string $protocolSlug = ''): string
    {
        require_once __DIR__ . '/QrUtil.php';

        try {
            // Use old Amnezia format with Qt/QDataStream encoding, but pass protocol slug
            $payloadOld = QrUtil::encodeOldPayloadFromConf($config, $protocolSlug);
            $dataUri = QrUtil::pngBase64($payloadOld);
            return $dataUri;
        } catch (Throwable $e) {
            error_log('Failed to generate QR code: ' . $e->getMessage());
            return ''; // QR code generation failed, but continue
        }
    }

    /**
     * Generate second QR code in vpn:// URL format
     * Used for newer Amnezia app versions that support vpn:// scheme
     */
    public static function generateQRCodeVpnUrl(string $config, string $protocolSlug = ''): string
    {
        require_once __DIR__ . '/QrUtil.php';

        try {
            // For AWG2 and other WireGuard/AWG, use vpn:// URL format with JSON + zlib
            $payloadVpn = QrUtil::encodeVpnUrlConf($config, $protocolSlug);
            $dataUri = QrUtil::pngBase64($payloadVpn);
            return $dataUri;
        } catch (Throwable $e) {
            error_log('Failed to generate vpn:// QR code: ' . $e->getMessage());
            return '';
        }
    }

    /**
     * Get all clients for a server
     */
    public static function listByServer(int $serverId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, p.name as protocol_name, p.show_text_content
            FROM vpn_clients c
            LEFT JOIN protocols p ON c.protocol_id = p.id
            WHERE c.server_id = ? 
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$serverId]);
        return $stmt->fetchAll();
    }

    /**
     * Get all clients for a user
     */
    public static function listByUser(int $userId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host as server_host, p.name as protocol_name, p.show_text_content
            FROM vpn_clients c
            LEFT JOIN vpn_servers s ON c.server_id = s.id
            LEFT JOIN protocols p ON c.protocol_id = p.id
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    /**
     * Revoke client access (disable without deleting)
     */
    public function revoke(): bool
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $isWireguard = self::isWireguardProtocol((int) ($this->data['protocol_id'] ?? 0));
        if ($isWireguard) {
            $server = new VpnServer($this->data['server_id']);
            $serverData = $server->getData();
            if ($serverData && $serverData['status'] === 'active') {
                try {
                    self::timed('revoke.remove_client_from_server', [
                        'server_id' => $this->data['server_id'] ?? null,
                        'client_id' => $this->clientId,
                    ], fn() => self::removeClientFromServer($serverData, $this->data['public_key']));
                } catch (Exception $e) {
                    error_log('Failed to remove client from server: ' . $e->getMessage());
                }
            }
        }

        // Mark as disabled in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return self::timed('revoke.db_update', [
            'server_id' => $this->data['server_id'] ?? null,
            'client_id' => $this->clientId,
        ], fn() => $stmt->execute(['disabled', $this->clientId]));
    }

    /**
     * Restore client access
     */
    public function restore(): bool
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $isWireguard = self::isWireguardProtocol((int) ($this->data['protocol_id'] ?? 0));
        if ($isWireguard) {
            $server = new VpnServer($this->data['server_id']);
            $serverData = $server->getData();
            if ($serverData && $serverData['status'] === 'active') {
                try {
                    self::timed('restore.add_client_to_server', [
                        'server_id' => $this->data['server_id'] ?? null,
                        'client_id' => $this->clientId,
                    ], fn() => self::addClientToServer($serverData, $this->data['public_key'], $this->data['client_ip']));
                } catch (Exception $e) {
                    throw new Exception('Failed to restore client on server: ' . $e->getMessage());
                }
            }
        }

        // Mark as active in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return self::timed('restore.db_update', [
            'server_id' => $this->data['server_id'] ?? null,
            'client_id' => $this->clientId,
        ], fn() => $stmt->execute(['active', $this->clientId]));
    }

    private static function isWireguardProtocol(?int $protocolId): bool
    {
        if (!$protocolId)
            return true;
        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT slug FROM protocols WHERE id = ?');
            $stmt->execute([$protocolId]);
            $slug = (string) $stmt->fetchColumn();
            return in_array($slug, ['awg2'], true);
        } catch (Exception $e) {
            return true;
        }
    }

    /**
     * Delete client permanently
     */
    public function delete(): bool
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        // First revoke to remove from server
        if ($this->data['status'] === 'active') {
            $this->revoke();
        }

        // Delete from database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM vpn_clients WHERE id = ?');
        return self::timed('delete.db_delete', [
            'server_id' => $this->data['server_id'] ?? null,
            'client_id' => $this->clientId,
        ], fn() => $stmt->execute([$this->clientId]));
    }

    /**
     * Remove client from server WireGuard configuration
     */
    private static function removeClientFromServer(array $serverData, string $publicKey): void
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        $configDir = '/opt/amnezia/awg';
        $publicKey = trim($publicKey);

        if ($publicKey === '') {
            throw new Exception('Refusing to remove client with empty public key');
        }

        $isAwg2 = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2');
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';
        $wgTool = $isAwg2 ? 'awg' : 'wg';
        $wgQuickTool = $isAwg2 ? 'awg-quick' : 'wg-quick';

        $script = <<<'BASH'
set -e

CONTAINER_NAME=__CONTAINER_NAME__
CONFIG_DIR=__CONFIG_DIR__
CONFIG_FILE=__CONFIG_FILE__
IS_AWG2=__IS_AWG2__
WG_TOOL=__WG_TOOL__
WG_QUICK_TOOL=__WG_QUICK_TOOL__
PUBLIC_KEY_B64=__PUBLIC_KEY_B64__

PUBLIC_KEY=$(printf '%s' "$PUBLIC_KEY_B64" | base64 -d)

if [ "$IS_AWG2" = "1" ]; then
  if ! docker exec -i "$CONTAINER_NAME" sh -c "test -f '$CONFIG_DIR/$CONFIG_FILE' && grep -q '\[Interface\]' '$CONFIG_DIR/$CONFIG_FILE'"; then
    CONFIG_FILE=wg0.conf
  fi
fi

IFACE_NAME=${CONFIG_FILE%.conf}

docker exec -i "$CONTAINER_NAME" "$WG_TOOL" set "$IFACE_NAME" peer "$PUBLIC_KEY" remove

PUBLIC_KEY_ESC=$(printf '%s' "$PUBLIC_KEY" | sed "s/'/'\\\\''/g")
docker exec -i "$CONTAINER_NAME" sh -c "awk -v target='$PUBLIC_KEY_ESC' '
function trim(s) {
  gsub(/^[ \t\r]+|[ \t\r]+$/, \"\", s)
  return s
}
function flush_block(i) {
  if (!skip) {
    for (i = 1; i <= n; i++) print block[i]
  }
  n = 0
  skip = 0
}
{
  line = \$0
  t = trim(line)
  if (t ~ /^\\[/) {
    flush_block()
    if (t == \"[Peer]\") {
      in_peer = 1
      block[++n] = line
      next
    }
    in_peer = 0
    print line
    next
  }
  if (in_peer) {
    block[++n] = line
    if (t ~ /^PublicKey[ \t]*=/) {
      key = line
      sub(/^[^=]*=/, \"\", key)
      if (trim(key) == target) skip = 1
    }
    next
  }
  print line
}
END {
  flush_block()
}
' '$CONFIG_DIR/$CONFIG_FILE' > '$CONFIG_DIR/$CONFIG_FILE.tmp' && mv '$CONFIG_DIR/$CONFIG_FILE.tmp' '$CONFIG_DIR/$CONFIG_FILE'"

docker exec -i "$CONTAINER_NAME" "$WG_QUICK_TOOL" save "$IFACE_NAME"

TABLE_JSON=$(docker exec -i "$CONTAINER_NAME" cat "$CONFIG_DIR/clientsTable" 2>/dev/null || true)
if command -v python3 >/dev/null 2>&1; then
  UPDATED_TABLE=$(printf '%s' "$TABLE_JSON" | CLIENT_PUBLIC_KEY="$PUBLIC_KEY" python3 -c 'import json, os, sys
raw = sys.stdin.read().strip()
try:
    table = json.loads(raw) if raw else []
except Exception:
    table = []
target = os.environ.get("CLIENT_PUBLIC_KEY", "")
if isinstance(table, list):
    table = [item for item in table if not (isinstance(item, dict) and item.get("clientId") == target)]
else:
    table = []
print(json.dumps(table, indent=4))')
  printf '%s\n' "$UPDATED_TABLE" | docker exec -i "$CONTAINER_NAME" sh -c "cat > '$CONFIG_DIR/clientsTable'"
else
  echo "__AMNEZIA_CLIENTS_TABLE_FALLBACK__"
fi

echo "__AMNEZIA_REMOVE_CLIENT_OK__"
BASH;

        $replacements = [
            '__CONTAINER_NAME__' => escapeshellarg($containerName),
            '__CONFIG_DIR__' => escapeshellarg($configDir),
            '__CONFIG_FILE__' => escapeshellarg($configFile),
            '__IS_AWG2__' => $isAwg2 ? '1' : '0',
            '__WG_TOOL__' => escapeshellarg($wgTool),
            '__WG_QUICK_TOOL__' => escapeshellarg($wgQuickTool),
            '__PUBLIC_KEY_B64__' => escapeshellarg(base64_encode($publicKey)),
        ];

        $output = self::executeServerCommand($serverData, 'bash -lc ' . escapeshellarg(strtr($script, $replacements)), true);
        if (strpos($output, '__AMNEZIA_REMOVE_CLIENT_OK__') === false) {
            $tail = trim(substr($output, -500));
            throw new Exception('Failed to remove client from server' . ($tail !== '' ? ': ' . $tail : ''));
        }
        if (strpos($output, '__AMNEZIA_CLIENTS_TABLE_FALLBACK__') !== false) {
            self::removeFromClientsTable($serverData, $publicKey);
        }
    }

    /**
     * Remove peer section from WireGuard config
     */
    private static function removePeerFromConfig(string $config, string $publicKey): string
    {
        $lines = explode("\n", $config);
        $newLines = [];
        $inPeerBlock = false;
        $skipBlock = false;

        foreach ($lines as $line) {
            $trimmed = trim($line);

            // Start of new section
            if (strpos($trimmed, '[') === 0) {
                $inPeerBlock = ($trimmed === '[Peer]');
                $skipBlock = false;
            }

            // Check if this peer block should be skipped
            if ($inPeerBlock && strpos($trimmed, 'PublicKey') === 0) {
                $parts = explode('=', $line, 2);
                if (count($parts) === 2 && trim($parts[1]) === $publicKey) {
                    $skipBlock = true;
                    // Remove the [Peer] line that was already added
                    array_pop($newLines);
                    continue;
                }
            }

            // Skip lines in the block to be removed
            if ($skipBlock && $inPeerBlock) {
                // Empty line ends the peer block
                if (empty($trimmed)) {
                    $skipBlock = false;
                    $inPeerBlock = false;
                }
                continue;
            }

            $newLines[] = $line;
        }

        return implode("\n", $newLines);
    }

    /**
     * Remove client from clientsTable
     */
    private static function removeFromClientsTable(array $serverData, string $publicKey): void
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        // Для AWG2 конфигурация внутри контейнера находится в /opt/amnezia/awg/
        $configDir = '/opt/amnezia/awg'; // Внутри контейнера всегда /opt/amnezia/awg

        // Read current table
        $cmd = sprintf("docker exec -i %s cat %s/clientsTable 2>/dev/null", escapeshellarg($containerName), $configDir);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);

        if (!is_array($table)) {
            return;
        }

        // Filter out the client
        $table = array_filter($table, function ($client) use ($publicKey) {
            return ($client['clientId'] ?? '') !== $publicKey;
        });

        // Re-index array
        $table = array_values($table);

        self::writeClientsTable($serverData, $containerName, $configDir, $table);
    }

    /**
     * Get client data
     */
    public function getData(): ?array
    {
        return $this->data;
    }

    /**
     * Get configuration file content
     */
    public function getConfig(): string
    {
        $config = $this->data['config'] ?? '';
        // Decode escape sequences like \n that may be stored in database
        return stripcslashes($config);
    }

    /**
     * Regenerate and persist client configuration using current server container data.
     * Useful when server was reinstalled/recreated and AWG params/keys changed.
     */
    public function regenerateConfigFromServer(bool $forceSyncServer = true): array
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $server = new VpnServer((int) $this->data['server_id']);
        $serverData = $server->getData();
        if (!$serverData) {
            throw new Exception('Server not found');
        }

        $protocolId = (int) ($this->data['protocol_id'] ?? 0);
        $protoRow = null;
        if ($protocolId > 0) {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT * FROM protocols WHERE id = ? LIMIT 1');
            $stmt->execute([$protocolId]);
            $protoRow = $stmt->fetch();
        }
        $slug = $protoRow['slug'] ?? '';
        $isWireguard = in_array($slug, ['awg2'], true);

        if (!$isWireguard) {
            return ['success' => false, 'error' => 'not_wireguard_protocol', 'protocol_slug' => $slug];
        }

        if ($forceSyncServer) {
            self::timed('regenerate.sync_server_keys', [
                'server_id' => $this->data['server_id'] ?? null,
                'client_id' => $this->clientId,
                'protocol' => $slug,
            ], fn() => self::syncServerKeysFromContainer($server, $serverData));
            $server->refresh();
            $serverData = $server->getData();
        }

        $privateKey = (string) ($this->data['private_key'] ?? '');
        $clientPublicKey = (string) ($this->data['public_key'] ?? '');
        $clientIP = (string) ($this->data['client_ip'] ?? '');
        if ($privateKey === '' || $clientIP === '') {
            throw new Exception('Client keys or IP missing');
        }

        $awgParams = json_decode($serverData['awg_params'] ?? '{}', true) ?? [];
        if (!is_array($awgParams)) {
            $awgParams = [];
        }

        // Accept mixed-case keys from installer outputs (e.g. Jc/Jmin/Jmax)
        // by duplicating them into canonical uppercase AWG keys.
        foreach ($awgParams as $k => $v) {
            $uk = strtoupper((string) $k);
            if (in_array($uk, ['JC', 'JMIN', 'JMAX', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'], true) && !isset($awgParams[$uk])) {
                $awgParams[$uk] = $v;
            }
        }

        // If AWG params are missing (common after reinstall), fetch them directly from wg0.conf
        // to avoid falling back to template defaults that will not match the server.
        if (in_array($slug, ['awg2'], true)) {
            $needKeys = $slug === 'awg2'
                ? ['JC', 'JMIN', 'JMAX', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5']
                : ['JC', 'JMIN', 'JMAX', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'];
            $missing = false;
            foreach ($needKeys as $k) {
                if (!isset($awgParams[$k])) {
                    $missing = true;
                    break;
                }
            }

            if ($missing) {
                $containerName = $serverData['container_name'] ?? ($slug === 'awg2' ? 'amnezia-awg2' : 'amnezia-awg');
                $configDir = '/opt/amnezia/awg';
                $configFile = $slug === 'awg2' ? 'awg0.conf' : 'wg0.conf';
                $direct = self::extractAwgParamsFromWg0Conf($server, $containerName, $configDir . '/' . $configFile);
                if (empty($direct) && $slug === 'awg2') {
                    $direct = self::extractAwgParamsFromWg0Conf($server, $containerName, $configDir . '/wg0.conf');
                }
                if (empty($direct)) {
                    $direct = self::extractAwgParamsFromWg0Conf($server, $containerName, '/etc/wireguard/wg0.conf');
                }

                if (!empty($direct)) {
                    $awgParams = $direct;

                    // Persist to server row for future generations/diagnostics
                    try {
                        $pdo = DB::conn();
                        $stmt = $pdo->prepare('UPDATE vpn_servers SET awg_params = ? WHERE id = ?');
                        $stmt->execute([json_encode($awgParams), (int) ($serverData['id'] ?? 0)]);
                    } catch (Exception $e) {
                        // Best-effort only; regeneration can continue.
                        error_log('Failed to persist AWG params during regeneration: ' . $e->getMessage());
                    }
                }
            }

            $awgParams = array_merge(self::getAwgParamDefaults($slug), $awgParams);

            // Still missing? Refuse to overwrite config with template defaults.
            foreach ($needKeys as $k) {
                if (!isset($awgParams[$k])) {
                    return [
                        'success' => false,
                        'error' => 'awg_params_missing',
                        'protocol_slug' => $slug,
                        'server_id' => (int) ($serverData['id'] ?? 0),
                    ];
                }
            }
        }

        // Prefer per-peer PSK from wg dump (server may use different PSKs per peer)
        $presharedKeyForConfig = (string) ($serverData['preshared_key'] ?? '');
        try {
            $containerName = $serverData['container_name'] ?? 'amnezia-awg';
            $peerPsk = self::timed('regenerate.extract_peer_psk', [
                'server_id' => $this->data['server_id'] ?? null,
                'client_id' => $this->clientId,
                'protocol' => $slug,
            ], fn() => self::extractPeerPskFromWgDump($server, $containerName, $clientPublicKey, $slug));
            if ($peerPsk !== null && $peerPsk !== '') {
                $presharedKeyForConfig = $peerPsk;
            }
        } catch (Exception $e) {
            // Best-effort; fallback to serverData['preshared_key']
            error_log('Failed to extract peer PSK from wg dump: ' . $e->getMessage());
        }

        $vars = [
            'private_key' => $privateKey,
            'client_ip' => $clientIP,
            'server_public_key' => (string) ($serverData['server_public_key'] ?? ''),
            'preshared_key' => $presharedKeyForConfig,
            'server_host' => self::endpointHost($serverData),
            'server_port' => (string) ((int) ($serverData['vpn_port'] ?? 0)),
            'dns_servers' => (string) ($serverData['dns_servers'] ?? '1.1.1.1, 1.0.0.1'),
        ];

        foreach (array_keys(self::getAwgParamDefaults($slug)) as $key) {
            if (isset($awgParams[$key])) {
                $vars[$key] = $awgParams[$key];
            }
        }

        if (!isset($vars['Jc']) && isset($vars['JC'])) {
            $vars['Jc'] = (string) $vars['JC'];
        }
        if (!isset($vars['Jmin']) && isset($vars['JMIN'])) {
            $vars['Jmin'] = (string) $vars['JMIN'];
        }
        if (!isset($vars['Jmax']) && isset($vars['JMAX'])) {
            $vars['Jmax'] = (string) $vars['JMAX'];
        }
        foreach (['S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $key) {
            if (!isset($vars[$key]) && isset($vars[strtoupper($key)])) {
                $vars[$key] = (string) $vars[strtoupper($key)];
            }
        }

        if ($protoRow && !empty($protoRow['output_template'])) {
            require_once __DIR__ . '/ProtocolService.php';
            $config = ProtocolService::generateProtocolOutput($protoRow, $vars);
        } else {
            $config = self::buildClientConfig(
                $privateKey,
                $clientIP,
                (string) ($serverData['server_public_key'] ?? ''),
                $presharedKeyForConfig,
                self::endpointHost($serverData),
                (int) ($serverData['vpn_port'] ?? 0),
                $awgParams,
                $slug
            );
        }

        $qrCode = self::timed('regenerate.generate_qr_code', [
            'server_id' => $this->data['server_id'] ?? null,
            'client_id' => $this->clientId,
            'protocol' => $slug,
        ], fn() => self::generateQRCode($config, $slug));

        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET config = ?, qr_code = ?, preshared_key = ? WHERE id = ?');
        self::timed('regenerate.db_update', [
            'server_id' => $this->data['server_id'] ?? null,
            'client_id' => $this->clientId,
            'protocol' => $slug,
        ], fn() => $stmt->execute([$config, $qrCode, $presharedKeyForConfig, (int) $this->clientId]));

        // Refresh cached data
        $this->load();

        return [
            'success' => true,
            'client_id' => (int) $this->clientId,
            'protocol_slug' => $slug,
            'server_id' => (int) ($this->data['server_id'] ?? 0),
            'awg_params' => $awgParams,
            'peer_psk_source' => ($presharedKeyForConfig !== '' && $presharedKeyForConfig !== (string) ($serverData['preshared_key'] ?? '')) ? 'wg_dump' : 'server_row',
        ];
    }

    /**
     * Get QR code
     */
    public function getQRCode(): string
    {
        return $this->data['qr_code'] ?? '';
    }

    /**
     * Sync traffic statistics from server
     */
    public function syncStats(): bool
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();

        if (!$serverData || $serverData['status'] !== 'active') {
            return false;
        }

        try {
            // Get previous stats for speed calculation
            $pdo = DB::conn();
            $stmtPrev = $pdo->prepare('SELECT bytes_sent, bytes_received, last_sync_at, last_handshake FROM vpn_clients WHERE id = ?');
            $stmtPrev->execute([$this->clientId]);
            $prev = $stmtPrev->fetch();

            $prevSent = (int) ($prev['bytes_sent'] ?? 0);
            $prevReceived = (int) ($prev['bytes_received'] ?? 0);
            $prevSyncAt = $prev['last_sync_at'] ? strtotime($prev['last_sync_at']) : 0;

            // AmneziaWG 2.0 stats are read directly from the WireGuard peer dump.
            $stats = self::getClientStatsFromServer($serverData, $this->data['public_key']);

            // Calculate speeds (bytes per second)
            $now = time();
            $timeDiff = $now - $prevSyncAt;
            $currentSpeed = 0;
            $speedUp = 0;
            $speedDown = 0;

            if ($timeDiff > 0 && $prevSyncAt > 0) {
                // Total speed
                $bytesDiff = ($stats['bytes_sent'] + $stats['bytes_received']) - ($prevSent + $prevReceived);
                if ($bytesDiff > 0) {
                    $currentSpeed = (int) ($bytesDiff / $timeDiff);
                }

                // Upload speed
                $sentDiff = $stats['bytes_sent'] - $prevSent;
                if ($sentDiff > 0) {
                    $speedUp = (int) ($sentDiff / $timeDiff);
                }

                // Download speed
                $receivedDiff = $stats['bytes_received'] - $prevReceived;
                if ($receivedDiff > 0) {
                    $speedDown = (int) ($receivedDiff / $timeDiff);
                }
            }

            $stmt = $pdo->prepare('
                UPDATE vpn_clients
                SET bytes_sent = ?, bytes_received = ?, last_handshake = ?, current_speed = ?, speed_up = ?, speed_down = ?, last_sync_at = NOW()
                WHERE id = ?
            ');

            $lastHandshake = $stats['last_handshake'] > 0
                ? date('Y-m-d H:i:s', $stats['last_handshake'])
                : null;

            return $stmt->execute([
                $stats['bytes_sent'],
                $stats['bytes_received'],
                $lastHandshake,
                $currentSpeed,
                $speedUp,
                $speedDown,
                $this->clientId
            ]);
        } catch (Exception $e) {
            error_log('Failed to sync client stats: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get client statistics from server
     */
    private static function getClientStatsFromServer(array $serverData, string $publicKey): array
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        $isAwg2 = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2');
        $wgTool = $isAwg2 ? 'awg' : 'wg';
        $ifaceName = $isAwg2 ? 'awg0' : 'wg0';

        // Get WireGuard interface stats
        $cmd = sprintf("docker exec -i %s %s show %s dump", $containerName, $wgTool, $ifaceName);
        $output = self::executeServerCommand($serverData, $cmd, true);
        if (trim($output) === '' && $isAwg2) {
            $cmd = sprintf("docker exec -i %s wg show wg0 dump", $containerName);
            $output = self::executeServerCommand($serverData, $cmd, true);
        }

        $stats = [
            'bytes_sent' => 0,
            'bytes_received' => 0,
            'last_handshake' => 0
        ];

        // Parse wg dump output
        // Format: public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
        // First line is server (private key), skip it
        // For clients: transfer_rx = bytes received by server (sent by client)
        //              transfer_tx = bytes sent by server (received by client)
        $lines = explode("\n", trim($output));
        foreach ($lines as $line) {
            if (empty($line))
                continue;

            $parts = preg_split('/\s+/', trim($line));

            // Skip first line (server) - it has different format
            if (count($parts) < 7)
                continue;

            // Match by public key
            if ($parts[0] === $publicKey) {
                $stats['last_handshake'] = (int) $parts[4];
                $stats['bytes_sent'] = (int) $parts[5];      // transfer_rx - client sent
                $stats['bytes_received'] = (int) $parts[6];  // transfer_tx - client received
                break;
            }
        }

        return $stats;
    }

    /**
     * Sync stats for all active clients on a server
     */
    public static function syncAllStatsForServer(int $serverId): int
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND status = ?');
        $stmt->execute([$serverId, 'active']);
        $clientIds = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $synced = 0;
        foreach ($clientIds as $clientId) {
            try {
                $client = new VpnClient($clientId);
                if ($client->syncStats()) {
                    $synced++;
                }
            } catch (Exception $e) {
                error_log('Failed to sync stats for client ' . $clientId . ': ' . $e->getMessage());
            }
        }

        return $synced;
    }

    /**
     * Get human-readable traffic statistics
     */
    public function getFormattedStats(): array
    {
        if (!$this->data) {
            return ['sent' => 'N/A', 'received' => 'N/A', 'total' => 'N/A', 'last_seen' => 'Never'];
        }

        $sent = $this->formatBytes($this->data['bytes_sent'] ?? 0);
        $received = $this->formatBytes($this->data['bytes_received'] ?? 0);
        $total = $this->formatBytes(($this->data['bytes_sent'] ?? 0) + ($this->data['bytes_received'] ?? 0));

        $lastSeen = 'Never';
        if (!empty($this->data['last_handshake'])) {
            $lastHandshake = strtotime($this->data['last_handshake']);
            $diff = time() - $lastHandshake;

            if ($diff < 300) {
                $lastSeen = 'Online';
            } elseif ($diff < 3600) {
                $lastSeen = floor($diff / 60) . ' minutes ago';
            } elseif ($diff < 86400) {
                $lastSeen = floor($diff / 3600) . ' hours ago';
            } else {
                $lastSeen = floor($diff / 86400) . ' days ago';
            }
        }

        return [
            'sent' => $sent,
            'received' => $received,
            'total' => $total,
            'last_seen' => $lastSeen,
            'is_online' => !empty($this->data['last_handshake']) && (time() - strtotime($this->data['last_handshake'])) < 300
        ];
    }

    /**
     * Format bytes to human-readable string (always in MB)
     */
    private function formatBytes(int $bytes): string
    {
        $mb = $bytes / 1048576; // 1024 * 1024
        return number_format($mb, 2) . ' MB';
    }

    /**
     * Set client expiration date
     * 
     * @param int $clientId Client ID
     * @param string|null $expiresAt Expiration date (Y-m-d H:i:s) or null for never expires
     * @return bool Success
     */
    public static function setExpiration(int $clientId, ?string $expiresAt): bool
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET expires_at = ? WHERE id = ?');
        return $stmt->execute([$expiresAt, $clientId]);
    }

    /**
     * Extend client expiration by days
     * 
     * @param int $clientId Client ID
     * @param int $days Days to extend
     * @return bool Success
     */
    public static function extendExpiration(int $clientId, int $days): bool
    {
        $pdo = DB::conn();

        // Get current expiration
        $stmt = $pdo->prepare('SELECT expires_at FROM vpn_clients WHERE id = ?');
        $stmt->execute([$clientId]);
        $client = $stmt->fetch();

        if (!$client) {
            return false;
        }

        // Calculate new expiration from current or now
        $baseDate = $client['expires_at'] ? strtotime($client['expires_at']) : time();
        $newExpiration = date('Y-m-d H:i:s', strtotime("+{$days} days", $baseDate));

        return self::setExpiration($clientId, $newExpiration);
    }

    /**
     * Get clients expiring soon
     * 
     * @param int $days Check for clients expiring within N days
     * @return array List of expiring clients
     */
    public static function getExpiringClients(int $days = 7): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host, u.name as user_name, u.email
            FROM vpn_clients c
            JOIN vpn_servers s ON c.server_id = s.id
            JOIN users u ON c.user_id = u.id
            WHERE c.expires_at IS NOT NULL 
            AND c.expires_at <= DATE_ADD(NOW(), INTERVAL ? DAY)
            AND c.expires_at > NOW()
            AND c.status = "active"
            ORDER BY c.expires_at ASC
        ');
        $stmt->execute([$days]);
        return $stmt->fetchAll();
    }

    /**
     * Get expired clients
     * 
     * @return array List of expired clients
     */
    public static function getExpiredClients(): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->query('
            SELECT c.*, s.name as server_name, s.host
            FROM vpn_clients c
            JOIN vpn_servers s ON c.server_id = s.id
            WHERE c.expires_at IS NOT NULL 
            AND c.expires_at <= NOW()
            AND c.status = "active"
            ORDER BY c.expires_at DESC
        ');
        return $stmt->fetchAll();
    }

    /**
     * Disable expired clients automatically
     * 
     * @return int Number of clients disabled
     */
    public static function disableExpiredClients(): int
    {
        $expiredClients = self::getExpiredClients();
        $count = 0;

        foreach ($expiredClients as $clientData) {
            try {
                $client = new self($clientData['id']);
                $client->revoke();
                $count++;
            } catch (Exception $e) {
                error_log("Failed to disable expired client {$clientData['id']}: " . $e->getMessage());
            }
        }

        return $count;
    }

    /**
     * Check if client is expired
     * 
     * @return bool True if expired
     */
    public function isExpired(): bool
    {
        if (!$this->data) {
            return false;
        }

        return $this->data['expires_at'] !== null && strtotime($this->data['expires_at']) <= time();
    }

    /**
     * Get days until expiration
     * 
     * @return int|null Days until expiration (negative if expired, null if never expires)
     */
    public function getDaysUntilExpiration(): ?int
    {
        if (!$this->data || $this->data['expires_at'] === null) {
            return null;
        }

        $diff = strtotime($this->data['expires_at']) - time();
        return (int) floor($diff / 86400);
    }

    /**
     * Set traffic limit for client
     * 
     * @param int|null $limitBytes Traffic limit in bytes (NULL = unlimited)
     * @return bool Success
     */
    public function setTrafficLimit(?int $limitBytes): bool
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET traffic_limit = ? WHERE id = ?');
        $result = $stmt->execute([$limitBytes, $this->clientId]);

        if ($result) {
            $this->data['traffic_limit'] = $limitBytes;
        }

        return $result;
    }

    /**
     * Get total traffic used (sent + received)
     * 
     * @return int Total traffic in bytes
     */
    public function getTotalTraffic(): int
    {
        if (!$this->data) {
            return 0;
        }

        return (int) ($this->data['traffic_sent'] ?? 0) + (int) ($this->data['traffic_received'] ?? 0);
    }

    /**
     * Check if client has exceeded traffic limit
     * 
     * @return bool True if over limit
     */
    public function isOverLimit(): bool
    {
        if (!$this->data || $this->data['traffic_limit'] === null) {
            return false; // No limit set
        }

        $totalTraffic = $this->getTotalTraffic();
        return $totalTraffic >= (int) $this->data['traffic_limit'];
    }

    /**
     * Get traffic limit status
     * 
     * @return array Status info
     */
    public function getTrafficLimitStatus(): array
    {
        $totalTraffic = $this->getTotalTraffic();
        $limit = $this->data['traffic_limit'] ?? null;

        return [
            'total_traffic' => $totalTraffic,
            'traffic_limit' => $limit,
            'is_unlimited' => $limit === null,
            'is_over_limit' => $this->isOverLimit(),
            'percentage_used' => $limit ? min(100, round(($totalTraffic / $limit) * 100, 2)) : 0,
            'remaining' => $limit ? max(0, $limit - $totalTraffic) : null
        ];
    }

    /**
     * Get all clients that exceeded their traffic limit
     * 
     * @return array List of client IDs over limit
     */
    public static function getClientsOverLimit(): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->query('
            SELECT id, name, traffic_sent, traffic_received, traffic_limit 
            FROM vpn_clients 
            WHERE traffic_limit IS NOT NULL 
            AND (traffic_sent + traffic_received) >= traffic_limit 
            AND status = "active"
            ORDER BY id
        ');

        return $stmt->fetchAll();
    }

    /**
     * Disable all clients that exceeded their traffic limit
     * 
     * @return int Number of clients disabled
     */
    public static function disableClientsOverLimit(): int
    {
        $clients = self::getClientsOverLimit();
        $disabled = 0;

        foreach ($clients as $clientData) {
            try {
                $client = new VpnClient($clientData['id']);
                if ($client->revoke()) {
                    $disabled++;
                    error_log("Client {$clientData['name']} (ID: {$clientData['id']}) disabled: traffic limit exceeded");
                }
            } catch (Exception $e) {
                error_log("Failed to disable client {$clientData['id']}: " . $e->getMessage());
            }
        }

        return $disabled;
    }
}
