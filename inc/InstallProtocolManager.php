<?php
require_once __DIR__ . '/Logger.php';

class InstallProtocolManager
{
    private const DEFAULT_SLUG = 'awg2';
    private const SESSION_KEY = 'pending_deploy_decisions';

    private static function persistServerContainerName(int $serverId, string $containerName): void
    {
        $containerName = trim($containerName);
        if ($serverId <= 0 || $containerName === '') {
            return;
        }

        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('UPDATE vpn_servers SET container_name = ? WHERE id = ?');
            $stmt->execute([$containerName, $serverId]);
        } catch (Throwable $e) {
        }
    }

    private static function installAwg2WatchdogIfNeeded(VpnServer $server, array $protocol, array $details = []): void
    {
        if (($protocol['slug'] ?? '') !== 'awg2') {
            return;
        }

        $sourcePath = dirname(__DIR__) . '/watchdog-amnezia-awg2.sh';
        if (!is_file($sourcePath)) {
            Logger::appendInstall($server->getId(), 'AWG2 watchdog skipped: local script not found');
            return;
        }

        try {
            $script = (string) file_get_contents($sourcePath);
            $metadata = $protocol['definition']['metadata'] ?? [];
            $containerName = trim((string) ($details['container_name'] ?? $metadata['container_name'] ?? 'amnezia-awg2'));
            if ($containerName === '') {
                $containerName = 'amnezia-awg2';
            }

            $vpnPort = (int) ($details['vpn_port'] ?? 0);
            if ($vpnPort <= 0) {
                $serverData = $server->getData();
                $vpnPort = (int) ($serverData['vpn_port'] ?? 0);
            }

            $script = preg_replace('/^CONTAINER=.*$/m', 'CONTAINER=' . self::shellDoubleQuotedLiteral($containerName), $script);
            $script = preg_replace('/^WG_IFACE=.*$/m', 'WG_IFACE="awg0"', $script);
            if ($vpnPort > 0) {
                $script = preg_replace('/^UDP_PORT=.*$/m', 'UDP_PORT="' . $vpnPort . '"', $script);
            }

            $remoteScript = '/usr/local/sbin/watchdog-amnezia-awg2.sh';
            $cronPath = '/etc/cron.d/amnezia-awg2-watchdog';
            $encodedScript = base64_encode($script);
            $cronLine = '* * * * * root ' . $remoteScript . ' >/dev/null 2>&1';
            $encodedCron = base64_encode($cronLine . "\n");

            $cmd = implode(' && ', [
                'mkdir -p /usr/local/sbin',
                'printf %s ' . escapeshellarg($encodedScript) . ' | base64 -d > ' . escapeshellarg($remoteScript),
                'chmod 0755 ' . escapeshellarg($remoteScript),
                'printf %s ' . escapeshellarg($encodedCron) . ' | base64 -d > ' . escapeshellarg($cronPath),
                'chmod 0644 ' . escapeshellarg($cronPath),
                '(systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || service cron start 2>/dev/null || true)',
                '(systemctl reload cron 2>/dev/null || systemctl reload crond 2>/dev/null || true)',
            ]);

            $server->executeCommand($cmd, true);
            Logger::appendInstall($server->getId(), 'AWG2 watchdog installed: ' . $remoteScript . ' cron=' . $cronPath);
        } catch (Throwable $e) {
            Logger::appendInstall($server->getId(), 'AWG2 watchdog install skipped: ' . $e->getMessage());
        }
    }

    private static function removeAwg2Watchdog(VpnServer $server): void
    {
        try {
            $server->executeCommand('rm -f /usr/local/sbin/watchdog-amnezia-awg2.sh /etc/cron.d/amnezia-awg2-watchdog 2>/dev/null || true', true);
            Logger::appendInstall($server->getId(), 'AWG2 watchdog removed');
        } catch (Throwable $e) {
            Logger::appendInstall($server->getId(), 'AWG2 watchdog remove skipped: ' . $e->getMessage());
        }
    }

    private static function shellDoubleQuotedLiteral(string $value): string
    {
        return '"' . str_replace(['\\', '"', '$', '`'], ['\\\\', '\\"', '\\$', '\\`'], $value) . '"';
    }

    public static function getDefaultSlug(): string
    {
        return self::DEFAULT_SLUG;
    }

    public static function ensureDefaults(): void
    {
        return;
    }

    public static function listActive(): array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->query('SELECT * FROM protocols WHERE is_active = 1 ORDER BY name');
            $rows = $stmt->fetchAll();
            return array_map([self::class, 'hydrateProtocol'], $rows);
        } catch (Throwable $e) {
            return [];
        }
    }

    /**
     * Protocols that can be installed as the server's primary protocol.
     * cf-warp is an egress add-on activated from the server page on top of a
     * running awg2 container, so it is excluded from the create-server flow.
     */
    public static function listStandalone(): array
    {
        return array_values(array_filter(self::listActive(), function ($p) {
            return ($p['slug'] ?? '') !== 'cf-warp';
        }));
    }

    public static function getAll(): array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->query('SELECT * FROM protocols ORDER BY name');
            $rows = $stmt->fetchAll();
            return array_map([self::class, 'hydrateProtocol'], $rows);
        } catch (Throwable $e) {
            return [];
        }
    }

    public static function getBySlug(string $slug): ?array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT * FROM protocols WHERE slug = ? LIMIT 1');
            $stmt->execute([$slug]);
            $row = $stmt->fetch();
            if ($row) {
                return self::hydrateProtocol($row);
            }
        } catch (Throwable $e) {
        }
        return null;
    }

    public static function getById(int $id): ?array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT * FROM protocols WHERE id = ? LIMIT 1');
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            return $row ? self::hydrateProtocol($row) : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    public static function save(array $data): int
    {
        $pdo = DB::conn();
        $definition = $data['definition'] ?? [];
        if (is_string($definition)) {
            $definition = json_decode($definition, true) ?: [];
        }

        $definitionJson = json_encode($definition, JSON_UNESCAPED_SLASHES);
        $isActive = isset($data['is_active']) ? (int) $data['is_active'] : 1;

        if (!empty($data['id'])) {
            $stmt = $pdo->prepare('
                UPDATE install_protocols
                SET slug = ?, name = ?, description = ?, definition = ?, is_active = ?, updated_at = NOW()
                WHERE id = ?
            ');
            $stmt->execute([
                $data['slug'],
                $data['name'],
                $data['description'] ?? null,
                $definitionJson,
                $isActive,
                $data['id']
            ]);
            return (int) $data['id'];
        }

        $stmt = $pdo->prepare('
            INSERT INTO install_protocols (slug, name, description, definition, is_active)
            VALUES (?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $data['slug'],
            $data['name'],
            $data['description'] ?? null,
            $definitionJson,
            $isActive
        ]);

        return (int) $pdo->lastInsertId();
    }

    public static function delete(int $id): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM install_protocols WHERE id = ?');
        $stmt->execute([$id]);
    }

    public static function deploy(VpnServer $server, array $options = []): array
    {
        $serverData = $server->getData();
        $protocolSlug = $serverData['install_protocol'] ?? null;
        if (!$protocolSlug || trim((string) $protocolSlug) === '') {
            throw new Exception('Install protocol not selected');
        }
        $protocol = self::getBySlug($protocolSlug);

        Logger::appendInstall($server->getId(), 'Deploy start for protocol ' . $protocolSlug);

        try {
            if (!$protocol) {
                throw new Exception('Install protocol not found: ' . $protocolSlug);
            }

            $installMode = $options['install_mode'] ?? null;
            $decisionToken = $options['decision_token'] ?? null;
            $serverId = $server->getId();
            $detectionPayload = null;

            if (empty($options['skip_connection_test'])) {
                if (!$server->testConnection()) {
                    Logger::appendInstall($serverId, 'SSH connection test failed');
                    throw new Exception('SSH connection failed');
                }
                Logger::appendInstall($serverId, 'SSH connection test OK');
            }

            if ($installMode !== null && $decisionToken) {
                $entry = self::consumeDecision($serverId, $decisionToken);
                if ($entry && ($entry['protocol'] ?? '') === $protocol['slug']) {
                    $detectionPayload = $entry['detection'] ?? null;
                    Logger::appendInstall($serverId, 'Consumed decision token for restore/reinstall');
                }
            }

            if ($installMode === null) {
                Logger::appendInstall($serverId, 'Running detection...');
                $detection = self::detect($server, $protocol, $options);
                Logger::appendInstall($serverId, 'Detection result: ' . json_encode($detection));

                if (in_array($detection['status'] ?? 'absent', ['existing', 'partial'], true)) {
                    $token = self::storeDecision($serverId, [
                        'protocol' => $protocol['slug'],
                        'detection' => $detection,
                        'stored_at' => time(),
                    ]);

                    Logger::appendInstall($serverId, 'Existing/partial config found, awaiting decision. token=' . $token);

                    return [
                        'success' => false,
                        'requires_action' => true,
                        'action' => 'existing_configuration',
                        'details' => $detection,
                        'decision_token' => $token,
                        'options' => [
                            'restore' => [
                                'mode' => 'restore',
                                'label' => 'Восстановить существующую конфигурацию'
                            ],
                            'reinstall' => [
                                'mode' => 'reinstall',
                                'label' => 'Переустановить заново'
                            ]
                        ]
                    ];
                }

                $installMode = 'install';
                Logger::appendInstall($serverId, 'Proceeding with clean install');
            }

            if ($installMode === 'restore') {
                Logger::appendInstall($serverId, 'Restoring existing configuration...');
                if ($detectionPayload === null) {
                    $detectionPayload = self::detect($server, $protocol, array_merge($options, ['force' => true]));
                    Logger::appendInstall($serverId, 'Forced detection for restore: ' . json_encode($detectionPayload));
                }

                if (!in_array($detectionPayload['status'] ?? '', ['existing', 'partial'], true)) {
                    throw new Exception('Существующая конфигурация на сервере не найдена');
                }

                $res = self::restore($server, $protocol, $detectionPayload, $options);
                Logger::appendInstall($serverId, 'Restore finished: ' . json_encode($res));
                self::installAwg2WatchdogIfNeeded($server, $protocol, [
                    'vpn_port' => $detectionPayload['details']['vpn_port'] ?? ($res['vpn_port'] ?? null),
                    'container_name' => $detectionPayload['details']['container_name'] ?? ($res['container_name'] ?? null),
                ]);
                return $res;
            }

            if ($installMode === 'reinstall') {
                $serverData = $server->getData();
                Logger::appendInstall($serverId, 'Reinstall mode selected');
                if (($serverData['status'] ?? '') === 'active' && empty($options['skip_backup'])) {
                    try {
                        $server->createBackup((int) $serverData['user_id'], 'automatic');
                        Logger::appendInstall($serverId, 'Automatic backup created before reinstall');
                    } catch (Throwable $e) {
                        Logger::appendInstall($serverId, 'Backup before reinstall failed: ' . $e->getMessage());
                        // backup errors do not abort reinstall
                    }
                }
            }

            return self::install($server, $protocol, $options);
        } catch (Throwable $e) {
            // Mark server error and log
            self::markServerError($server->getId(), $e->getMessage());
            Logger::appendInstall($server->getId(), 'Deploy failed: ' . $e->getMessage());
            throw $e;
        }
    }

    private static function detect(VpnServer $server, array $protocol, array $options = []): array
    {
        $handler = self::resolveHandler($protocol);

        switch ($handler) {
            case 'warp':
                return self::detectBuiltinWarp($server, $protocol);
            default:
                return self::runScript($server, $protocol, 'detect', $options);
        }
    }

    public static function install(VpnServer $server, array $protocol, array $options = []): array
    {
        $serverId = $server->getId();

        try {
            Logger::appendInstall($serverId, 'Running scripted install...');
            $metadata = $protocol['definition']['metadata'] ?? [];
            // Choose/ensure VPN UDP port for script-driven installs
            if (!isset($options['server_port']) || !is_int($options['server_port'])) {
                $options['server_port'] = self::chooseServerPort($server, $metadata);
            }
            $result = self::runScript($server, $protocol, 'install', $options);
            Logger::appendInstall($serverId, 'Scripted install finished: ' . json_encode($result));

            // A failed remote script must not mark the protocol as applied:
            // the output parser happily turns build logs into key-value pairs,
            // so check for an explicit error and for the keys the panel needs.
            if (!empty($result['error'])) {
                throw new Exception('Install script failed: ' . $result['error']);
            }
            if (($protocol['slug'] ?? '') === 'awg2' && empty($result['server_public_key'])) {
                throw new Exception('Install script did not return server_public_key — деплой не завершён');
            }
            if (!isset($result['success'])) {
                $result['success'] = true;
            }

            $rawPort = $result['vpn_port'] ?? null;
            $resolvedPort = (is_numeric($rawPort) && (int) $rawPort > 0)
                ? (int) $rawPort
                : ($options['server_port'] ?? null);

            $awgParams = $result['awg_params'] ?? null;
            if (!is_array($awgParams)) {
                $flat = [];
                foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $k) {
                    if (array_key_exists($k, $result) && $result[$k] !== '' && $result[$k] !== null) {
                        $flat[$k] = $result[$k];
                    }
                }
                if (!empty($flat)) {
                    $awgParams = $flat;
                }
            }

            $extras = [
                'vpn_port' => $resolvedPort,
                'server_public_key' => $result['server_public_key'] ?? null,
                'preshared_key' => $result['preshared_key'] ?? null,
                'awg_params' => $awgParams,
                'secret' => $result['secret'] ?? null,
                'server_host' => $result['server_host'] ?? null,
                'container_name' => $result['container_name'] ?? ($metadata['container_name'] ?? null),
            ];
            self::markServerActive($serverId, null, $extras);
            self::installAwg2WatchdogIfNeeded($server, $protocol, [
                'vpn_port' => $resolvedPort,
                'container_name' => $extras['container_name'] ?? null,
            ]);
            return $result;
        } catch (Throwable $e) {
            Logger::appendInstall($serverId, 'Scripted install failed: ' . $e->getMessage());
            self::markServerError($serverId, $e->getMessage());
            throw $e;
        }
    }

    private static function restore(VpnServer $server, array $protocol, array $detection, array $options = []): array
    {
        $handler = self::resolveHandler($protocol);

        switch ($handler) {
            default:
                $result = self::runScript($server, $protocol, 'restore', array_merge($options, [
                    'detection' => $detection
                ]));
                if (!isset($result['success'])) {
                    $result['success'] = true;
                }
                return $result;
        }
    }
    public static function addClient(VpnServer $server, array $protocol, array $options = []): array
    {
        return self::runScript($server, $protocol, 'add_client', $options);
    }

    private static function runScript(VpnServer $server, array $protocol, string $phase, array $options = []): array
    {
        $definition = $protocol['definition'] ?? [];
        $scripts = $definition['scripts'][$phase] ?? null;
        if (!$scripts) {
            if ($phase === 'install') {
                $scripts = $protocol['install_script'] ?? null;
            } elseif ($phase === 'uninstall') {
                $scripts = $protocol['uninstall_script'] ?? null;
            }
        }
        if (!$scripts) {
            if ($phase === 'detect') {
                return [
                    'status' => 'absent',
                    'message' => 'Скрипт обнаружения не настроен для протокола'
                ];
            }
            if ($phase === 'uninstall') {
                return [
                    'success' => true,
                    'message' => 'Скрипт удаления не настроен для протокола'
                ];
            }
            if ($phase === 'add_client') {
                // If no script and no builtin handler, we just skip it (assume not needed or manual)
                // Or throw generic error? Better return success to not break flow if not implemented for other protocols
                return ['success' => true, 'message' => 'No add_client script defined'];
            }
            throw new Exception('Скрипт ' . $phase . ' не настроен для протокола');
        }

        $context = self::buildContext($server, $protocol, $options);
        $script = self::renderTemplate($scripts, $context);
        $script = preg_replace('/\n\+\s*/', "\n", $script);
        $exportLines = self::buildExports($context);

        $metadata = $definition['metadata'] ?? [];
        $requiresDocker = !array_key_exists('requires_docker', $metadata) || filter_var($metadata['requires_docker'], FILTER_VALIDATE_BOOLEAN);

        if ($phase === 'install' && $requiresDocker) {
            Logger::appendInstall($server->getId(), 'INSTALL phase: docker preflight start');
            $bootstrapCmd = "bash -lc 'set -e; "
                . "if command -v docker >/dev/null 2>&1; then command -v docker; docker --version || true; exit 0; fi; "
                . "if command -v curl >/dev/null 2>&1; then curl -fsSL https://get.docker.com | sh; "
                . "elif command -v wget >/dev/null 2>&1; then wget -qO- https://get.docker.com | sh; "
                . "else echo \"curl/wget not found\"; exit 127; fi; "
                . "(systemctl enable --now docker || service docker start || true); "
                . "command -v docker >/dev/null 2>&1 || { echo \"docker bootstrap failed\"; exit 127; }; "
                . "command -v docker; docker --version || true'";
            $bootstrapOut = trim((string) $server->executeCommand($bootstrapCmd, true));
            if ($bootstrapOut !== '') {
                $bootstrapHead = substr(str_replace(["\r", "\n"], ' ', $bootstrapOut), 0, 280);
                Logger::appendInstall($server->getId(), 'INSTALL phase: docker preflight output ' . $bootstrapHead);
            }

            $dockerCheckAfter = trim((string) $server->executeCommand('command -v docker || true', true));
            if ($dockerCheckAfter === '') {
                throw new Exception('Docker не установлен на сервере и авто-установка не удалась');
            }
        } elseif ($phase === 'install') {
            Logger::appendInstall($server->getId(), 'INSTALL phase: docker preflight skipped');
        }

        $remoteScript = "set -eo pipefail\n" . $exportLines . $script . "\n";
        $remotePath = '/tmp/amnezia_protocol_' . preg_replace('/[^a-zA-Z0-9_-]+/', '_', (string) ($protocol['slug'] ?? 'script')) . '_' . $phase . '.sh';
        $server->uploadContent($remotePath, $remoteScript, 0700);
        $wrapper = sprintf(
            "bash %s; rc=\$?; rm -f %s; exit \$rc",
            escapeshellarg($remotePath),
            escapeshellarg($remotePath)
        );
        Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: executing remote script');
        $output = $server->executeCommand($wrapper, true);
        Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: output size ' . strlen((string) $output) . ' bytes');
        $head = substr(str_replace(["\r", "\n"], ' ', (string) $output), 0, 280);
        if ($head !== '') {
            Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: output head ' . $head);
        }
        $trimmed = trim($output);
        $installProbeSummary = '';

        if ($phase === 'install' && $trimmed === '') {
            $probeCmd = "echo whoami:\$(whoami) 2>/dev/null || true; echo shell:\$SHELL; command -v docker || echo docker:not-found; docker --version 2>&1 || true; id 2>&1 || true";
            $probeOut = trim((string) $server->executeCommand($probeCmd, true));
            if ($probeOut !== '') {
                $normalizedProbe = substr(str_replace(["\r", "\n"], ' | ', $probeOut), 0, 320);
                Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: probe ' . $normalizedProbe);
                $installProbeSummary = '; probe: ' . $normalizedProbe;
            }
        }

        // Try JSON first
        $decoded = json_decode($trimmed, true);
        if (is_array($decoded)) {
            Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: parsed JSON result');
            return $decoded;
        }

        if ($phase === 'install') {
            $lower = strtolower($trimmed);
            $hardErrors = [
                'connection refused',
                'permission denied',
                'command not found',
                'no route to host',
                'could not resolve hostname',
                'host key verification failed',
                'timed out',
                'operation timed out',
                'requires at least 1 argument',
                'usage: docker',
                'no such container',
            ];
            foreach ($hardErrors as $needle) {
                if ($needle !== '' && strpos($lower, $needle) !== false) {
                    throw new Exception('Ошибка установки (script): ' . $trimmed);
                }
            }
        }

        // Try key-value format (e.g., "Port: 123" or "Server Public Key: abc")
        $result = self::parseKeyValueOutput($trimmed);
        if (!empty($result)) {
            Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: parsed key-value result with ' . count($result) . ' keys');
            return array_merge(['success' => true], $result);
        }

        // Heuristic: treat obvious errors on install as failure to avoid false "active" status
        if ($phase === 'install') {
            $lower = strtolower($trimmed);
            if ($lower === '' || strpos($lower, 'command not found') !== false || strpos($lower, 'error') !== false) {
                throw new Exception('Ошибка установки (script): ' . ($trimmed !== '' ? $trimmed : 'empty output') . $installProbeSummary);
            }
        }

        return [
            'success' => true,
            'output' => $output
        ];
    }

    /**
     * Parse key-value output from installation scripts
     * Supports formats like:
     * - "Port: 123"
     * - "Server Public Key: abc123"
     * - "PresharedKey = xyz789"
     */
    private static function parseKeyValueOutput(string $output): array
    {
        $result = [];
        $lines = preg_split('/\r?\n/', $output);

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '')
                continue;
            $line = preg_replace('/^\+\s*/', '', $line);

            // Match "Variable: name=value" format (for protocol variables)
            if (preg_match('/^Variable:\s*(\w+)=(.*)$/', $line, $matches)) {
                $varName = trim($matches[1]);
                $varValue = trim($matches[2]);
                $result[$varName] = $varValue;
                continue;
            }

            // Match "Key: Value" or "Key = Value" format
            if (preg_match('/^([^:=]+?)[:=]\s*(.+)$/', $line, $matches)) {
                $key = trim($matches[1]);
                $value = trim($matches[2]);

                // Normalize key names to snake_case
                $normalizedKey = strtolower(preg_replace('/\s+/', '_', $key));

                // Map common key names
                $keyMap = [
                    'port' => 'vpn_port',
                    'server_public_key' => 'server_public_key',
                    'presharedkey' => 'preshared_key',
                    'preshared_key' => 'preshared_key',
                    'awg_params' => 'awg_params',
                    'clientid' => 'client_id',
                    'client_id' => 'client_id',
                    'server_port' => 'server_port',
                    'container_name' => 'container_name',
                    'containername' => 'container_name',
                    'publickey' => 'reality_public_key',
                    'privatekey' => 'reality_private_key',
                    'shortid' => 'reality_short_id',
                    'servername' => 'reality_server_name',
                    'secret' => 'secret',
                    'serverhost' => 'server_host',
                    'server_host' => 'server_host',
                ];

                $finalKey = $keyMap[$normalizedKey] ?? $normalizedKey;
                $result[$finalKey] = $value;
            }
        }

        return $result;
    }

    private static function markServerActive(int $serverId, ?string $message = null, array $extras = []): void
    {
        $pdo = DB::conn();
        $setParts = ['status = ?', 'error_message = NULL', 'deployed_at = COALESCE(deployed_at, NOW())'];
        $params = ['active'];
        if (isset($extras['vpn_port']) && $extras['vpn_port'] !== null) {
            $setParts[] = 'vpn_port = ?';
            $params[] = (int) $extras['vpn_port'];
        }
        if (isset($extras['server_public_key']) && $extras['server_public_key'] !== null) {
            $setParts[] = 'server_public_key = ?';
            $params[] = (string) $extras['server_public_key'];
        }
        if (isset($extras['preshared_key']) && $extras['preshared_key'] !== null) {
            $setParts[] = 'preshared_key = ?';
            $params[] = (string) $extras['preshared_key'];
        }
        if (isset($extras['container_name']) && $extras['container_name'] !== null && $extras['container_name'] !== '') {
            $setParts[] = 'container_name = ?';
            $params[] = (string) $extras['container_name'];
        }
        if (array_key_exists('awg_params', $extras)) {
            $awgParams = $extras['awg_params'];
            if (is_array($awgParams)) {
                $awgParams = json_encode($awgParams);
            }
            if (is_string($awgParams)) {
                $setParts[] = 'awg_params = ?';
                $params[] = $awgParams;
            }
        }
        $params[] = $serverId;
        $sql = 'UPDATE vpn_servers SET ' . implode(', ', $setParts) . ' WHERE id = ?';
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        try {
            $stmt2 = $pdo->prepare('SELECT install_protocol, host, vpn_port FROM vpn_servers WHERE id = ?');
            $stmt2->execute([$serverId]);
            $row = $stmt2->fetch();
            $slug = $row['install_protocol'] ?? null;
            if ($slug) {
                $stmt3 = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
                $stmt3->execute([$slug]);
                $protocolId = $stmt3->fetchColumn();
                if ($protocolId) {
                    $config = [
                        'server_host' => $row['host'] ?? null,
                        'server_port' => $row['vpn_port'] ?? null,
                        'extras' => $extras
                    ];
                    $stmt4 = $pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()');
                    $stmt4->execute([$serverId, (int) $protocolId, json_encode($config)]);
                }
            }
        } catch (Throwable $e) {
            // ignore linkage errors
        }
    }

    private static function markServerError(int $serverId, string $message): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = ? WHERE id = ?');
        $stmt->execute(['error', $message, $serverId]);
    }

    private static function buildContext(VpnServer $server, array $protocol, array $options): array
    {
        return [
            'server' => $server->getData(),
            'protocol' => $protocol,
            'metadata' => $protocol['definition']['metadata'] ?? [],
            'options' => $options
        ];
    }

    private static function buildExports(array $context): string
    {
        $exports = [];
        $serverData = $context['server'] ?? [];
        $metadata = $context['metadata'] ?? [];
        $options = $context['options'] ?? [];

        $pairs = [
            'SERVER_HOST' => $serverData['host'] ?? '',
            'SERVER_USER' => $serverData['username'] ?? '',
            // Prefer protocol-specific settings for scripted installs to avoid
            // reusing a container name/port from another protocol on same server.
            'SERVER_CONTAINER' => $options['container_name']
                ?? ($metadata['container_name'] ?? ($serverData['container_name'] ?? '')),
            'SERVER_PORT' => isset($options['server_port']) && (int) $options['server_port'] > 0
                ? (int) $options['server_port']
                : (isset($serverData['vpn_port']) && (int) $serverData['vpn_port'] > 0
                    ? (int) $serverData['vpn_port']
                    : ''),
        ];

        // Check for saved Reality keys in server_protocols table
        $serverId = $serverData['id'] ?? null;
        if ($serverId) {
            try {
                $pdo = DB::conn();
                $stmt = $pdo->prepare('SELECT config_data FROM server_protocols WHERE server_id = ? ORDER BY applied_at DESC LIMIT 1');
                $stmt->execute([$serverId]);
                $configJson = $stmt->fetchColumn();
                if ($configJson) {
                    $config = json_decode($configJson, true);
                    $extras = $config['extras'] ?? [];
                    // Export saved Reality keys if reinstalling (allow script to reuse them)
                    if (!empty($extras['reality_private_key'])) {
                        $pairs['PRIVATE_KEY'] = $extras['reality_private_key'];
                    }
                    if (!empty($extras['reality_short_id'])) {
                        $pairs['SHORT_ID'] = $extras['reality_short_id'];
                    }
                    // Note: CLIENT_ID is per-client, not per-server, so we don't restore it here
                }
            } catch (Throwable $e) {
                // Ignore errors, will generate new keys
            }
        }

        foreach ($pairs as $key => $value) {
            if ($value !== '' && $value !== null) {
                $exports[] = sprintf('export %s=%s', $key, escapeshellarg((string) $value));
            }
        }

        foreach ($metadata as $key => $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $normalized = strtoupper(preg_replace('/[^A-Z0-9]+/i', '_', (string) $key));
            if ($normalized === '') {
                continue;
            }
            $exports[] = sprintf('export PROTOCOL_%s=%s', $normalized, escapeshellarg((string) $value));
        }

        return $exports ? implode("\n", $exports) . "\n" : '';
    }

    /**
     * Choose the VPN UDP port. Prefers the metadata default_port (443 unless
     * overridden — clients connect to domain:443 and UDP/443 blends in with
     * QUIC); falls back to a random free port in the metadata-defined range.
     */
    private static function chooseServerPort(VpnServer $server, array $metadata): int
    {
        $preferred = (int) ($metadata['default_port'] ?? 443);
        if ($preferred > 0 && self::isUdpPortFree($server, $preferred)) {
            return $preferred;
        }

        $range = $metadata['port_range'] ?? [30000, 65000];
        $min = 30000;
        $max = 65000;
        if (is_string($range)) {
            // Accept formats like "[30000, 65000]" or "30000-65000"
            if (preg_match('/(\d{2,})\D+(\d{2,})/', $range, $m)) {
                $min = (int) $m[1];
                $max = (int) $m[2];
            }
        } elseif (is_array($range) && count($range) >= 2) {
            $min = (int) $range[0];
            $max = (int) $range[1];
        }

        for ($attempt = 0; $attempt < 30; $attempt++) {
            $candidate = random_int($min, $max);
            if (self::isUdpPortFree($server, $candidate)) {
                return $candidate;
            }
        }

        return 40001; // fallback
    }

    private static function isUdpPortFree(VpnServer $server, int $port): bool
    {
        $cmd = "ss -lun | awk '{print $4}' | grep -E ':(" . $port . ")($| )' || true";
        return trim($server->executeCommand($cmd, false)) === '';
    }

    private static function renderTemplate(string $template, array $context): string
    {
        return preg_replace_callback('/{{\s*([a-zA-Z0-9_.]+)\s*}}/', function ($matches) use ($context) {
            $path = explode('.', $matches[1]);
            $value = $context;
            foreach ($path as $segment) {
                if (is_array($value) && array_key_exists($segment, $value)) {
                    $value = $value[$segment];
                } else {
                    return '';
                }
            }
            return is_scalar($value) ? (string) $value : json_encode($value);
        }, $template);
    }

    private static function parseWireGuardConfig(string $config): array
    {
        $lines = preg_split('/\r?\n/', $config);
        $awgKeys = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'];
        $awgParams = [];
        $listenPort = null;

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, '=') === false) {
                continue;
            }
            [$key, $value] = array_map('trim', explode('=', $line, 2));
            if ($key === 'ListenPort') {
                $listenPort = (int) $value;
            }
            if (in_array($key, $awgKeys, true)) {
                $awgParams[$key] = is_numeric($value) ? (int) $value : $value;
            }
        }

        return [
            'listen_port' => $listenPort,
            'awg_params' => $awgParams
        ];
    }

    private static function hydrateProtocol(array $row): array
    {
        if (isset($row['definition']) && is_string($row['definition'])) {
            $decoded = json_decode($row['definition'], true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                $row['definition'] = $decoded;
            } else {
                $row['definition'] = [];
            }
        }
        return $row;
    }

    /**
     * ──────────────────────────────────────────────────────────────────
     * PROTOCOL HANDLER REGISTRY
     * ──────────────────────────────────────────────────────────────────
     * Central dispatcher that determines which builtin handler manages
     * a given protocol. Every dispatch point (detect, install, uninstall)
     * MUST use this method instead of ad-hoc slug/regex checks.
     *
     * Returns one of:
     *   'awg'    – AmneziaWG / AWG variants (Docker container based)
     *   'warp'   – Cloudflare WARP (systemd service, host-level)
     *   'script' – Generic script-driven protocol (install/uninstall via shell)
     *
     * Priority order:
     *   1. Explicit slug match (highest priority, cannot be overridden)
     *   2. Engine field from protocol definition
     *   3. Heuristic: install_script content analysis (lowest priority)
     */
    private static function resolveHandler(array $protocol): string
    {
        $slug = $protocol['slug'] ?? '';

        if ($slug === 'awg2') {
            return 'script';
        }

        // Explicit slug → handler mapping. Only Cloudflare WARP needs a builtin
        // handler; everything else (including awg2) is script-driven.
        static $slugMap = [
            'cf-warp'         => 'warp',
            'cloudflare-warp' => 'warp',
        ];

        return $slugMap[$slug] ?? 'script';
    }
    private static function storeDecision(int $serverId, array $payload): string
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return '';
        }
        $token = bin2hex(random_bytes(16));
        if (!isset($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = [];
        }
        $_SESSION[self::SESSION_KEY][$serverId] = [
            'token' => $token,
            'payload' => $payload,
            'expires_at' => time() + 600
        ];
        return $token;
    }

    private static function consumeDecision(int $serverId, string $token): ?array
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return null;
        }

        if (!isset($_SESSION[self::SESSION_KEY][$serverId])) {
            return null;
        }

        $entry = $_SESSION[self::SESSION_KEY][$serverId];
        if (($entry['token'] ?? '') !== $token) {
            return null;
        }

        unset($_SESSION[self::SESSION_KEY][$serverId]);

        if (($entry['expires_at'] ?? 0) < time()) {
            return null;
        }

        return $entry['payload'] ?? null;
    }

    /**
     * Run detection script for a scenario on a server
     * Used for testing scenarios before deployment
     */
    public static function runDetection(VpnServer $server, array $protocol, array $options = []): array
    {
        $handler = self::resolveHandler($protocol);

        switch ($handler) {
            case 'warp':
                return self::detectBuiltinWarp($server, $protocol);
            default:
                return self::runScript($server, $protocol, 'detect', $options);
        }
    }

    /**
     * Uninstall a protocol from the given server. Supports builtin AWG and scripted protocols
     * Returns array with success and message keys on completion or throws on fatal error
     */
    public static function uninstall(VpnServer $server, array $protocol, array $options = []): array
    {
        $slug = $protocol['slug'] ?? 'unknown';
        $handler = self::resolveHandler($protocol);
        Logger::appendInstall($server->getId(), 'UNINSTALL: slug=' . $slug . ' handler=' . $handler);

        switch ($handler) {
            case 'warp':
                return self::uninstallBuiltinWarp($server, $protocol, $options);

            case 'script':
            default:
                return self::runScript($server, $protocol, 'uninstall', $options);
        }
    }
    public static function activate(VpnServer $server, array $protocol, array $options = []): array
    {
        $serverId = $server->getId();
        try {
            Logger::appendInstall($serverId, 'Activate start for ' . ($protocol['slug'] ?? 'unknown'));

            // ── Check for existing installation before doing anything destructive ──
            $slug = $protocol['slug'] ?? '';

            // For Cloudflare WARP — always run install script even if WARP binary exists
            // because the script is idempotent and handles redsocks/iptables setup
            if (self::resolveHandler($protocol) === 'warp') {
                $warpDetection = self::detectBuiltinWarp($server, $protocol);
                Logger::appendInstall($serverId, 'WARP detect result: status=' . ($warpDetection['status'] ?? 'null'));
                if (($warpDetection['status'] ?? '') === 'existing') {
                    Logger::appendInstall($serverId, 'Existing WARP found, running install script anyway for redsocks/iptables setup');
                    // Don't return — fall through to run the install script
                }
            }

            // ── No existing installation found — proceed with fresh install ──

            if (!isset($options['server_port']) || !is_int($options['server_port'])) {
                $options['server_port'] = self::chooseServerPort($server, $protocol['definition']['metadata'] ?? []);
            }
            $res = self::runScript($server, $protocol, 'install', $options);
            if (!isset($res['success'])) {
                $res['success'] = true;
            }
            $port = null;
            $password = null;
            $clientId = null;
            if (isset($res['vpn_port'])) {
                $port = (int) $res['vpn_port'];
            }
            if (isset($res['server_port'])) {
                $port = (int) $res['server_port'];
            }
            if (isset($res['client_id']) && is_string($res['client_id'])) {
                $clientId = $res['client_id'];
            }
            if (is_string($res['output'] ?? '')) {
                $out = $res['output'];
                if (preg_match('/Port:\s*(\d+)/i', $out, $m)) {
                    $port = (int) $m[1];
                }
                if (preg_match('/Password:\s*([\w-]+)/i', $out, $m)) {
                    $password = $m[1];
                }
                if (preg_match('/ClientID:\s*([0-9a-fA-F-]+)/i', $out, $m)) {
                    $clientId = $m[1];
                }
            }
            Logger::appendInstall($serverId, 'Scripted install parsed port ' . ($port ?? 0) . ' password ' . ($password ?? ''));
            $pdo = DB::conn();
            $pid = self::resolveProtocolId($protocol);
            if ($pid) {
                $config = [
                    'server_host' => $server->getData()['host'] ?? null,
                    'server_port' => $port,
                    'extras' => [
                        'password' => $password,
                        'client_id' => $clientId,
                        'result' => $res,
                        'reality_public_key' => $res['reality_public_key'] ?? null,
                        'reality_private_key' => $res['reality_private_key'] ?? null,
                        'reality_short_id' => $res['reality_short_id'] ?? null,
                        'reality_server_name' => $res['reality_server_name'] ?? null,
                    ]
                ];
                $stmt2 = $pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()');
                $stmt2->execute([$serverId, $pid, json_encode($config)]);
            }
            // Save vpn_port to vpn_servers table ONLY for the primary (first) protocol
            // Secondary protocols store their ports in server_protocols.config_data only
            if ($port !== null && $port > 0) {
                $existingProtocol = $server->getData()['install_protocol'] ?? '';
                $currentSlug = $protocol['slug'] ?? '';
                $isFirstProtocol = ($existingProtocol === '' || $existingProtocol === $currentSlug);

                $activeExtras = [
                    'vpn_port' => $port,
                ];

                // Scripted WireGuard/AWG protocols, especially awg2, return keys from install_script.
                // Persist them into vpn_servers too, because VpnClient::create() uses serverData.
                if (!empty($res['server_public_key'])) {
                    $activeExtras['server_public_key'] = $res['server_public_key'];
                }

                if (!empty($res['preshared_key'])) {
                    $activeExtras['preshared_key'] = $res['preshared_key'];
                }

                if (!empty($res['container_name'])) {
                    $activeExtras['container_name'] = $res['container_name'];
                } elseif (($protocol['slug'] ?? '') === 'awg2') {
                    $activeExtras['container_name'] = 'amnezia-awg2';
                }

                $awgParams = [];
                foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $k) {
                    if (array_key_exists($k, $res) && $res[$k] !== null && $res[$k] !== '') {
                        $awgParams[$k] = $res[$k];
                    }
                }

                if (!empty($awgParams)) {
                    $activeExtras['awg_params'] = $awgParams;
                }

                if ($isFirstProtocol) {
                    self::markServerActive($serverId, null, $activeExtras);
                } else {
                    self::markServerActive($serverId, null, []);
                }
            }

            self::installAwg2WatchdogIfNeeded($server, $protocol, [
                'vpn_port' => $port,
                'container_name' => $res['container_name'] ?? null,
            ]);

            return $res;
        } catch (Throwable $e) {
            $message = (string) $e->getMessage();
            if (
                stripos($message, 'server_protocols_ibfk_1') !== false
                || (stripos($message, 'foreign key constraint fails') !== false && stripos($message, 'server_protocols') !== false)
            ) {
                $message = 'Сервер был удален или пересоздан во время установки. Обновите страницу и запустите установку заново.';
            }

            self::markServerError($serverId, $message);
            Logger::appendInstall($serverId, 'Activate failed: ' . $message);
            throw new Exception($message, 0, $e);
        }
    }

    /**
     * Resolve protocol ID from protocol array, looking up by slug if needed
     */
    private static function resolveProtocolId(array $protocol): int
    {
        $pid = (int) ($protocol['id'] ?? 0);
        if (!$pid) {
            $slug = $protocol['slug'] ?? '';
            if ($slug === '') {
                return 0;
            }
            try {
                $pdo = DB::conn();
                $stmt = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
                $stmt->execute([$slug]);
                $pid = (int) $stmt->fetchColumn();
            } catch (Throwable $e) {
                return 0;
            }
        }
        return $pid;
    }

    // ─────────────────────────────────────────────────────────────────
    // Cloudflare WARP — builtin detection, uninstall, status
    // WARP runs as a systemd service (warp-svc), NOT as a Docker container
    // ─────────────────────────────────────────────────────────────────

    /**
     * Detect existing Cloudflare WARP installation on the server
     */
    private static function detectBuiltinWarp(VpnServer $server, array $protocol): array
    {
        $metadata = $protocol['definition']['metadata'] ?? [];
        $proxyPort = $metadata['proxy_port'] ?? 40000;

        $egressUnit = trim($server->executeCommand('systemctl is-enabled awg2-warp-egress.service 2>/dev/null || echo ""', true));
        $egressNs = trim($server->executeCommand('ip netns list 2>/dev/null | grep -w awg2warp || echo ""', true));
        if ($egressUnit !== '' || $egressNs !== '') {
            $egressStatus = trim($server->executeCommand('systemctl is-active awg2-warp-egress.service 2>/dev/null || echo "inactive"', true));
            $traceOut = trim($server->executeCommand(
                'ip netns exec awg2warp curl -4 -s --max-time 5 --resolve cloudflare.com:443:104.16.132.229 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo ""',
                true
            ));
            $warpIp = '';
            $warpOn = false;
            if (preg_match('/ip=([^\s]+)/', $traceOut, $m)) {
                $warpIp = $m[1];
            }
            if (preg_match('/warp=on/i', $traceOut)) {
                $warpOn = true;
            }

            return [
                'status' => 'existing',
                'message' => 'Cloudflare WARP egress установлен' . ($warpOn ? ' и подключён' : ''),
                'details' => [
                    'service_status' => $egressStatus,
                    'connected' => $warpOn,
                    'registered' => true,
                    'warp_mode' => 'wireguard_netns',
                    'warp_proxy_port' => null,
                    'warp_ip' => $warpIp,
                    'port_listening' => false,
                    'summary' => sprintf(
                        'WARP client egress %s, mode=wireguard_netns%s',
                        $warpOn ? 'connected' : 'installed',
                        $warpIp !== '' ? ', exit_ip=' . $warpIp : ''
                    )
                ]
            ];
        }

        // Check if warp-cli binary exists
        $warpCliCheck = trim($server->executeCommand('command -v warp-cli 2>/dev/null || echo ""', true));
        if ($warpCliCheck === '') {
            return [
                'status' => 'absent',
                'message' => 'Cloudflare WARP не установлен на сервере'
            ];
        }

        // Check warp-svc service status
        $svcStatus = trim($server->executeCommand('systemctl is-active warp-svc 2>/dev/null || echo "inactive"', true));

        // Get WARP connection status
        $warpStatus = trim($server->executeCommand('warp-cli --accept-tos status 2>/dev/null || echo "error"', true));

        $isConnected = (bool) preg_match('/Connected/i', $warpStatus);
        $isRegistered = !preg_match('/Registration Missing|unregistered/i', $warpStatus);

        if (!$isRegistered) {
            return [
                'status' => 'partial',
                'message' => 'WARP установлен, но не зарегистрирован',
                'details' => [
                    'warp_cli' => $warpCliCheck,
                    'service_status' => $svcStatus,
                    'warp_status' => $warpStatus,
                ]
            ];
        }

        // Get WARP mode
        $warpMode = '';
        if (preg_match('/Mode:\s*(\S+)/i', $warpStatus, $m)) {
            $warpMode = $m[1];
        }

        // Get WARP account info
        $accountInfo = trim($server->executeCommand('warp-cli --accept-tos registration show 2>/dev/null || echo ""', true));
        $accountId = '';
        if (preg_match('/Account\s*ID[:\s]+([a-zA-Z0-9-]+)/i', $accountInfo, $m)) {
            $accountId = $m[1];
        }

        // Check if proxy port is listening
        $portListening = trim($server->executeCommand(
            'ss -tlnp 2>/dev/null | grep ":' . (int) $proxyPort . '" | head -1 || echo ""', true
        ));

        // Get WARP IP (best-effort)
        $warpIp = '';
        if ($isConnected && $portListening !== '') {
            $traceOut = trim($server->executeCommand(
                'curl -x socks5h://127.0.0.1:' . (int) $proxyPort . ' -s --max-time 5 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo ""', true
            ));
            if (preg_match('/ip=([^\s]+)/', $traceOut, $m)) {
                $warpIp = $m[1];
            }
        }

        return [
            'status' => 'existing',
            'message' => 'Cloudflare WARP установлен и ' . ($isConnected ? 'подключён' : 'отключён'),
            'details' => [
                'warp_cli' => $warpCliCheck,
                'service_status' => $svcStatus,
                'warp_status_raw' => $warpStatus,
                'connected' => $isConnected,
                'registered' => $isRegistered,
                'warp_mode' => $warpMode,
                'warp_proxy_port' => (int) $proxyPort,
                'warp_ip' => $warpIp,
                'warp_account' => $accountId,
                'port_listening' => $portListening !== '',
                'summary' => sprintf(
                    'WARP %s, mode=%s, proxy=%s:%d%s',
                    $isConnected ? 'connected' : 'disconnected',
                    $warpMode ?: 'unknown',
                    '127.0.0.1',
                    (int) $proxyPort,
                    $warpIp !== '' ? ', exit_ip=' . $warpIp : ''
                )
            ]
        ];
    }

    /**
     * Uninstall Cloudflare WARP from the server (systemd service, not Docker)
     */
    private static function uninstallBuiltinWarp(VpnServer $server, array $protocol, array $options = []): array
    {
        $serverId = $server->getId();
        Logger::appendInstall($serverId, 'Uninstalling Cloudflare WARP (full cleanup)...');

        try {
            // Run entire uninstall as a single remote script to avoid SSH escaping issues
            $script = <<<'BASH'
#!/bin/bash
echo "WARP_UNINSTALL_START"

# 1. Restore X-Ray config
XRAY_NAME=$(docker ps 2>/dev/null | grep -i xray | awk '{ print $NF }' | head -1)
if [ -n "$XRAY_NAME" ]; then
  # Try server.json first (actual runtime config), then config.json
  XRAY_CFG_PATH=""
  for P in /opt/amnezia/xray/server.json /etc/xray/config.json; do
    CONTENT=$(docker exec "$XRAY_NAME" cat "$P" 2>/dev/null || echo "")
    if [ -n "$CONTENT" ] && echo "$CONTENT" | grep -q "warp-out"; then
      XRAY_CFG_PATH="$P"
      XRAY_CFG="$CONTENT"
      break
    fi
  done
  if [ -n "$XRAY_CFG_PATH" ]; then
    echo "$XRAY_CFG" | python3 -c "
import sys, json
try:
    cfg = json.load(sys.stdin)
    cfg['outbounds'] = [o for o in cfg.get('outbounds',[]) if o.get('tag') != 'warp-out']
    if 'routing' in cfg:
        cfg['routing']['rules'] = [r for r in cfg['routing'].get('rules',[]) if r.get('outboundTag') != 'warp-out']
        if not cfg['routing']['rules']: del cfg['routing']
    print(json.dumps(cfg, indent=2))
except: pass
" 2>/dev/null | docker exec -i "$XRAY_NAME" tee "$XRAY_CFG_PATH" > /dev/null 2>&1
    docker restart "$XRAY_NAME" 2>/dev/null || true
    echo "xray_restored"
  fi
fi

# 2. Remove DNAT rules
DOCKER_GW=$(docker network inspect bridge 2>/dev/null | grep Gateway | head -1 | awk -F'"' '{print $4}')
if [ -z "$DOCKER_GW" ]; then DOCKER_GW="172.17.0.1"; fi
iptables -t nat -D OUTPUT -d "$DOCKER_GW" -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true
iptables -t nat -D PREROUTING -d "$DOCKER_GW" -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true
iptables -t nat -D PREROUTING -d "$DOCKER_GW" -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true
echo "dnat_removed"

# 3. Remove AWG2 WARP netns egress and legacy REDSOCKS chains
systemctl stop awg2-warp-egress.service 2>/dev/null || true
systemctl disable awg2-warp-egress.service 2>/dev/null || true

STATE_DIR_AWG2="/var/lib/cloudflare-warp/awg2-egress"
NS_AWG2="awg2warp"
VETH_AWG2="awg2warp0"
VETH_CIDR_AWG2="10.255.0.0/30"
TABLE_AWG2="51888"
MARK_AWG2="0x2cf2"
CHAIN_AWG2="AWG2_WARP_EGRESS"
OLD_CHAIN_AWG2="AWG2_WARP_TCP"

AWG2_IPS=$(cat "$STATE_DIR_AWG2/container_ips" 2>/dev/null || docker exec amnezia-awg2 hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' || true)
for IP in $AWG2_IPS; do
  while iptables -t mangle -D PREROUTING -s "$IP/32" -j "$CHAIN_AWG2" 2>/dev/null; do :; done
  while iptables -t nat -D PREROUTING -s "$IP/32" -p tcp -j "$OLD_CHAIN_AWG2" 2>/dev/null; do :; done
done

iptables -t mangle -F "$CHAIN_AWG2" 2>/dev/null || true
iptables -t mangle -X "$CHAIN_AWG2" 2>/dev/null || true
iptables -t nat -F "$OLD_CHAIN_AWG2" 2>/dev/null || true
iptables -t nat -X "$OLD_CHAIN_AWG2" 2>/dev/null || true
while iptables -D FORWARD -i "$VETH_AWG2" -o eth0 -j ACCEPT 2>/dev/null; do :; done
while iptables -D FORWARD -i eth0 -o "$VETH_AWG2" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s "$VETH_CIDR_AWG2" -o eth0 -j MASQUERADE 2>/dev/null; do :; done

while ip rule del fwmark "$MARK_AWG2" table "$TABLE_AWG2" 2>/dev/null; do :; done
ip route flush table "$TABLE_AWG2" 2>/dev/null || true
ip link del "$VETH_AWG2" 2>/dev/null || true
ip netns del "$NS_AWG2" 2>/dev/null || true
rm -f /etc/systemd/system/awg2-warp-egress.service
rm -f /usr/local/sbin/awg2-warp-egress
rm -f /etc/wireguard/awg2-warp-egress.conf
rm -rf "$STATE_DIR_AWG2"
echo "awg2_warp_netns_removed"

# 4. Remove REDSOCKS_WARP chain
SUBNETS=$(cat /var/lib/cloudflare-warp/routed_subnets 2>/dev/null || echo "10.8.1.0/24 10.0.0.0/24")
for S in $SUBNETS; do
  iptables -t nat -D PREROUTING -s "$S" -p tcp -j REDSOCKS_WARP 2>/dev/null || true
done
iptables -t nat -F REDSOCKS_WARP 2>/dev/null || true
iptables -t nat -X REDSOCKS_WARP 2>/dev/null || true
echo "iptables_cleaned"

# 5. Remove redsocks
systemctl stop redsocks-warp 2>/dev/null || true
systemctl disable redsocks-warp 2>/dev/null || true
rm -f /etc/systemd/system/redsocks-warp.service
rm -rf /etc/redsocks
systemctl daemon-reload 2>/dev/null || true
echo "redsocks_removed"

# 6. Disconnect and remove WARP
warp-cli --accept-tos disconnect 2>/dev/null || true
warp-cli --accept-tos registration delete 2>/dev/null || true
systemctl stop warp-svc 2>/dev/null || true
systemctl disable warp-svc 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get remove -y cloudflare-warp >/dev/null 2>&1 || true
apt-get autoremove -y >/dev/null 2>&1 || true
echo "warp_removed"

# 7. Cleanup
rm -rf /var/lib/cloudflare-warp 2>/dev/null || true
rm -f /etc/apt/sources.list.d/cloudflare-client.list 2>/dev/null || true
rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null || true
rm -f /etc/sysctl.d/99-warp.conf 2>/dev/null || true
sysctl -w net.ipv4.conf.docker0.route_localnet=0 2>/dev/null || true
sysctl -w net.ipv4.conf.all.route_localnet=0 2>/dev/null || true

# 8. Save iptables
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

echo "WARP_UNINSTALL_DONE"
BASH;

            Logger::appendInstall($serverId, 'WARP uninstall: writing script to server...');
            $b64 = base64_encode($script);
            // Phase 1: write script file
            $server->executeCommand("echo " . $b64 . " | base64 -d > /tmp/_warp_uninstall.sh && chmod +x /tmp/_warp_uninstall.sh", true);
            Logger::appendInstall($serverId, 'WARP uninstall: executing script...');
            // Phase 2: execute script
            $output = $server->executeCommand("bash /tmp/_warp_uninstall.sh 2>&1; rm -f /tmp/_warp_uninstall.sh", true);
            $outputStr = (string) $output;
            Logger::appendInstall($serverId, 'WARP uninstall output: ' . substr(str_replace(["\r", "\n"], ' ', $outputStr), 0, 500));

            $success = strpos($outputStr, 'WARP_UNINSTALL_DONE') !== false;

            if ($success) {
                Logger::appendInstall($serverId, 'WARP uninstalled successfully (full cleanup)');
            } else {
                Logger::appendInstall($serverId, 'WARP uninstall script may have partially failed');
            }

            return [
                'success' => $success,
                'message' => $success ? 'Cloudflare WARP удалён' : 'WARP удалён частично, проверьте логи',
                'mode' => 'uninstall'
            ];
        } catch (Throwable $e) {
            Logger::appendInstall($serverId, 'WARP uninstall exception: ' . $e->getMessage());
            throw new Exception('WARP uninstall failed: ' . $e->getMessage());
        }
    }

    /**
     * Get WARP runtime status from a server (used by API endpoint)
     * Returns connection status, proxy port, exit IP, and account info
     */
    public static function getWarpStatus(VpnServer $server, bool $useCache = true): array
    {
        $cacheFile = sys_get_temp_dir() . '/amnezia_warp_status_' . $server->getId() . '.json';
        if ($useCache && is_file($cacheFile) && (time() - filemtime($cacheFile)) < 60) {
            $cached = json_decode((string) file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                $cached['cached'] = true;
                return $cached;
            }
        }

        $script = <<<'SH'
set +e
b64() { base64 -w0 2>/dev/null || base64; }
egress_unit="$(systemctl is-enabled awg2-warp-egress.service 2>/dev/null || true)"
egress_ns="$(ip netns list 2>/dev/null | grep -w awg2warp || true)"
if [ -n "$egress_unit" ] || [ -n "$egress_ns" ]; then
  svc_status="$(systemctl is-active awg2-warp-egress.service 2>/dev/null || echo inactive)"
  trace_out="$(ip netns exec awg2warp curl -4 -s --max-time 3 --resolve cloudflare.com:443:104.16.132.229 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
  printf 'mode_type=netns\n'
  printf 'service_status=%s\n' "$svc_status"
  printf 'trace_b64=%s\n' "$(printf '%s' "$trace_out" | b64)"
  exit 0
fi

warp_cli="$(command -v warp-cli 2>/dev/null || true)"
if [ -z "$warp_cli" ]; then
  printf 'mode_type=missing\n'
  exit 0
fi

svc_status="$(systemctl is-active warp-svc 2>/dev/null || echo inactive)"
warp_status="$(warp-cli --accept-tos status 2>/dev/null || echo error)"
proxy_port="$(warp-cli --accept-tos settings 2>/dev/null | grep -i 'proxy port' | grep -oE '[0-9]+' | head -1)"
[ -n "$proxy_port" ] || proxy_port=40000
port_check="$(ss -tlnp 2>/dev/null | grep ":${proxy_port}" | head -1 || true)"
trace_out=""
if printf '%s' "$warp_status" | grep -qi Connected && [ -n "$port_check" ]; then
  trace_out="$(curl -x "socks5h://127.0.0.1:${proxy_port}" -s --max-time 3 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
fi
printf 'mode_type=warp_cli\n'
printf 'service_status=%s\n' "$svc_status"
printf 'warp_status_b64=%s\n' "$(printf '%s' "$warp_status" | b64)"
printf 'proxy_port=%s\n' "$proxy_port"
printf 'proxy_listening=%s\n' "$([ -n "$port_check" ] && echo 1 || echo 0)"
printf 'trace_b64=%s\n' "$(printf '%s' "$trace_out" | b64)"
SH;

        $output = (string) $server->executeCommand($script, true);
        $values = [];
        foreach (preg_split('/\r?\n/', trim($output)) as $line) {
            if (strpos($line, '=') === false) {
                continue;
            }
            [$key, $value] = explode('=', $line, 2);
            $values[$key] = $value;
        }

        $decode = static function (string $key) use ($values): string {
            if (empty($values[$key])) {
                return '';
            }
            $decoded = base64_decode($values[$key], true);
            return $decoded === false ? '' : $decoded;
        };

        if (($values['mode_type'] ?? '') === 'netns') {
            $traceOut = $decode('trace_b64');
            $warpIp = '';
            if (preg_match('/ip=([^\s]+)/', $traceOut, $m)) {
                $warpIp = $m[1];
            }
            $status = [
                'installed' => true,
                'connected' => (bool) preg_match('/warp=on/i', $traceOut),
                'service_status' => trim((string) ($values['service_status'] ?? 'inactive')),
                'mode' => 'wireguard_netns',
                'proxy_port' => null,
                'proxy_listening' => false,
                'warp_ip' => $warpIp,
                'warp_status_raw' => $traceOut,
            ];
            @file_put_contents($cacheFile, json_encode($status));
            return $status;
        }

        if (($values['mode_type'] ?? '') === 'missing') {
            $status = [
                'installed' => false,
                'connected' => false,
                'message' => 'WARP не установлен'
            ];
            @file_put_contents($cacheFile, json_encode($status));
            return $status;
        }

        if (($values['mode_type'] ?? '') === 'warp_cli') {
            $warpStatus = $decode('warp_status_b64');
            $traceOut = $decode('trace_b64');
            $warpIp = '';
            if (preg_match('/ip=([^\s]+)/', $traceOut, $m)) {
                $warpIp = $m[1];
            }
            $warpMode = '';
            if (preg_match('/Mode:\s*(\S+)/i', $warpStatus, $m)) {
                $warpMode = $m[1];
            }
            $status = [
                'installed' => true,
                'connected' => (bool) preg_match('/Connected/i', $warpStatus),
                'service_status' => trim((string) ($values['service_status'] ?? 'inactive')),
                'mode' => $warpMode,
                'proxy_port' => (int) ($values['proxy_port'] ?? 40000),
                'proxy_listening' => ($values['proxy_listening'] ?? '0') === '1',
                'warp_ip' => $warpIp,
                'warp_status_raw' => $warpStatus,
            ];
            @file_put_contents($cacheFile, json_encode($status));
            return $status;
        }

        $egressUnit = trim($server->executeCommand('systemctl is-enabled awg2-warp-egress.service 2>/dev/null || echo ""', true));
        $egressNs = trim($server->executeCommand('ip netns list 2>/dev/null | grep -w awg2warp || echo ""', true));
        if ($egressUnit !== '' || $egressNs !== '') {
            $svcStatus = trim($server->executeCommand('systemctl is-active awg2-warp-egress.service 2>/dev/null || echo "inactive"', true));
            $traceOut = trim($server->executeCommand(
                'ip netns exec awg2warp curl -4 -s --max-time 5 --resolve cloudflare.com:443:104.16.132.229 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo ""',
                true
            ));
            $warpIp = '';
            if (preg_match('/ip=([^\s]+)/', $traceOut, $m)) {
                $warpIp = $m[1];
            }
            $isConnected = (bool) preg_match('/warp=on/i', $traceOut);

            return [
                'installed' => true,
                'connected' => $isConnected,
                'service_status' => $svcStatus,
                'mode' => 'wireguard_netns',
                'proxy_port' => null,
                'proxy_listening' => false,
                'warp_ip' => $warpIp,
                'warp_status_raw' => $traceOut,
            ];
        }

        $warpCliCheck = trim($server->executeCommand('command -v warp-cli 2>/dev/null || echo ""', true));
        if ($warpCliCheck === '') {
            return [
                'installed' => false,
                'connected' => false,
                'message' => 'WARP не установлен'
            ];
        }

        $svcStatus = trim($server->executeCommand('systemctl is-active warp-svc 2>/dev/null || echo "inactive"', true));
        $warpStatus = trim($server->executeCommand('warp-cli --accept-tos status 2>/dev/null || echo "error"', true));
        $isConnected = (bool) preg_match('/Connected/i', $warpStatus);

        $warpMode = '';
        if (preg_match('/Mode:\s*(\S+)/i', $warpStatus, $m)) {
            $warpMode = $m[1];
        }

        // Get proxy port from settings
        $proxyPortRaw = trim($server->executeCommand('warp-cli --accept-tos settings 2>/dev/null | grep -i "proxy port" || echo ""', true));
        $proxyPort = 40000;
        if (preg_match('/(\d+)/', $proxyPortRaw, $m)) {
            $proxyPort = (int) $m[1];
        }

        $warpIp = '';
        $portListening = false;
        if ($isConnected) {
            $portCheck = trim($server->executeCommand(
                'ss -tlnp 2>/dev/null | grep ":' . $proxyPort . '" | head -1 || echo ""', true
            ));
            $portListening = $portCheck !== '';

            if ($portListening) {
                $traceOut = trim($server->executeCommand(
                    'curl -x socks5h://127.0.0.1:' . $proxyPort . ' -s --max-time 5 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo ""', true
                ));
                if (preg_match('/ip=([^\s]+)/', $traceOut, $m)) {
                    $warpIp = $m[1];
                }
            }
        }

        return [
            'installed' => true,
            'connected' => $isConnected,
            'service_status' => $svcStatus,
            'mode' => $warpMode,
            'proxy_port' => $proxyPort,
            'proxy_listening' => $portListening,
            'warp_ip' => $warpIp,
            'warp_status_raw' => $warpStatus,
        ];
    }

}
