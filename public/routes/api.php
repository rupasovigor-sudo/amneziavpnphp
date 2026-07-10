<?php
/**
 * Route module — required from public/index.php after the bootstrap
 * (global helpers, Config/Auth/View init). Uses the global helper functions
 * and Router:: registered there; registration order across modules is
 * preserved by the require order in index.php.
 */

/**
 * API ROUTES (for Telegram bot integration)
 */

// API: Generate JWT token
Router::post('/api/auth/token', function () {
    header('Content-Type: application/json');

    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $rateIdentity = strtolower(trim($email)) . '|' . clientIp();
    $rateWindow = configInt('API_TOKEN_RATE_LIMIT_WINDOW_SECONDS', 300);
    $rateLimit = configInt('API_TOKEN_RATE_LIMIT_ATTEMPTS', 10);
    $rate = rateLimitExceeded('api_token', $rateIdentity, $rateLimit, $rateWindow);

    if ($rate['limited']) {
        http_response_code(429);
        header('Retry-After: ' . $rate['retry_after']);
        echo json_encode(['error' => 'Too many token requests', 'retry_after' => $rate['retry_after']]);
        return;
    }

    if (empty($email) || empty($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Email and password are required']);
        return;
    }

    $user = Auth::getUserByEmail($email);
    if (!$user || !password_verify($password, $user['password_hash'])) {
        recordRateLimitFailure('api_token', $rateIdentity, $rateWindow);
        http_response_code(401);
        echo json_encode(['error' => 'Invalid credentials']);
        return;
    }

    clearRateLimit('api_token', $rateIdentity);

    try {
        $tokenData = JWT::createApiToken($user['id'], 'Login API Token', 30 * 24 * 3600);
        echo json_encode([
            'success' => true,
            'token' => $tokenData['token'],
            'token_id' => $tokenData['id'],
            'type' => 'Bearer',
            'expires_in' => 30 * 24 * 3600 // 30 days
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Token generation failed']);
    }
});

// API: Create persistent API token
Router::post('/api/tokens', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $name = $_POST['name'] ?? 'API Token';
    $expiresIn = isset($_POST['expires_in']) ? (int) $_POST['expires_in'] : 2592000; // 30 days default

    try {
        $tokenData = JWT::createApiToken($user['id'], $name, $expiresIn);
        echo json_encode([
            'success' => true,
            'token' => $tokenData
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List user's API tokens
Router::get('/api/tokens', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $tokens = JWT::getUserTokens($user['id']);

    echo json_encode(['tokens' => $tokens]);
});

// API: Revoke API token
Router::delete('/api/tokens/{id}', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    try {
        JWT::revokeApiToken($params['id'], $user['id']);
        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List servers
Router::get('/api/servers', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $servers = VpnServer::redactServerList(VpnServer::listByUser($user['id']));

    // Enrich with installed protocols
    $pdo = DB::conn();
    foreach ($servers as &$server) {
        $stmt = $pdo->prepare('SELECT p.id, p.slug, p.name FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ?');
        $stmt->execute([$server['id']]);
        $server['protocols'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    unset($server);

    echo json_encode(['servers' => $servers]);
});

// API: Create server
Router::post('/api/servers/create', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $input = json_decode(file_get_contents('php://input'), true);

    $name = trim($input['name'] ?? '');
    $host = trim($input['host'] ?? '');
    $port = (int) ($input['port'] ?? 22);
    $username = trim($input['username'] ?? 'root');
    $password = $input['password'] ?? '';
    $installProtocol = trim($input['install_protocol'] ?? '');
    if ($installProtocol === '') {
        $installProtocol = InstallProtocolManager::getDefaultSlug();
    }

    if (empty($name) || empty($host) || empty($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields: name, host, password']);
        return;
    }

    try {
        $serverId = VpnServer::create([
            'user_id' => $user['id'],
            'name' => $name,
            'host' => $host,
            'domain' => $input['domain'] ?? '',
            'port' => $port,
            'username' => $username,
            'password' => $password,
            'install_protocol' => $installProtocol,
            'install_options' => $input['install_options'] ?? null,
        ]);

        http_response_code(201);
        echo json_encode([
            'success' => true,
            'server_id' => $serverId,
            'message' => 'Server created successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Delete server
Router::delete('/api/servers/{id}/delete', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $server->delete();
        echo json_encode([
            'success' => true,
            'message' => 'Server deleted successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});


// API: List clients
Router::get('/api/clients', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clients = VpnClient::listByUser($user['id']);
    echo json_encode(['clients' => $clients]);
});

// API: Get client details with stats
Router::get('/api/clients/{id}/details', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if (!canAccessClient($clientData, $user)) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        // Sync stats before returning
        $client->syncStats();

        // Reload data
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        $stats = $client->getFormattedStats();

        echo json_encode([
            'success' => true,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'created_at' => $clientData['created_at'],
                'stats' => $stats,
                'bytes_sent' => $clientData['bytes_sent'],
                'bytes_received' => $clientData['bytes_received'],
                'last_handshake' => $clientData['last_handshake'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Diagnose client connectivity against the live WireGuard/AWG container
Router::get('/api/clients/{id}/diagnostics', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        jsonError('Unauthorized', 401);
        return;
    }

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        if (!$clientData) {
            jsonError('Client not found', 404);
            return;
        }

        $server = new VpnServer((int) $clientData['server_id']);
        $serverData = $server->getData();
        if (!$serverData || !canAccessServer($serverData, $user)) {
            jsonError('Forbidden', 403);
            return;
        }

        $protocolSlug = getClientProtocolSlug($clientData);
        $containerName = resolveClientContainer($serverData, $clientData);
        $checks = [
            [
                'name' => 'client_status',
                'ok' => ($clientData['status'] ?? '') === 'active',
                'severity' => 'warning',
                'message' => (($clientData['status'] ?? '') === 'active')
                    ? 'Клиент активен в панели'
                    : 'Клиент не активен в панели: ' . (string) ($clientData['status'] ?? 'unknown'),
            ],
            [
                'name' => 'server_status',
                'ok' => ($serverData['status'] ?? '') === 'active',
                'severity' => 'critical',
                'message' => (($serverData['status'] ?? '') === 'active')
                    ? 'Сервер активен в панели'
                    : 'Сервер не активен в панели: ' . (string) ($serverData['status'] ?? 'unknown'),
            ],
        ];

        if (stripos($protocolSlug, 'awg') !== false || stripos($protocolSlug, 'wireguard') !== false || $protocolSlug === '') {
            $live = getWireGuardPeerDiagnostics($server, $containerName, $clientData);
            $checks = array_merge($checks, $live['checks']);
            $peer = $live['peer'];
        } else {
            $peer = null;
            $checks[] = [
                'name' => 'protocol',
                'ok' => true,
                'severity' => 'warning',
                'message' => "Для протокола {$protocolSlug} доступна только базовая диагностика",
            ];
        }

        echo json_encode([
            'success' => true,
            'client' => [
                'id' => (int) $clientData['id'],
                'name' => $clientData['name'],
                'ip' => $clientData['client_ip'],
                'protocol_slug' => $protocolSlug,
                'container_name' => $containerName,
            ],
            'checks' => $checks,
            'peer' => $peer,
        ]);
    } catch (Throwable $e) {
        jsonError($e->getMessage(), 500);
    }
});

// API: Get client QR code
Router::get('/api/clients/{id}/qr', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if (!canAccessClient($clientData, $user)) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        echo json_encode([
            'success' => true,
            'qr_code' => $clientData['qr_code'],
            'client_name' => $clientData['name']
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Revoke client
Router::post('/api/clients/{id}/revoke', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if (!canAccessClient($clientData, $user)) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->revoke()) {
            echo json_encode(['success' => true, 'message' => 'Client revoked']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to revoke client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Restore client
Router::post('/api/clients/{id}/restore', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if (!canAccessClient($clientData, $user)) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->restore()) {
            echo json_encode(['success' => true, 'message' => 'Client restored']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to restore client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Delete client
Router::delete('/api/clients/{id}/delete', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->delete()) {
            echo json_encode(['success' => true, 'message' => 'Client deleted']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to delete client']);
        }
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Get server metrics
Router::get('/api/servers/{id}/metrics', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $serverId = (int) $params['id'];
    $hours = isset($_GET['hours']) ? max(1, min(24 * 30, (int) $_GET['hours'])) : 24;
    $maxPoints = isset($_GET['max_points']) ? max(1, min(5000, (int) $_GET['max_points'])) : 720;

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $metrics = ServerMonitoring::getServerMetrics($serverId, $hours);

        echo json_encode(['success' => true, 'metrics' => $metrics]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get live server health checks for the monitoring dashboard
Router::get('/api/servers/{id}/health', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        jsonError('Unauthorized', 401);
        return;
    }

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        if (!$serverData || !canAccessServer($serverData, $user)) {
            jsonError('Forbidden', 403);
            return;
        }

        $monitoring = new ServerMonitoring($serverId);
        $checks = [];
        foreach ($monitoring->collectHealthChecks() as $name => $check) {
            $checks[] = [
                'name' => $name,
                'ok' => (bool) ($check['ok'] ?? false),
                'severity' => (string) ($check['severity'] ?? 'warning'),
                'message' => (string) ($check['message'] ?? ''),
            ];
        }

        $stmt = DB::conn()->prepare("
            SELECT alert_key, severity, status, fail_count, message, first_seen_at, last_seen_at, last_sent_at, resolved_at
            FROM alert_states
            WHERE server_id = ?
            ORDER BY COALESCE(last_seen_at, first_seen_at, created_at) DESC
            LIMIT 20
        ");
        $stmt->execute([$serverId]);

        echo json_encode([
            'success' => true,
            'server' => [
                'id' => $serverId,
                'name' => $serverData['name'],
                'status' => $serverData['status'],
            ],
            'checks' => $checks,
            'alerts' => $stmt->fetchAll(PDO::FETCH_ASSOC),
        ]);
    } catch (Throwable $e) {
        jsonError($e->getMessage(), 500);
    }
});

// API: Get client metrics
Router::get('/api/clients/{id}/metrics', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $clientId = (int) $params['id'];
    $hours = isset($_GET['hours']) ? max(1, min(24 * 30, (int) $_GET['hours'])) : 24;
    $maxPoints = isset($_GET['max_points']) ? max(1, min(5000, (int) $_GET['max_points'])) : 720;

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Get server to check ownership
        $server = new VpnServer($clientData['server_id']);
        $serverData = $server->getData();

        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $metrics = ServerMonitoring::getClientMetrics($clientId, $hours, $maxPoints);

        echo json_encode(['success' => true, 'metrics' => $metrics], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get all client metrics for a server
Router::get('/api/servers/{id}/client-metrics', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $serverId = (int) $params['id'];
    $hours = isset($_GET['hours']) ? max(1, min(24 * 30, (int) $_GET['hours'])) : 24;
    $maxPointsPerClient = isset($_GET['max_points_per_client'])
        ? max(1, min(2000, (int) $_GET['max_points_per_client']))
        : 120;

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $metrics = ServerMonitoring::getClientMetricsForServer($serverId, $hours, $maxPointsPerClient);

        echo json_encode([
            'success' => true,
            'metrics' => $metrics,
            'meta' => [
                'hours' => $hours,
                'max_points_per_client' => $maxPointsPerClient,
                'count' => count($metrics),
            ],
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get server clients
Router::get('/api/servers/{id}/clients', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        // Sync all stats first
        VpnClient::syncAllStatsForServer($serverId);

        $clients = VpnClient::listByServer($serverId);
        $clientsData = [];

        foreach ($clients as $clientData) {
            $client = new VpnClient($clientData['id']);
            $stats = $client->getFormattedStats();

            $clientsData[] = [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'created_at' => $clientData['created_at'],
                'stats' => $stats,
                'bytes_sent' => $clientData['bytes_sent'],
                'bytes_received' => $clientData['bytes_received'],
                'last_handshake' => $clientData['last_handshake'],
            ];
        }

        echo json_encode(['success' => true, 'clients' => $clientsData]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get online clients for a server (real-time)
Router::get('/api/servers/{id}/online', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        require_once __DIR__ . '/../../inc/ServerMonitoring.php';
        $onlineLogins = ServerMonitoring::getOnlineClientsForServer($serverData);

        echo json_encode(['success' => true, 'online' => $onlineLogins]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List server protocols
Router::get('/api/servers/{id}/protocols', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT sp.protocol_id, sp.config_data, sp.applied_at, p.name, p.slug, p.description FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ? ORDER BY p.name');
        $stmt->execute([$serverId]);
        $rows = $stmt->fetchAll();

        echo json_encode(['success' => true, 'protocols' => $rows], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List active (installable) protocols
Router::get('/api/protocols/active', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $protocols = InstallProtocolManager::listActive();
    $list = array_map(function ($p) {
        return [
            'id' => (int) ($p['id'] ?? 0),
            'slug' => $p['slug'] ?? '',
            'name' => $p['name'] ?? '',
            'description' => $p['description'] ?? null,
        ];
    }, $protocols);

    echo json_encode(['success' => true, 'protocols' => $list], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
});

// API: Install/activate protocol on server
Router::post('/api/servers/{id}/protocols/install', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];
    $rawBody = file_get_contents('php://input');
    $input = [];
    if ($rawBody !== false && trim($rawBody) !== '') {
        $decoded = json_decode($rawBody, true);
        if (is_array($decoded)) {
            $input = $decoded;
        }
    }
    if (empty($input) && !empty($_POST)) {
        $input = $_POST;
    }
    $protocolId = isset($input['protocol_id']) ? (int) $input['protocol_id'] : 0;

    if ($protocolId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'protocol_id required']);
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $protocol = InstallProtocolManager::getById($protocolId);
        if (!$protocol) {
            http_response_code(404);
            echo json_encode(['error' => 'Protocol not found']);
            return;
        }

        $result = InstallProtocolManager::activate($server, $protocol, []);

        // Keep API behavior consistent with UI flow: once protocol activation succeeds,
        // clear transient error state and mark server as active for client creation.
        if (is_array($result) && !empty($result['success'])) {
            $pdo = DB::conn();
            $stmtUpdate = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = NULL WHERE id = ?');
            $stmtUpdate->execute(['active', $serverId]);
        }
        echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Self-test WireGuard/AWG install + client config correctness
// Creates a client (optional) and verifies that:
// - Client private key derives the same public key as stored in DB
// - Server wg0 knows the peer and has matching PSK/AllowedIPs
// - Server public key/listening port match what client config contains
// - Reports current handshake/endpoint state
Router::post('/api/servers/{id}/protocols/selftest', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) ($params['id'] ?? 0);
    if ($serverId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid server id']);
        return;
    }

    $raw = file_get_contents('php://input');
    $data = [];
    if (is_string($raw) && trim($raw) !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $data = $decoded;
        }
    }
    if (empty($data) && !empty($_POST)) {
        $data = $_POST;
    }
    if (!is_array($data)) {
        $data = [];
    }

    $protocolId = isset($data['protocol_id']) ? (int) $data['protocol_id'] : 0;
    $install = !empty($data['install']);
    $clientId = isset($data['client_id']) ? (int) $data['client_id'] : 0;
    $createClient = array_key_exists('create_client', $data) ? (bool) $data['create_client'] : true;
    $clientName = trim((string) ($data['client_name'] ?? 'selftest-' . date('Ymd-His')));
    $includeSecrets = !empty($data['include_secrets']) && (($user['role'] ?? '') === 'admin');

    $extract = function (string $config, string $key): string {
        $pattern = '/^\s*' . preg_quote($key, '/') . '\s*=\s*(.+)\s*$/mi';
        if (preg_match($pattern, $config, $m)) {
            return trim($m[1]);
        }
        return '';
    };

    $deriveWgPublicKey = function (string $privateKeyB64): array {
        $privateKeyB64 = trim($privateKeyB64);
        if ($privateKeyB64 === '') {
            return ['ok' => false, 'error' => 'empty_private_key'];
        }

        $raw = base64_decode($privateKeyB64, true);
        if ($raw === false || strlen($raw) !== 32) {
            return ['ok' => false, 'error' => 'invalid_private_key_base64_or_length'];
        }

        if (!function_exists('sodium_crypto_scalarmult_base')) {
            return ['ok' => false, 'error' => 'libsodium_not_available'];
        }

        try {
            $pubRaw = sodium_crypto_scalarmult_base($raw);
            return ['ok' => true, 'public_key' => base64_encode($pubRaw)];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => 'derive_failed: ' . $e->getMessage()];
        }
    };

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (($serverData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($protocolId > 0 && $install) {
            $protocol = InstallProtocolManager::getById($protocolId);
            if (!$protocol) {
                http_response_code(404);
                echo json_encode(['error' => 'Protocol not found']);
                return;
            }
            InstallProtocolManager::activate($server, $protocol, []);
        }

        $client = null;
        if ($clientId > 0) {
            $client = new VpnClient($clientId);
            $clientData = $client->getData();
            if (($clientData['server_id'] ?? null) != $serverId) {
                http_response_code(400);
                echo json_encode(['error' => 'client_id does not belong to server']);
                return;
            }
            if (($clientData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
                http_response_code(403);
                echo json_encode(['error' => 'Forbidden']);
                return;
            }
        } elseif ($createClient) {
            $bindProtocolId = $protocolId > 0 ? $protocolId : null;
            if ($bindProtocolId !== null) {
                $pdo = DB::conn();
                $chk = $pdo->prepare('SELECT 1 FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
                $chk->execute([$serverId, $bindProtocolId]);
                if (!$chk->fetchColumn()) {
                    http_response_code(400);
                    echo json_encode(['error' => 'protocol_id is not installed on this server']);
                    return;
                }
            }
            $newClientId = VpnClient::create($serverId, (int) $user['id'], $clientName, null, $bindProtocolId);
            $client = new VpnClient($newClientId);
        } else {
            http_response_code(400);
            echo json_encode(['error' => 'Provide client_id or set create_client=true']);
            return;
        }

        $clientData = $client->getData();
        $config = $client->getConfig();

        $cfgPrivate = $extract($config, 'PrivateKey');
        $cfgPsk = $extract($config, 'PresharedKey');
        $cfgServerPub = $extract($config, 'PublicKey');
        $cfgEndpoint = $extract($config, 'Endpoint');
        $cfgAddress = $extract($config, 'Address');

        if ($cfgPrivate === '') {
            http_response_code(500);
            echo json_encode([
                'error' => 'Generated config missing PrivateKey',
                'client_id' => (int) ($clientData['id'] ?? 0),
            ]);
            return;
        }

        $containerName = (string) ($serverData['container_name'] ?? 'amnezia-awg');

        $derived = $deriveWgPublicKey($cfgPrivate);
        $computedClientPub = '';
        if (!empty($derived['ok']) && !empty($derived['public_key'])) {
            $computedClientPub = (string) $derived['public_key'];
        } else {
            $err = (string) ($derived['error'] ?? 'derive_failed');
            // If we can't derive locally (e.g., libsodium missing), fall back to wg inside container.
            if ($err === 'libsodium_not_available') {
                $shComputePub = "set -e; priv=" . escapeshellarg($cfgPrivate) . "; printf '%s' \"\$priv\" | wg pubkey";
                $cmdComputePub = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg($shComputePub);
                $computedClientPub = trim($server->executeCommand($cmdComputePub, true));
            } else {
                $computedClientPub = $err;
            }
        }

        $cmdServerPub = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 2>/dev/null | awk '/public key:/ {print \$3; exit}' || true");
        $serverPubLive = trim($server->executeCommand($cmdServerPub, true));

        $cmdServerPort = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 2>/dev/null | awk '/listening port:/ {print \$3; exit}' || true");
        $serverPortLive = trim($server->executeCommand($cmdServerPort, true));

        $cmdPskFile = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true");
        $serverPskFile = trim($server->executeCommand($cmdPskFile, true));

        $cmdDump = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 dump 2>/dev/null || true");
        $dump = (string) $server->executeCommand($cmdDump, true);

        $targetPeerPub = $computedClientPub;
        $looksLikeB64Key = (bool) preg_match('/^[A-Za-z0-9+\/]{42,44}={0,2}$/', $targetPeerPub);
        $isDeriveError = ($targetPeerPub === ''
            || !$looksLikeB64Key
            || strpos($targetPeerPub, 'invalid_') === 0
            || strpos($targetPeerPub, 'derive_failed') === 0
            || strpos($targetPeerPub, 'wg:') === 0
            || $targetPeerPub === 'libsodium_not_available'
            || $targetPeerPub === 'empty_private_key');
        if ($isDeriveError) {
            $targetPeerPub = (string) ($clientData['public_key'] ?? '');
        }

        $peer = null;
        $lines = preg_split('/\r?\n/', trim($dump));
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $parts = preg_split('/\s+/', $line);
            // Peer line format: public-key preshared-key endpoint allowed-ips latest-handshake transfer-rx transfer-tx persistent-keepalive
            if (!$parts || count($parts) < 8) {
                continue;
            }
            // Skip interface line: starts with interface name 'wg0'
            if ($parts[0] === 'wg0') {
                continue;
            }
            if ($targetPeerPub !== '' && hash_equals($parts[0], $targetPeerPub)) {
                $peer = [
                    'public_key' => $parts[0],
                    'preshared_key' => $parts[1],
                    'endpoint' => $parts[2],
                    'allowed_ips' => $parts[3],
                    'latest_handshake' => (int) $parts[4],
                    'transfer_rx' => (int) $parts[5],
                    'transfer_tx' => (int) $parts[6],
                    'persistent_keepalive' => $parts[7],
                ];
                break;
            }
        }

        $checks = [];
        $mismatches = [];

        $dbClientPub = (string) ($clientData['public_key'] ?? '');
        if ($dbClientPub !== '' && $computedClientPub !== '' && !hash_equals($dbClientPub, $computedClientPub)) {
            $mismatches[] = 'client_public_key_db_mismatch';
        }
        if ($serverPubLive !== '' && $cfgServerPub !== '' && !hash_equals($serverPubLive, $cfgServerPub)) {
            $mismatches[] = 'server_public_key_mismatch';
        }
        if ($serverPskFile !== '' && $cfgPsk !== '' && !hash_equals($serverPskFile, $cfgPsk)) {
            $mismatches[] = 'preshared_key_mismatch';
        }
        if ($peer === null) {
            $mismatches[] = 'peer_not_found_on_server';
        }

        $checks['client_public_key'] = [
            'db' => $dbClientPub,
            'computed_from_private' => $computedClientPub,
            'ok' => ($dbClientPub === '' || $computedClientPub === '') ? null : hash_equals($dbClientPub, $computedClientPub),
        ];
        $checks['server_public_key'] = [
            'config' => $cfgServerPub,
            'live' => $serverPubLive,
            'ok' => ($cfgServerPub === '' || $serverPubLive === '') ? null : hash_equals($cfgServerPub, $serverPubLive),
        ];
        $checks['preshared_key'] = [
            'config' => $includeSecrets ? $cfgPsk : ($cfgPsk !== '' ? (substr($cfgPsk, 0, 6) . '...') : ''),
            'server_file' => $includeSecrets ? $serverPskFile : ($serverPskFile !== '' ? (substr($serverPskFile, 0, 6) . '...') : ''),
            'ok' => ($cfgPsk === '' || $serverPskFile === '') ? null : hash_equals($cfgPsk, $serverPskFile),
        ];

        echo json_encode([
            'success' => empty($mismatches),
            'server_id' => $serverId,
            'protocol_id' => $protocolId > 0 ? $protocolId : null,
            'client' => [
                'id' => (int) ($clientData['id'] ?? 0),
                'name' => $clientData['name'] ?? null,
                'client_ip' => $clientData['client_ip'] ?? null,
                'public_key_db' => $dbClientPub,
                'public_key_computed' => $computedClientPub,
                'address_in_config' => $cfgAddress,
                'endpoint_in_config' => $cfgEndpoint,
                'private_key' => $includeSecrets ? $cfgPrivate : ($cfgPrivate !== '' ? (substr($cfgPrivate, 0, 6) . '...') : ''),
            ],
            'wg' => [
                'server_public_key_live' => $serverPubLive,
                'server_listen_port_live' => $serverPortLive,
                'peer' => $peer,
            ],
            'checks' => $checks,
            'mismatches' => $mismatches,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Diagnose why WG/AWG handshake is not happening
// Collects server-side evidence: wg show, peer dump, docker port mapping, basic firewall/NAT snippets,
// and (if available) a short tcpdump capture on the VPN UDP port.
Router::post('/api/servers/{id}/protocols/diagnose-handshake', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    // High-sensitivity endpoint (firewall rules, tcpdump). Keep it admin-only unless explicitly enabled.
    $debugEnabled = debugRoutesEnabled();
    if (($user['role'] ?? '') !== 'admin' && !$debugEnabled) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    $serverId = (int) ($params['id'] ?? 0);
    if ($serverId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid server id']);
        return;
    }

    $raw = file_get_contents('php://input');
    $data = [];
    if (is_string($raw) && trim($raw) !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $data = $decoded;
        }
    }
    if (empty($data) && !empty($_POST)) {
        $data = $_POST;
    }
    if (!is_array($data)) {
        $data = [];
    }

    $clientId = isset($data['client_id']) ? (int) $data['client_id'] : 0;
    $duration = isset($data['duration_seconds']) ? (int) $data['duration_seconds'] : 5;
    if ($duration < 1)
        $duration = 1;
    if ($duration > 15)
        $duration = 15;

    $deriveWgPublicKey = function (string $privateKeyB64): array {
        $privateKeyB64 = trim($privateKeyB64);
        if ($privateKeyB64 === '') {
            return ['ok' => false, 'error' => 'empty_private_key'];
        }

        $raw = base64_decode($privateKeyB64, true);
        if ($raw === false || strlen($raw) !== 32) {
            return ['ok' => false, 'error' => 'invalid_private_key_base64_or_length'];
        }

        if (!function_exists('sodium_crypto_scalarmult_base')) {
            return ['ok' => false, 'error' => 'libsodium_not_available'];
        }

        try {
            $pubRaw = sodium_crypto_scalarmult_base($raw);
            return ['ok' => true, 'public_key' => base64_encode($pubRaw)];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => 'derive_failed: ' . $e->getMessage()];
        }
    };

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (($serverData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $containerName = (string) ($serverData['container_name'] ?? 'amnezia-awg');
        $vpnPort = (int) ($serverData['vpn_port'] ?? 0);

        // Optionally derive client public key from stored client config
        $clientPub = '';
        $clientPubError = '';
        $clientIp = '';
        if ($clientId > 0) {
            $client = new VpnClient($clientId);
            $clientData = $client->getData();
            if (($clientData['server_id'] ?? null) != $serverId) {
                http_response_code(400);
                echo json_encode(['error' => 'client_id does not belong to server']);
                return;
            }
            if (($clientData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
                http_response_code(403);
                echo json_encode(['error' => 'Forbidden']);
                return;
            }

            $clientIp = (string) ($clientData['client_ip'] ?? '');

            $cfg = $client->getConfig();
            $cfgPrivate = '';
            if (preg_match('/^\s*PrivateKey\s*=\s*(.+)\s*$/mi', $cfg, $m)) {
                $cfgPrivate = trim($m[1]);
            }
            if ($cfgPrivate !== '') {
                $derived = $deriveWgPublicKey($cfgPrivate);
                if (!empty($derived['ok'])) {
                    $clientPub = (string) ($derived['public_key'] ?? '');
                } else {
                    $clientPubError = (string) ($derived['error'] ?? 'derive_failed');
                    // Fallback: compute using wg inside container (best-effort)
                    $shComputePub = "set -e; priv=" . escapeshellarg($cfgPrivate) . "; printf '%s' \"\$priv\" | wg pubkey";
                    $cmdComputePub = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg($shComputePub);
                    $computed = trim((string) $server->executeCommand($cmdComputePub, true));
                    // Basic validation: wg outputs a 44-char base64 key
                    if (preg_match('/^[A-Za-z0-9+\/]{42}==$/', $computed)) {
                        $clientPub = $computed;
                        $clientPubError = '';
                    } elseif ($computed !== '') {
                        $clientPubError = 'wg_pubkey_failed: ' . $computed;
                    }
                }
            }
        }

        // Gather status
        $cmdHostDate = "date -u '+%Y-%m-%dT%H:%M:%SZ'";
        $hostDate = trim($server->executeCommand($cmdHostDate, true));

        $cmdDockerPs = "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' | head -50";
        $dockerPs = $server->executeCommand($cmdDockerPs, true);

        $cmdInspectPorts = "docker inspect " . escapeshellarg($containerName) . " --format '{{json .NetworkSettings.Ports}}' 2>/dev/null || true";
        $dockerPortsJson = trim($server->executeCommand($cmdInspectPorts, true));

        $cmdWgShow = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 2>/dev/null || true");
        $wgShow = $server->executeCommand($cmdWgShow, true);

        $cmdWgDump = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 dump 2>/dev/null || true");
        $wgDump = $server->executeCommand($cmdWgDump, true);

        $cmdHostSs = ($vpnPort > 0)
            ? ("sh -c " . escapeshellarg("ss -lun | grep -E '(:" . (int) $vpnPort . ")\\b' || true"))
            : "sh -c 'echo no_vpn_port_in_db'";
        $hostUdpListen = $server->executeCommand($cmdHostSs, true);

        $cmdCtnSs = ($vpnPort > 0)
            ? ("docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("ss -lun 2>/dev/null | grep -E '(:" . (int) $vpnPort . ")\\b' || true"))
            : "docker exec -i " . escapeshellarg($containerName) . " sh -c 'echo no_vpn_port_in_db'";
        $containerUdpListen = $server->executeCommand($cmdCtnSs, true);

        // Firewall/NAT snippets (best-effort)
        $cmdUfw = "sh -c " . escapeshellarg("ufw status verbose 2>/dev/null || echo 'no ufw'");
        $ufw = $server->executeCommand($cmdUfw, true);

        $cmdIpt = "sh -c " . escapeshellarg("iptables -S INPUT 2>/dev/null | grep -E 'udp|" . (int) $vpnPort . "' | head -80 || true");
        $iptablesInput = $server->executeCommand($cmdIpt, true);

        $cmdNft = "sh -c " . escapeshellarg("nft list ruleset 2>/dev/null | grep -n '" . (int) $vpnPort . "' | head -60 || true");
        $nftPortLines = $server->executeCommand($cmdNft, true);

        // Probe changes over time (wg dump + nft counters) during the same request.
        $wgShowAfter = '';
        $wgDumpAfter = '';
        $nftPortLinesAfter = '';
        if ($duration > 0) {
            $cmdSleep = "sh -c " . escapeshellarg("sleep " . (int) $duration);
            $server->executeCommand($cmdSleep, true);
            $wgShowAfter = $server->executeCommand($cmdWgShow, true);
            $wgDumpAfter = $server->executeCommand($cmdWgDump, true);
            $nftPortLinesAfter = $server->executeCommand($cmdNft, true);
        }

        // tcpdump capture (optional)
        $tcpdump = '';
        if ($vpnPort > 0) {
            $tcpCmd = "sh -c " . escapeshellarg(
                "command -v tcpdump >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1 && timeout " . (int) $duration . " tcpdump -ni any udp port " . (int) $vpnPort . " -vv -c 10 2>/dev/null || echo 'tcpdump_unavailable_or_timeout_missing'"
            );
            $tcpdump = $server->executeCommand($tcpCmd, true);
        }

        // Try to extract peer line if clientPub is known
        $peerLine = '';
        $peerLineAfter = '';
        if ($clientPub !== '' && is_string($wgDump) && trim($wgDump) !== '') {
            $lines = preg_split('/\r?\n/', trim($wgDump));
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, 'wg0')) {
                    continue;
                }
                $parts = preg_split('/\s+/', $line);
                if ($parts && isset($parts[0]) && hash_equals($parts[0], $clientPub)) {
                    $peerLine = $line;
                    break;
                }
            }
        }

        if ($clientPub !== '' && is_string($wgDumpAfter) && trim($wgDumpAfter) !== '') {
            $lines = preg_split('/\r?\n/', trim($wgDumpAfter));
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, 'wg0')) {
                    continue;
                }
                $parts = preg_split('/\s+/', $line);
                if ($parts && isset($parts[0]) && hash_equals($parts[0], $clientPub)) {
                    $peerLineAfter = $line;
                    break;
                }
            }
        }

        $hints = [];
        if ($vpnPort <= 0) {
            $hints[] = 'vpn_port is missing in DB; endpoint may be wrong';
        }
        if (is_string($tcpdump) && str_contains($tcpdump, 'tcpdump_unavailable_or_timeout_missing')) {
            $hints[] = 'tcpdump/timeout not available on server; use nft counters or install tcpdump for deeper packet visibility';
        }
        if ($clientPub === '' && $clientPubError !== '') {
            $hints[] = 'failed to derive client public key from stored config: ' . $clientPubError;
        }
        if ($clientPub !== '' && $peerLine === '') {
            $hints[] = 'peer not found in wg dump for derived client public key (client might not be applied on server)';
        }

        echo json_encode([
            'success' => true,
            'server_id' => $serverId,
            'checked_at_utc' => $hostDate,
            'container_name' => $containerName,
            'vpn_port_db' => $vpnPort,
            'client' => [
                'client_id' => $clientId > 0 ? $clientId : null,
                'client_ip' => $clientIp !== '' ? $clientIp : null,
                'client_public_key_derived' => $clientPub !== '' ? $clientPub : null,
                'client_public_key_derive_error' => $clientPubError !== '' ? $clientPubError : null,
                'peer_line_from_dump' => $peerLine !== '' ? $peerLine : null,
                'peer_line_from_dump_after' => $peerLineAfter !== '' ? $peerLineAfter : null,
            ],
            'evidence' => [
                'docker_ps' => $dockerPs,
                'docker_ports_json' => $dockerPortsJson,
                'host_udp_listen' => $hostUdpListen,
                'container_udp_listen' => $containerUdpListen,
                'wg_show' => $wgShow,
                'wg_dump' => $wgDump,
                'wg_show_after' => $wgShowAfter,
                'wg_dump_after' => $wgDumpAfter,
                'ufw' => $ufw,
                'iptables_input_snippet' => $iptablesInput,
                'nft_port_lines' => $nftPortLines,
                'nft_port_lines_after' => $nftPortLinesAfter,
                'tcpdump' => $tcpdump,
            ],
            'hints' => $hints,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Uninstall all protocols from server
Router::post('/api/servers/{id}/protocols/uninstall-all', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT sp.protocol_id, p.slug FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ?');
        $stmt->execute([$serverId]);
        $rows = $stmt->fetchAll();

        $removedClients = 0;
        $removedBindings = 0;
        $uninstalled = [];
        $errors = [];

        foreach ($rows as $row) {
            $pid = (int) ($row['protocol_id'] ?? 0);
            $slug = (string) ($row['slug'] ?? '');
            if ($pid <= 0 || $slug === '') {
                continue;
            }

            try {
                $protocol = InstallProtocolManager::getById($pid);
                if (!$protocol) {
                    throw new Exception('Protocol not found');
                }

                InstallProtocolManager::uninstall($server, $protocol, []);

                $stmtDelSp = $pdo->prepare('DELETE FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
                $stmtDelSp->execute([$serverId, $pid]);
                $removedBindings += (int) $stmtDelSp->rowCount();

                $stmtDelClients = $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ? AND protocol_id = ?');
                $stmtDelClients->execute([$serverId, $pid]);
                $removedClients += (int) $stmtDelClients->rowCount();

                $uninstalled[] = ['protocol_id' => $pid, 'slug' => $slug];
            } catch (Exception $e) {
                $errors[] = ['protocol_id' => $pid, 'slug' => $slug, 'error' => $e->getMessage()];
            }
        }

        $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = NULL WHERE id = ?')->execute(['active', $serverId]);

        echo json_encode([
            'success' => empty($errors),
            'uninstalled' => $uninstalled,
            'errors' => $errors,
            'bindings_removed' => $removedBindings,
            'clients_removed' => $removedClients,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Uninstall protocol on server by slug
Router::post('/api/servers/{id}/protocols/{slug}/uninstall', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];
    $slug = $params['slug'] ?? '';

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $protocol = InstallProtocolManager::getBySlug($slug);
        if (!$protocol) {
            http_response_code(404);
            echo json_encode(['error' => 'Protocol not found']);
            return;
        }

        $result = InstallProtocolManager::uninstall($server, $protocol);

        // Cleanup bindings + clients (same behavior as UI route)
        $pdo = DB::conn();
        $stmtId = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
        $stmtId->execute([$slug]);
        $pid = (int) $stmtId->fetchColumn();
        $deletedClients = 0;
        $deletedBindings = 0;
        if ($pid) {
            $stmtDelSp = $pdo->prepare('DELETE FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
            $stmtDelSp->execute([$serverId, $pid]);
            $deletedBindings = $stmtDelSp->rowCount();
            $stmtDelClients = $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ? AND protocol_id = ?');
            $stmtDelClients->execute([$serverId, $pid]);
            $deletedClients = $stmtDelClients->rowCount();
        }
        $stmtUpdate = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = NULL WHERE id = ?');
        $stmtUpdate->execute(['active', $serverId]);

        echo json_encode(array_merge($result, [
            'bindings_removed' => $deletedBindings,
            'clients_removed' => $deletedClients
        ]), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

