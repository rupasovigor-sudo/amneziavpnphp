<?php
/**
 * Route module — required from public/index.php after the bootstrap
 * (global helpers, Config/Auth/View init). Uses the global helper functions
 * and Router:: registered there; registration order across modules is
 * preserved by the require order in index.php.
 */

Router::get('/', function () {
    if (!Auth::check()) {
        redirect('/login');
    }
    redirect('/dashboard');
});

// Login page
Router::get('/login', function () {
    if (Auth::check()) {
        redirect('/dashboard');
    }
    View::render('login.twig');
});

Router::post('/login', function () {
    $email = is_string($_POST['email'] ?? null) ? trim($_POST['email']) : '';
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $rate = authThrottleCheck($email);

    if ($rate['limited']) {
        http_response_code(429);
        View::render('login.twig', ['error' => 'Too many login attempts. Try again in ' . $rate['retry_after'] . ' seconds.']);
        return;
    }

    if (Auth::login($email, $password)) {
        authThrottleSuccess($email);
        redirect('/dashboard');
    }

    authThrottleFail($email);
    View::render('login.twig', ['error' => 'Invalid credentials']);
});

// Register page
Router::get('/register', function () {
    if (!registrationEnabled()) {
        http_response_code(404);
        echo 'Not Found';
        return;
    }

    if (Auth::check()) {
        redirect('/dashboard');
    }
    View::render('register.twig');
});

Router::post('/register', function () {
    if (!registrationEnabled()) {
        http_response_code(404);
        echo 'Not Found';
        return;
    }

    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        View::render('register.twig', ['error' => 'Invalid email address']);
        return;
    }

    if (strlen($password) < 6) {
        View::render('register.twig', ['error' => 'Password must be at least 6 characters']);
        return;
    }

    try {
        $success = Auth::register($name, $email, $password);
        if ($success) {
            Auth::login($email, $password);
            redirect('/dashboard');
        }
    } catch (Throwable $e) {
        // Email already exists or other error
    }

    View::render('register.twig', ['error' => 'Registration failed. Email may already be in use.']);
});

// Logout — POST only, so it is CSRF-protected (a GET /logout could be
// triggered cross-site via <img src=/logout> to force-logout a user).
Router::post('/logout', function () {
    Auth::logout();
    redirect('/login');
});

/**
 * AUTHENTICATED ROUTES
 */

// Dashboard
Router::get('/dashboard', function () {
    requireAuth();
    $user = Auth::user();

    // Get user's servers
    $servers = VpnServer::attachPoolInfo(VpnServer::redactServerList(VpnServer::listByUser($user['id'], false)));

    // Get user's clients
    $clients = VpnClient::listByUser($user['id']);

    // Count clients with a recent handshake (within 5 minutes) as online (WireGuard/AWG).
    // Admins see the whole system; other users only their own clients.
    $pdo = DB::conn();
    $onlineSql = "
        SELECT COUNT(*) as cnt FROM vpn_clients
        WHERE last_handshake IS NOT NULL
        AND last_handshake > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        AND status = 'active'
    ";
    if (Auth::isAdmin()) {
        $stmt = $pdo->query($onlineSql);
    } else {
        $stmt = $pdo->prepare($onlineSql . ' AND user_id = ?');
        $stmt->execute([(int) $user['id']]);
    }
    $totalOnline = (int) $stmt->fetchColumn();

    View::render('dashboard.twig', [
        'servers' => $servers,
        'clients' => $clients,
        'online_count' => $totalOnline,
        'online_users' => [],
    ]);
});

// Servers list
Router::get('/servers', function () {
    requireAuth();
    $user = Auth::user();

    $servers = Auth::isAdmin()
        ? VpnServer::listAll(false)
        : VpnServer::listByUser($user['id'], false);
    $servers = VpnServer::attachPoolInfo(VpnServer::redactServerList($servers));

    View::render('servers/index.twig', ['servers' => $servers]);
});

// Clients workspace: the selected VPN server is switched with tabs. Pool
// members intentionally share one list because their peers are synchronized.
Router::get('/clients', function () {
    requireAuth();
    $user = Auth::user();

    $servers = Auth::isAdmin()
        ? VpnServer::listAll(false)
        : VpnServer::listByUser((int) $user['id'], false);
    $servers = array_values(array_filter($servers, static function (array $server): bool {
        return ($server['role'] ?? 'vpn') !== 'front';
    }));
    $servers = VpnServer::attachPoolInfo($servers);

    $requestedId = isset($_GET['server_id']) ? (int) $_GET['server_id'] : 0;
    $selectedServer = null;
    foreach ($servers as $server) {
        if ((int) ($server['id'] ?? 0) === $requestedId) {
            $selectedServer = $server;
            break;
        }
    }
    if ($selectedServer === null) {
        foreach ($servers as $server) {
            if (($server['status'] ?? '') === 'active') {
                $selectedServer = $server;
                break;
            }
        }
    }
    if ($selectedServer === null && $servers) {
        $selectedServer = $servers[0];
    }

    $clients = [];
    $onlineLogins = [];
    $selectedFront = null;
    if ($selectedServer !== null) {
        $poolId = (int) ($selectedServer['pool_id'] ?? 0);
        $clients = $poolId > 0
            ? VpnClient::listByPool($poolId)
            : VpnClient::listByServer((int) $selectedServer['id']);
        $onlineLogins = ServerMonitoring::getOnlineClientsForServer($selectedServer);
        if ($poolId > 0) {
            $front = PoolFront::forPool($poolId);
            if ($front && (int) ($front['enabled'] ?? 0) === 1 && ($front['dns_mode'] ?? '') === 'front') {
                $selectedFront = [
                    'name' => (string) ($front['server_name'] ?? 'RU-фронт'),
                    'host' => (string) ($front['server_host'] ?? ''),
                ];
            }
        }
    }

    View::render('clients/index.twig', [
        'servers' => VpnServer::redactServerList($servers),
        'selected_server' => $selectedServer !== null
            ? VpnServer::redactServerSecrets($selectedServer)
            : null,
        'clients' => $clients,
        'online_logins' => $onlineLogins,
        'online_window' => ServerMonitoring::onlineWindow(),
        'selected_front' => $selectedFront,
    ]);
});

// Create server page
Router::get('/servers/create', function () {
    requireAuth();
    $protocols = InstallProtocolManager::listStandalone();
    $defaultProtocol = !empty($protocols) ? ($protocols[0]['slug'] ?? InstallProtocolManager::getDefaultSlug()) : InstallProtocolManager::getDefaultSlug();
    View::render('servers/create.twig', [
        'selected_mode' => 'manual',
        'form_data' => [],
        'protocols' => $protocols,
        'default_protocol' => $defaultProtocol
    ]);
});

// Create server action
Router::post('/servers/create', function () {
    requireAuth();
    $user = Auth::user();
    $creationMode = $_POST['creation_mode'] ?? 'manual';
    $formData = $_POST;
    $protocols = InstallProtocolManager::listStandalone();
    $defaultProtocol = InstallProtocolManager::getDefaultSlug();
    $formData['install_protocol'] = $_POST['install_protocol'] ?? $defaultProtocol;
    // Reject non-standalone protocols (e.g. the cf-warp egress add-on).
    $standaloneSlugs = array_map(function ($p) {
        return $p['slug'] ?? '';
    }, $protocols);
    if (!in_array($formData['install_protocol'], $standaloneSlugs, true)) {
        $formData['install_protocol'] = $defaultProtocol;
    }

    $name = trim($_POST['name'] ?? '');
    $host = trim($_POST['host'] ?? '');
    $port = (int) ($_POST['port'] ?? 22);
    $username = trim($_POST['username'] ?? 'root');
    $password = $_POST['password'] ?? '';
    // ssh_key handling
    $sshKey = trim($_POST['ssh_key'] ?? '');

    $protocolSlug = $formData['install_protocol'] ?? $defaultProtocol;
    $protocolRecord = InstallProtocolManager::getBySlug($protocolSlug);
    if (!$protocolRecord) {
        View::render('servers/create.twig', [
            'error' => 'Selected protocol not found or inactive',
            'selected_mode' => $creationMode,
            'form_data' => $formData,
            'protocols' => $protocols,
            'default_protocol' => $defaultProtocol
        ]);
        return;
    }
    $protocolMetadata = $protocolRecord['definition']['metadata'] ?? [];
    $containerName = $protocolMetadata['container_name'] ?? 'amnezia-awg';
    $defaultSubnet = $protocolMetadata['vpn_subnet'] ?? '10.8.1.0/24';
    $vpnSubnet = $formData['vpn_subnet'] ?? $defaultSubnet;
    $installOptions = $protocolRecord['definition']['defaults'] ?? null;

    if (empty($name) || empty($host) || (empty($password) && empty($sshKey))) {
        View::render('servers/create.twig', [
            'error' => 'All fields are required (either Password or SSH Key)',
            'selected_mode' => $creationMode,
            'form_data' => $formData,
            'protocols' => $protocols,
            'default_protocol' => $defaultProtocol
        ]);
        return;
    }

    try {
        $serverId = VpnServer::create([
            'user_id' => $user['id'],
            'name' => $name,
            'host' => $host,
            'domain' => $_POST['domain'] ?? '',
            'port' => $port,
            'username' => $username,
            'password' => $password,
            'ssh_key' => $sshKey,
            'container_name' => $containerName,
            'vpn_subnet' => $vpnSubnet,
            'install_protocol' => $protocolSlug,
            'install_options' => $installOptions,
        ]);

        redirect('/servers/' . $serverId . '/deploy');
    } catch (Exception $e) {
        View::render('servers/create.twig', [
            'error' => $e->getMessage(),
            'selected_mode' => $creationMode,
            'form_data' => $formData,
            'protocols' => $protocols,
            'default_protocol' => $defaultProtocol
        ]);
    }
});

// Delete server action
Router::post('/servers/{id}/delete', function ($params) {
    requireAuth();
    $user = Auth::user();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $server->delete();
        $_SESSION['success_message'] = 'Server deleted successfully';
        redirect('/servers');
    } catch (Exception $e) {
        $_SESSION['error_message'] = $e->getMessage();
        redirect('/servers');
    }
});

// Deploy server page
Router::get('/servers/{id}/deploy', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        View::render('servers/deploy.twig', ['server' => VpnServer::redactServerSecrets($serverData)]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Server not found';
    }
});

// Deploy server action (AJAX)
Router::post('/servers/{id}/deploy', function ($params) {
    requireAuth();
    // Release the PHP session file lock immediately: this request holds it for the
    // whole ~2 min deploy (with ignore_user_abort), which would otherwise block
    // EVERY other request from the same browser session (e.g. navigating to
    // /servers) until the deploy finishes — the "redirect just hangs" symptom.
    // $_SESSION stays readable for Auth::user()/isAdmin() below.
    @session_write_close();
    @set_time_limit(900);
    @ini_set('max_execution_time', '900');
    // The deploy rebuilds a docker image (~2 min). Finish it server-side even if
    // the browser fetch times out and disconnects, so the server isn't left stuck
    // in status='deploying' (the deploy sets status active/error at the end).
    @ignore_user_abort(true);
    header('Content-Type: application/json');
    if (rejectFrontServer((int) $params['id'])) {
        return;
    }

    $serverId = (int) $params['id'];
    $rawBody = file_get_contents('php://input');
    $options = [];
    if ($rawBody !== false && trim($rawBody) !== '') {
        $decoded = json_decode($rawBody, true);
        if (is_array($decoded)) {
            $options = $decoded;
        }
    }
    if (empty($options) && !empty($_POST)) {
        $options = $_POST;
    }
    if (!is_array($options)) {
        $options = [];
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $result = $server->deploy($options);
        if (!isset($result['success']) && empty($result['requires_action'])) {
            $result['success'] = true;
        }

        // If the server has an endpoint domain and a DNS provider token is
        // configured, point the domain's A-record at this server. Best-effort:
        // never fail the deploy because of DNS.
        // Pool-safe: a standby pool member must NOT repoint the shared domain on
        // deploy (that would hijack traffic to a non-active node). Only the pool's
        // active member — or a standalone server — updates the A-record.
        $domain = trim((string) ($serverData['domain'] ?? ''));
        $memberPoolId = (int) ($serverData['pool_id'] ?? 0);
        // The DNS token belongs to the panel owner: only an admin's deploy may
        // write A-records (a user could otherwise repoint any name in the zone).
        $mayRepoint = Auth::isAdmin();
        if ($domain !== '' && $mayRepoint) {
            // Never let a non-active node hijack a pool's shared domain. This must
            // catch a STANDALONE server that merely carries the same domain (e.g.
            // a freshly provisioned server before it is deliberately made active),
            // not only servers already recorded as pool members.
            $owningPool = ServerPool::findByDomain($domain);
            if ($owningPool) {
                $mayRepoint = (int) ($owningPool['active_server_id'] ?? 0) === $serverId;
            } elseif ($memberPoolId > 0) {
                $poolRow = ServerPool::get($memberPoolId);
                $mayRepoint = $poolRow && (int) ($poolRow['active_server_id'] ?? 0) === $serverId;
            }
            // While the pool domain points at its front (entry relay), a member
            // redeploy must not pull it back onto one server.
            $repointPoolId = $owningPool ? (int) $owningPool['id'] : $memberPoolId;
            if ($repointPoolId > 0 && PoolFront::domainOnFront($repointPoolId)) {
                $mayRepoint = false;
            }
        }
        if (!empty($result['success']) && $domain !== '' && $mayRepoint && DnsManager::isConfigured()) {
            try {
                $dns = DnsManager::upsertARecord($domain, (string) ($serverData['host'] ?? ''));
                $result['dns'] = $dns;
            } catch (Throwable $e) {
                $result['dns'] = ['success' => false, 'message' => $e->getMessage()];
                error_log('DNS upsert failed on deploy: ' . $e->getMessage());
            }
        }

        echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
});

// Uninstall all protocols from server (mass cleanup) - MUST be before {slug}/uninstall
Router::post('/servers/{id}/protocols/uninstall-all', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Forbidden']);
            return;
        }
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT p.* FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ?');
        $stmt->execute([$serverId]);
        $protocols = $stmt->fetchAll();
        $removedClients = 0;
        foreach ($protocols as $protocol) {
            try {
                $res = InstallProtocolManager::uninstall($server, $protocol, []);
                $pid = (int) $protocol['id'];
                $pdo->prepare('DELETE FROM server_protocols WHERE server_id = ? AND protocol_id = ?')->execute([$serverId, $pid]);
                // Remove clients bound to this protocol
                $stmtDel = $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ? AND protocol_id = ?');
                $stmtDel->execute([$serverId, $pid]);
                $removedClients += (int) $stmtDel->rowCount();
            } catch (Exception $e) {
                // continue with next protocol
            }
        }
        echo json_encode(['success' => true, 'clients_removed' => $removedClients, 'message' => 'All protocols uninstalled']);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Uninstall a specific protocol on server (AJAX)
Router::post('/servers/{id}/protocols/{slug}/uninstall', function ($params) {
    requireAuth();
    header('Content-Type: application/json');

    $serverId = (int) $params['id'];
    $slug = $params['slug'] ?? '';

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
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

        // Update server status
        $stmtCount = $pdo->prepare('SELECT COUNT(*) FROM server_protocols WHERE server_id = ?');
        $stmtCount->execute([$serverId]);
        $remaining = (int) $stmtCount->fetchColumn();

        // If we successfully uninstalled, we can clear the error state
        // If no protocols remain, status is 'absent', otherwise 'active'
        $newStatus = 'active';
        $stmtUpdate = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = NULL WHERE id = ?');
        $stmtUpdate->execute([$newStatus, $serverId]);

        echo json_encode(array_merge($result, [
            'bindings_removed' => $deletedBindings,
            'clients_removed' => $deletedClients
        ]));
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Activate protocol on server (AJAX)
Router::post('/servers/{id}/protocols/activate', function ($params) {
    requireAuth();
    // A protocol install runs for minutes; don't hold the session lock (it
    // would freeze every other page of this admin meanwhile). $_SESSION stays
    // readable in memory for the rest of the handler.
    session_write_close();

    // Suppress errors and clean output buffer to prevent HTML corruption of JSON
    @ini_set('display_errors', '0');
    error_reporting(0);
    while (ob_get_level()) {
        @ob_end_clean();
    }

    header('Content-Type: application/json');

    $serverId = (int) $params['id'];
    if (rejectFrontServer($serverId)) {
        return;
    }
    $protocolId = isset($_POST['protocol_id']) ? (int) $_POST['protocol_id'] : 0;
    Logger::appendInstall($serverId, 'HTTP activate requested protocol_id=' . $protocolId);

    if ($protocolId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'protocol_id required']);
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            Logger::appendInstall($serverId, 'HTTP activate forbidden user=' . ($user['id'] ?? 0));
            return;
        }

        $protocol = InstallProtocolManager::getById($protocolId);
        if (!$protocol) {
            http_response_code(404);
            echo json_encode(['error' => 'Protocol not found']);
            Logger::appendInstall($serverId, 'HTTP activate protocol not found id=' . $protocolId);
            return;
        }

        $result = InstallProtocolManager::activate($server, $protocol, []);
        echo json_encode($result);
        Logger::appendInstall($serverId, 'HTTP activate finished ok');
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
        Logger::appendInstall($serverId, 'HTTP activate failed: ' . $e->getMessage());
    }
});

// Get WARP status for a server (AJAX)
Router::get('/servers/{id}/warp/status', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        $status = InstallProtocolManager::getWarpStatus($server);
        echo json_encode(array_merge(['success' => true], $status, ['warp_enabled' => (int) ($serverData['warp_enabled'] ?? 1)]));
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// WARP actions: connect/disconnect/reconnect (AJAX)
Router::post('/servers/{id}/warp/action', function ($params) {
    requireAdmin();
    session_write_close(); // on/off waits up to ~50s for the unit
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
    if (!in_array($action, ['connect', 'disconnect', 'reconnect', 'rotate'], true)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action. Allowed: connect, disconnect, reconnect, rotate']);
        return;
    }
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        // cf-warp v3 is always the WireGuard-netns profile pool; drive it via
        // systemd and the runtime engine (no legacy warp-cli path).
        // connect/disconnect are the persistent on/off switch (a bare
        // "systemctl stop" was undone by the health timer within a minute).
        switch ($action) {
            case 'connect':
            case 'disconnect':
                DB::conn()->prepare('UPDATE vpn_servers SET warp_enabled = ? WHERE id = ?')
                    ->execute([$action === 'connect' ? 1 : 0, $serverId]);
                $res = ServerUpdateManager::applyWarpSettings($serverId);
                $status = InstallProtocolManager::getWarpStatus($server, false);
                echo json_encode(array_merge($status, [
                    'success' => !empty($res['success']),
                    'action' => $action,
                    'message' => $res['message'] ?? '',
                    'warp_enabled' => $action === 'connect' ? 1 : 0,
                ]), JSON_UNESCAPED_UNICODE);
                return;
            case 'reconnect':
                // --no-block: a start may wait minutes on apt locks; never hang the request.
                $server->executeCommand('systemctl reset-failed awg2-warp-egress.service 2>/dev/null; systemctl restart --no-block awg2-warp-egress.service 2>/dev/null || true', true);
                break;
            case 'rotate':
                // Switch to the next profile in the pool without dropping the tunnel.
                $server->executeCommand('/usr/local/sbin/awg2-warp-egress rotate manual_ui 2>/dev/null || true', true);
                break;
        }
        sleep(2);
        $status = InstallProtocolManager::getWarpStatus($server, false);
        echo json_encode(array_merge(['success' => true, 'action' => $action], $status, ['warp_enabled' => (int) ($serverData['warp_enabled'] ?? 1)]));
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// DNS status of the server's endpoint domain (AJAX)
Router::get('/servers/{id}/dns/status', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        $domain = trim((string) ($serverData['domain'] ?? ''));
        $host = (string) ($serverData['host'] ?? '');
        $resolved = [];
        if ($domain !== '') {
            foreach ((dns_get_record($domain, DNS_A) ?: []) as $rec) {
                if (!empty($rec['ip'])) {
                    $resolved[] = $rec['ip'];
                }
            }
        }
        echo json_encode([
            'success' => true,
            'domain' => $domain,
            'host' => $host,
            'resolved_ips' => $resolved,
            'points_here' => $domain !== '' && in_array($host, $resolved, true),
            'provider' => DnsManager::provider(),
            'provider_configured' => DnsManager::isConfigured(),
        ], JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Rename a server (AJAX, admin/owner).
Router::post('/servers/{id}/rename', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $name = trim((string) ($input['name'] ?? ''));
    if ($name === '' || mb_strlen($name) > 100) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Имя обязательно (до 100 символов)']);
        return;
    }
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if (($serverData['user_id'] ?? null) != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Forbidden']);
            return;
        }
        DB::conn()->prepare('UPDATE vpn_servers SET name = ? WHERE id = ?')->execute([$name, $serverId]);
        echo json_encode(['success' => true, 'name' => $name], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Save the endpoint domain and/or repoint its A-record at this server (AJAX)
Router::post('/servers/{id}/dns/update', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (array_key_exists('domain', $input)) {
            $domain = strtolower(trim((string) $input['domain'], ". \t\n"));
            if ($domain !== '' && !preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/', $domain)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Invalid domain name']);
                return;
            }
            $stmt = DB::conn()->prepare('UPDATE vpn_servers SET domain = ? WHERE id = ?');
            $stmt->execute([$domain !== '' ? $domain : null, $serverId]);
            $serverData['domain'] = $domain;
        }

        $domain = trim((string) ($serverData['domain'] ?? ''));
        $response = ['success' => true, 'domain' => $domain];

        if ($domain !== '' && !empty($input['upsert'])) {
            if (!DnsManager::isConfigured()) {
                $response['dns'] = ['success' => false, 'message' => 'DNS provider token is not configured (Settings → API)'];
            } else {
                $frontPool = ServerPool::findByDomain($domain);
                if ($frontPool && PoolFront::domainOnFront((int) $frontPool['id'])) {
                    $response['success'] = false;
                    $response['dns'] = ['success' => false, 'message' => 'Этот домен принадлежит пулу и сейчас указывает на RU-фронт — перенаправление на отдельный сервер заблокировано.'];
                } else {
                    $response['dns'] = DnsManager::upsertARecord($domain, (string) ($serverData['host'] ?? ''));
                    $response['success'] = (bool) $response['dns']['success'];
                }
            }
        }

        echo json_encode($response, JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Failover pool status for a server (AJAX)
Router::get('/servers/{id}/pool/status', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        if ($poolId <= 0) {
            // Standalone: offer the pools this server could join.
            $available = array_map(static function ($p) {
                return ['id' => (int) $p['id'], 'name' => $p['name'], 'domain' => $p['domain']];
            }, ServerPool::list());
            echo json_encode(['success' => true, 'in_pool' => false, 'server_id' => $serverId, 'available_pools' => $available]);
            return;
        }
        $status = ServerPool::status($poolId);
        echo json_encode(array_merge(['success' => true, 'in_pool' => true, 'server_id' => $serverId], $status ?? []), JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Split a standby into its own direct pool while keeping the source pool's
// shared AWG identity/client set (AJAX, admin).
Router::post('/servers/{id}/pool/split', function ($params) {
    requireAdmin();
    @set_time_limit(300);
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    try {
        $res = ServerPool::splitMemberToLinkedPool(
            $serverId,
            trim((string) ($input['name'] ?? '')),
            trim((string) ($input['domain'] ?? '')),
            !array_key_exists('repoint', $input) || !empty($input['repoint'])
        );
        if (empty($res['success'])) {
            http_response_code(409);
        }
        echo json_encode($res, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
});

// Select another compatible pool as the authoritative client/peer source.
Router::post('/servers/{id}/pool/peer-source', function ($params) {
    requireAdmin();
    @set_time_limit(300);
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    try {
        $data = (new VpnServer($serverId))->getData();
        $poolId = (int) ($data['pool_id'] ?? 0);
        if ($poolId <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Сервер не состоит в пуле'], JSON_UNESCAPED_UNICODE);
            return;
        }
        $sourceId = (int) ($input['source_pool_id'] ?? 0);
        $res = ServerPool::setPeerSource($poolId, $sourceId > 0 ? $sourceId : null);
        if (empty($res['success'])) {
            http_response_code(409);
        }
        echo json_encode($res, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
});

// Create a failover pool by adopting this server's awg2 identity (AJAX, admin)
Router::post('/servers/{id}/pool/create', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    if (rejectFrontServer($serverId)) {
        return;
    }
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $name = trim((string) ($input['name'] ?? ''));
    if ($name === '') {
        $name = 'pool-' . $serverId;
    }
    try {
        $res = ServerPool::createFromServer($serverId, $name);
        echo json_encode($res, JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Live client summary: peers with a recent handshake on this server's awg2
// interface — proof it actually serves clients (real traffic, no synthetic
// probe). AJAX.
Router::get('/servers/{id}/net/live-clients', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        echo json_encode(array_merge(['success' => true], $server->liveClientSummary()), JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Live per-client online status from legacy awg0 and parallel awg31, keyed by public key. Pool-aware:
// reads the ACTIVE member's interface (that's where clients actually connect),
// so the table's status/last-handshake stay live without waiting for the
// metrics-collector cycle.
Router::get('/servers/{id}/clients/live-status', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        // One SSH round-trip per pool member per poll, multiplied by every open
        // tab, adds up fast. The data only needs to be a few seconds fresh, so
        // serve a short-lived shared cache instead.
        $cacheTtl = max(0, (int) Config::get('LIVE_STATUS_CACHE_SECONDS', '20'));
        $cacheFile = sys_get_temp_dir() . '/live_status_' . ($poolId > 0 ? 'group' . ServerPool::peerRootPoolId($poolId) : 'srv' . $serverId) . '.json';
        if ($cacheTtl > 0 && is_readable($cacheFile)) {
            $cached = json_decode((string) @file_get_contents($cacheFile), true);
            if (is_array($cached) && (time() - (int) ($cached['at'] ?? 0)) < $cacheTtl && isset($cached['peers'])) {
                echo json_encode([
                    'success' => true,
                    'peers' => $cached['peers'],
                    'online_window' => ServerMonitoring::onlineWindow(),
                    'cached' => true,
                ], JSON_UNESCAPED_SLASHES);
                return;
            }
        }

        if ($poolId > 0) {
            // A client sits on whichever member it last resolved — after a switch
            // it lingers on the OLD one until it re-resolves the domain. Reading
            // only the active member would report every client that still lives
            // elsewhere as offline and reset its badge to "active". Merge all
            // members and keep the freshest handshake per peer.
            $peers = [];
            $activeMemberIds = [];
            foreach (ServerPool::peerGroupPoolIds($poolId) as $groupPoolId) {
                $groupPool = ServerPool::get($groupPoolId);
                $activeMemberIds[(int) ($groupPool['active_server_id'] ?? 0)] = true;
            }
            foreach (ServerPool::peerGroupServerIds($poolId) as $memberId) {
                try {
                    $memberData = (new VpnServer($memberId))->getData();
                    $memberPeers = (new VpnServer($memberId))->liveClientPeers();
                } catch (Exception $e) {
                    continue; // a single unreachable member must not blank the list
                }
                foreach ($memberPeers as $pub => $info) {
                    $age = $info['handshake_age'] ?? null;
                    $seen = $peers[$pub]['handshake_age'] ?? null;
                    if (!isset($peers[$pub]) || ($age !== null && ($seen === null || $age < $seen))) {
                        // Remember WHICH member this handshake came from. Clients
                        // stay on the member they last resolved, so after a switch
                        // they linger on the old one — surfacing that per client
                        // turns an invisible split into something the operator
                        // can see at a glance.
                        $info['server_id'] = $memberId;
                        $info['server_name'] = (string) ($memberData['name'] ?? ('#' . $memberId));
                        $info['connection_pool_id'] = (int) ($memberData['pool_id'] ?? 0);
                        $info['is_active_member'] = isset($activeMemberIds[$memberId]);
                        $peers[$pub] = $info;
                    }
                }
            }
        } else {
            $peers = $server->liveClientPeers();
        }
        // Stamp each peer with the SAME online verdict the rest of the panel uses
        // (traffic received from the client), so the two pollers and the initial
        // render can never disagree — that disagreement is what made statuses
        // flicker before.
        $onlineNames = array_flip(ServerMonitoring::clientsWithRecentTraffic($poolId, $serverId));
        $keyToName = [];
        foreach (DB::conn()->query("SELECT public_key, name FROM vpn_clients WHERE status = 'active'")->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $keyToName[(string) $row['public_key']] = (string) $row['name'];
        }
        foreach ($peers as $pk => $info) {
            $name = $keyToName[(string) $pk] ?? null;
            $peers[$pk]['online'] = $name !== null && isset($onlineNames[$name]);
        }
        // Mark the actual path using the front of the pool carrying this peer.
        // A linked direct pool and a fronted source pool share clients, so using
        // only the page's pool would mislabel a FI/front session as KZ/direct.
        if ($poolId > 0) {
            $fronts = [];
            foreach ($peers as $pk => $info) {
                $connectionPoolId = (int) ($info['connection_pool_id'] ?? 0);
                if (!array_key_exists($connectionPoolId, $fronts)) {
                    $fronts[$connectionPoolId] = PoolFront::forPool($connectionPoolId);
                }
                $front = $fronts[$connectionPoolId];
                if ($front && (int) $front['enabled'] === 1 && $front['dns_mode'] === 'front') {
                    $peers[$pk]['via_front'] = (string) ($info['endpoint_ip'] ?? '') === (string) $front['server_host'];
                    $peers[$pk]['front_name'] = (string) ($front['server_name'] ?? 'RU-фронт');
                    $peers[$pk]['front_host'] = (string) ($front['server_host'] ?? '');
                }
            }
        }

        if ($cacheTtl > 0) {
            @file_put_contents($cacheFile, json_encode(['peers' => $peers, 'at' => time()]));
        }
        echo json_encode([
            'success' => true,
            'peers' => $peers,
            'online_window' => ServerMonitoring::onlineWindow(),
            'cached' => false,
        ], JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// ── Package updates ──────────────────────────────────────────────────────
// Fleet-wide update overview (page + data).
Router::get('/updates', function () {
    requireAdmin();
    View::render('updates.twig', []);
});

// Dedicated maintenance page works for VPN members and entry fronts alike.
// Fronts do not have the regular /servers/{id} VPN page, so without this page
// their package audit was visible in the fleet but had nowhere actionable to go.
Router::get('/updates/server/{id}', function ($params) {
    requireAdmin();
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        View::render('server_updates.twig', [
            'server' => VpnServer::redactServerSecrets($serverData),
        ]);
    } catch (Throwable $e) {
        http_response_code(404);
        echo 'Server not found';
    }
});

// Rolling update of a whole pool in a detached worker (AJAX, admin).
Router::post('/updates/pool/{id}', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $poolId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $actions = array_values(array_intersect(
        (array) ($input['actions'] ?? ['os']),
        ['os', 'kernel', 'docker', 'awg2', 'warp', 'reboot']
    ));
    if (!$actions) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Не выбрано ни одного действия']);
        return;
    }
    try {
        $members = ServerPool::members($poolId);
        if (count($members) < 2) {
            http_response_code(409);
            echo json_encode([
                'success' => false,
                'error' => 'В пуле меньше двух серверов — обновление без простоя невозможно.',
            ], JSON_UNESCAPED_UNICODE);
            return;
        }
        foreach ($members as $m) {
            $st = ServerUpdateManager::getState((int) $m['id']);
            if (($st['state'] ?? '') === 'running') {
                http_response_code(409);
                echo json_encode(['success' => false, 'error' => 'На сервере ' . $m['name'] . ' уже идёт задача'], JSON_UNESCAPED_UNICODE);
                return;
            }
        }

        $php = is_file('/usr/local/bin/php') ? '/usr/local/bin/php' : PHP_BINARY;
        $worker = dirname(__DIR__, 2) . '/bin/server_update_worker.php';
        $log = dirname(__DIR__, 2) . '/logs/pool_update_' . $poolId . '.log';
        ServerUpdateManager::ensureWritableLog($log);
        exec(sprintf(
            'nohup %s %s --pool-id=%d --actions=%s >> %s 2>&1 &',
            escapeshellarg($php), escapeshellarg($worker), $poolId,
            escapeshellarg(implode(',', $actions)), escapeshellarg($log)
        ));

        echo json_encode([
            'success' => true,
            'message' => 'Rolling-обновление пула запущено: сначала резервные, затем переключение и бывший активный.',
        ], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

Router::get('/updates/fleet', function () {
    requireAdmin();
    header('Content-Type: application/json');
    try {
        ServerUpdateManager::reapStuck();
        $refresh = !empty($_GET['refresh']);
        $rows = DB::conn()->query(
            "SELECT s.id, s.name, s.host, s.role, s.pool_id, p.name AS pool_name
             FROM vpn_servers s LEFT JOIN server_pools p ON p.id = s.pool_id
             WHERE s.status != 'deleted' ORDER BY s.id"
        )->fetchAll(PDO::FETCH_ASSOC) ?: [];

        $out = [];
        foreach ($rows as $r) {
            $id = (int) $r['id'];
            // A refresh SSHes into every server, so it is opt-in; the default
            // view serves the stored audit (also kept current by the daily cron).
            $audit = $refresh ? ServerUpdateManager::audit($id) : ServerUpdateManager::lastAudit($id);
            $out[] = [
                'id'        => $id,
                'name'      => $r['name'],
                'host'      => $r['host'],
                'role'      => $r['role'] ?? 'vpn',
                'pool_id'   => (int) ($r['pool_id'] ?? 0),
                'pool_name' => $r['pool_name'] ?? null,
                'is_active' => ServerUpdateManager::isActivePoolMember($id),
                'audit'     => $audit,
                'state'     => ServerUpdateManager::getState($id),
            ];
        }
        echo json_encode(['success' => true, 'servers' => $out], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Read-only audit of what is out of date on the server (AJAX, admin).
Router::get('/servers/{id}/updates/audit', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $fresh = !empty($_GET['refresh']);
        $audit = $fresh ? ServerUpdateManager::audit($serverId) : (ServerUpdateManager::lastAudit($serverId) ?? ServerUpdateManager::audit($serverId));
        echo json_encode([
            'success'   => !empty($audit['ok']),
            'audit'     => $audit,
            'is_active' => ServerUpdateManager::isActivePoolMember($serverId),
            'state'     => ServerUpdateManager::getState($serverId),
            'history'   => ServerUpdateManager::history($serverId, 8),
        ], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Start a maintenance action in a detached worker (AJAX, admin).
// action: os | docker | awg2 | warp | reboot
Router::post('/servers/{id}/updates/os', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $force = !empty($input['force']);
    $action = (string) ($input['action'] ?? 'os');
    if (!in_array($action, ['os', 'kernel', 'docker', 'awg2', 'warp', 'reboot'], true)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Неизвестное действие']);
        return;
    }
    try {
        // Guardrail: the active member is carrying live clients. Refuse unless
        // the operator explicitly forces it after switching the pool.
        if (!$force && ServerUpdateManager::isActivePoolMember($serverId)) {
            http_response_code(409);
            echo json_encode([
                'success' => false,
                'needs_force' => true,
                'error' => 'Это активный член пула — на нём висят клиенты. Переключите пул на другой сервер или подтвердите принудительно.',
            ], JSON_UNESCAPED_UNICODE);
            return;
        }
        $state = ServerUpdateManager::getState($serverId);
        if (($state['state'] ?? '') === 'running') {
            echo json_encode(['success' => true, 'async' => true, 'state' => 'running', 'message' => 'Обновление уже идёт'], JSON_UNESCAPED_UNICODE);
            return;
        }

        ServerUpdateManager::setState($serverId, 'running', 'Запуск задачи…');

        $php = is_file('/usr/local/bin/php') ? '/usr/local/bin/php' : PHP_BINARY;
        $worker = dirname(__DIR__, 2) . '/bin/server_update_worker.php';
        $log = dirname(__DIR__, 2) . '/logs/server_update_' . $serverId . '.log';
        ServerUpdateManager::ensureWritableLog($log);
        $cmd = sprintf(
            'nohup %s %s --server-id=%d --action=%s%s >> %s 2>&1 &',
            escapeshellarg($php), escapeshellarg($worker), $serverId, escapeshellarg($action),
            $force ? ' --force=1' : '', escapeshellarg($log)
        );
        exec($cmd);

        echo json_encode([
            'success' => true,
            'async'   => true,
            'state'   => 'running',
            'message' => 'Обновление запущено в фоне — можно закрыть страницу.',
        ], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Poll the background update worker (AJAX, admin).
Router::get('/servers/{id}/updates/status', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        // Release jobs whose worker died, so the UI does not poll forever.
        ServerUpdateManager::reapStuck();
        echo json_encode([
            'success' => true,
            'state'   => ServerUpdateManager::getState($serverId),
            'audit'   => ServerUpdateManager::lastAudit($serverId),
            'history' => ServerUpdateManager::history($serverId, 8),
        ], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Add this (standalone) server to an existing pool (AJAX, admin).
// Redeploys the server with the pool's shared identity and syncs client peers —
// a multi-minute operation (docker build); the request blocks until done.
Router::post('/servers/{id}/pool/join', function ($params) {
    requireAdmin();
    @set_time_limit(600);
    // The join runs several multi-minute deploys (awg2 image build + WARP install).
    // Keep going even if the browser fetch times out and disconnects, so the member
    // finishes joining/syncing/WARP server-side instead of being left half-joined.
    @ignore_user_abort(true);
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    if (rejectFrontServer($serverId)) {
        return;
    }
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $poolId = (int) ($input['pool_id'] ?? 0);
    if ($poolId <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'pool_id required']);
        return;
    }
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        if (!empty($serverData['pool_id'])) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Server is already in a pool']);
            return;
        }
        // A worker that died (container restart, OOM) leaves 'deploying' behind
        // forever; after 45 minutes treat it as stale and allow a retry.
        $joinStarted = strtotime((string) ($serverData['pool_join_started_at'] ?? '')) ?: 0;
        if (($serverData['pool_join_state'] ?? '') === 'deploying' && (time() - $joinStarted) < 2700) {
            echo json_encode(['success' => true, 'async' => true, 'state' => 'deploying', 'message' => 'Добавление уже выполняется…']);
            return;
        }
        $priority = isset($input['priority']) ? (int) $input['priority'] : 100;

        // Mark deploying immediately (so a page reload already shows progress),
        // then run the join in a DETACHED worker: the browser doesn't block on the
        // multi-minute deploy/peer-sync/WARP and the job survives a disconnect.
        DB::conn()->prepare('UPDATE vpn_servers SET pool_join_state = ?, pool_join_message = ?, pool_join_started_at = NOW() WHERE id = ?')
            ->execute(['deploying', 'Запуск добавления в пул…', $serverId]);

        $php = is_file('/usr/local/bin/php') ? '/usr/local/bin/php' : PHP_BINARY;
        $worker = dirname(__DIR__, 2) . '/bin/pool_join_worker.php';
        $log = dirname(__DIR__, 2) . '/logs/pool_join_' . $serverId . '.log';
        $cmd = sprintf(
            'nohup %s %s --server-id=%d --pool-id=%d --priority=%d >> %s 2>&1 &',
            escapeshellarg($php), escapeshellarg($worker), $serverId, $poolId, $priority, escapeshellarg($log)
        );
        exec($cmd);

        echo json_encode([
            'success' => true,
            'async' => true,
            'state' => 'deploying',
            'message' => 'Добавление в пул запущено в фоне — можно закрыть страницу.',
        ], JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Poll the background pool-join worker's progress (AJAX, admin).
Router::get('/servers/{id}/join-status', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $stmt = DB::conn()->prepare('SELECT pool_join_state, pool_join_message, pool_id, status FROM vpn_servers WHERE id = ?');
        $stmt->execute([$serverId]);
        $r = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
        echo json_encode([
            'success' => true,
            'state' => $r['pool_join_state'] ?? null,
            'message' => $r['pool_join_message'] ?? null,
            'in_pool' => !empty($r['pool_id']),
            'status' => $r['status'] ?? null,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Edit the pool this server belongs to: name and/or shared domain (AJAX, admin).
Router::post('/servers/{id}/pool/update', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        if ($poolId <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Server is not in a pool']);
            return;
        }
        $pool = ServerPool::get($poolId);
        $response = ['success' => true];

        if (array_key_exists('name', $input)) {
            $name = trim((string) $input['name']);
            if ($name === '' || mb_strlen($name) > 100) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Имя пула обязательно (до 100 символов)']);
                return;
            }
            DB::conn()->prepare('UPDATE server_pools SET name = ? WHERE id = ?')->execute([$name, $poolId]);
            $response['name'] = $name;
        }

        if (array_key_exists('domain', $input)) {
            $domain = strtolower(trim((string) $input['domain'], ". \t\n"));
            if ($domain !== '' && !preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/', $domain)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Неверный домен']);
                return;
            }
            // The domain is shared: update the pool row AND every member so client-config
            // generation uses the new endpoint.
            DB::conn()->prepare('UPDATE server_pools SET domain = ? WHERE id = ?')->execute([$domain !== '' ? $domain : null, $poolId]);
            DB::conn()->prepare('UPDATE vpn_servers SET domain = ? WHERE pool_id = ?')->execute([$domain !== '' ? $domain : null, $poolId]);
            $response['domain'] = $domain;
            $response['warning'] = 'Домен пула изменён. Существующие клиентские конфиги ведут на старый домен — их нужно перевыпустить.';

            // Point the new domain at the current active member.
            if ($domain !== '' && !empty($input['repoint'])) {
                if (!DnsManager::isConfigured()) {
                    $response['dns'] = ['success' => false, 'message' => 'DNS provider token не настроен (Settings → API)'];
                } else {
                    $activeId = (int) ($pool['active_server_id'] ?? 0);
                    $activeHost = '';
                    foreach (ServerPool::members($poolId) as $m) {
                        if ((int) $m['id'] === $activeId) { $activeHost = (string) $m['host']; break; }
                    }
                    // Behind a front the domain belongs on the front, not a member.
                    $poolFront = PoolFront::forPool($poolId);
                    if ($poolFront && PoolFront::domainOnFront($poolId)) {
                        $activeHost = (string) $poolFront['server_host'];
                    }
                    if ($activeHost !== '') {
                        $response['dns'] = DnsManager::upsertARecord($domain, $activeHost);
                    }
                }
            }
        }

        echo json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Dissolve & delete the pool this server belongs to (AJAX, admin). Members become
// standalone again (keep their awg2 + clients); optionally free the endpoint domain.
Router::post('/servers/{id}/pool/delete', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        if ($poolId <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Server is not in a pool']);
            return;
        }
        $pool = ServerPool::get($poolId);
        $domain = trim((string) ($pool['domain'] ?? ''));
        $poolName = (string) ($pool['name'] ?? ('pool ' . $poolId));

        $linked = DB::conn()->prepare('SELECT COUNT(*) FROM server_pools WHERE peer_source_pool_id = ?');
        $linked->execute([$poolId]);
        if ((int) $linked->fetchColumn() > 0) {
            http_response_code(409);
            echo json_encode(['success' => false, 'error' => 'Этот пул является источником клиентов для других пулов — сначала отключите их связь с источником'], JSON_UNESCAPED_UNICODE);
            return;
        }

        // A pool's entry relay would be orphaned: with no members it relays to
        // nothing, and the domain (if on the front) would blackhole everyone.
        if ($front = PoolFront::forPool($poolId)) {
            if ($front['dns_mode'] === 'front') {
                http_response_code(409);
                echo json_encode(['success' => false, 'error' => 'Домен пула указывает на RU-фронт — сначала верните его на сервер (страница «Пулы»)'], JSON_UNESCAPED_UNICODE);
                return;
            }
            PoolFront::remove($poolId);
        }

        // Dissolve: clear pool membership/state on every member → standalone.
        DB::conn()->prepare(
            'UPDATE vpn_servers
             SET pool_id = NULL, pool_priority = 0, pool_sync_pending = 0,
                 validated_clean = NULL, validated_at = NULL, validation_note = NULL,
                 pool_join_state = NULL, pool_join_message = NULL, pool_join_started_at = NULL
             WHERE pool_id = ?'
        )->execute([$poolId]);
        DB::conn()->prepare('DELETE FROM server_pools WHERE id = ?')->execute([$poolId]);
        try {
            DB::conn()->prepare('DELETE FROM pool_repair_state WHERE pool_id = ?')->execute([$poolId]);
        } catch (Throwable $e) {
            // table may not exist on older schemas
        }

        $response = ['success' => true, 'message' => "Пул «{$poolName}» распущен и удалён; серверы стали standalone."];

        // Optional: free the endpoint domain (remove its A-records).
        if (!empty($input['remove_dns']) && $domain !== '' && DnsManager::isConfigured()) {
            $response['dns'] = DnsManager::deleteAllARecords($domain);
            $response['message'] .= ' DNS: ' . ($response['dns']['message'] ?? '');
        }
        echo json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Mark a pool member as validated-clean (or clear it) — the manual canary: the
// operator verifies the member live (make active, connect from a censored
// network), then marks it good so auto-failover may target it.
Router::post('/servers/{id}/pool/mark-clean', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $clean = !empty($input['clean']);
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        if ((int) ($serverData['pool_id'] ?? 0) <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Server is not in a pool']);
            return;
        }
        if ($clean) {
            DB::conn()->prepare('UPDATE vpn_servers SET validated_clean = 1, validated_at = NOW(), validation_note = ? WHERE id = ?')
                ->execute(['вручную помечен годным (проверен оператором)', $serverId]);
            $msg = 'Помечен годным — доступен для авто-failover';
        } else {
            DB::conn()->prepare('UPDATE vpn_servers SET validated_clean = NULL, validated_at = NOW(), validation_note = ? WHERE id = ?')
                ->execute(['пометка «годен» снята', $serverId]);
            $msg = 'Пометка снята';
        }
        echo json_encode(['success' => true, 'message' => $msg], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Make this server the active member (repoint the pool domain here) (AJAX, admin)
Router::post('/servers/{id}/pool/activate', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        if ($poolId <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Server is not in a pool']);
            return;
        }
        $res = ServerPool::setActive($poolId, $serverId, 'manual_ui');
        echo json_encode($res, JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Force connected clients toward the active member (kick them off the standbys).
Router::post('/servers/{id}/pool/force-migrate', function ($params) {
    requireAdmin();
    @set_time_limit(120);
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $poolId = (int) ((new VpnServer($serverId))->getData()['pool_id'] ?? 0);
        if ($poolId <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Server is not in a pool']);
            return;
        }
        echo json_encode(ServerPool::forceMigrateToActive($poolId), JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Re-sync a pool member's client peers (clears the pool_sync_pending flag so the
// member can serve as a failover target again).
Router::post('/servers/{id}/pool/resync', function ($params) {
    requireAdmin();
    @set_time_limit(300);
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        if ($poolId <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Server is not in a pool']);
            return;
        }
        $failed = 0;
        $synced = ServerPool::syncClientsToServer($poolId, $serverId, $failed);
        echo json_encode([
            'success' => $failed === 0,
            'synced' => $synced,
            'failed' => $failed,
            'message' => $failed === 0
                ? "Re-synced {$synced} client peers"
                : "{$failed} of " . ($synced + $failed) . " peers still failed — member kept out of failover",
        ], JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Tier-1 reachability probe: from an external pool member (the active one),
// stand up a throwaway amneziawg client against this server's public ip:port and
// check for a handshake. Confirms the ingress is UP/routed from the datacenter —
// does NOT prove the IP is "clean" for censored client networks (that's the canary).
Router::post('/servers/{id}/pool/probe', function ($params) {
    requireAdmin();
    @set_time_limit(120);
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        if ($poolId <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Server is not in a pool']);
            return;
        }
        $res = ServerPool::probeReachability($poolId, $serverId);
        echo json_encode($res, JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// View server
Router::get('/servers/{id}', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        // A pool front has no VPN page — it is managed from the pools page.
        if (PoolFront::isFrontServer($serverData)) {
            redirect('/pools');
        }

        $pdo = DB::conn();
        $serverProtocols = [];
        try {
            $stmt = $pdo->prepare('SELECT sp.protocol_id, sp.config_data, sp.applied_at, p.name, p.slug, p.description FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ? ORDER BY p.name');
            $stmt->execute([$serverId]);
            $serverProtocols = $stmt->fetchAll();
            foreach ($serverProtocols as &$sp) {
                $cfg = [];
                if (!empty($sp['config_data'])) {
                    $cfg = is_string($sp['config_data']) ? json_decode($sp['config_data'], true) : $sp['config_data'];
                }
                $sp['server_host'] = is_array($cfg) ? ($cfg['server_host'] ?? '') : '';
                $sp['server_port'] = is_array($cfg) ? ($cfg['server_port'] ?? '') : '';
                $sp['extras'] = (is_array($cfg) && isset($cfg['extras']) && is_array($cfg['extras'])) ? $cfg['extras'] : [];
                $sp['result_json'] = '';
                if (is_array($sp['extras']) && isset($sp['extras']['result']) && is_array($sp['extras']['result'])) {
                    $sp['result_json'] = json_encode($sp['extras']['result'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
                }
            }
            unset($sp);
        } catch (Exception $e) {
            $serverProtocols = [];
        }

        $allActive = InstallProtocolManager::listActive();
        $installedIds = array_map(function ($row) {
            return (int) $row['protocol_id'];
        }, $serverProtocols);
        $availableProtocols = array_values(array_filter($allActive, function ($p) use ($installedIds) {
            $pid = (int) ($p['id'] ?? 0);
            return $pid > 0 && !in_array($pid, $installedIds, true);
        }));

        View::render('servers/view.twig', [
            'server' => VpnServer::redactServerSecrets($serverData),
            'server_protocols' => $serverProtocols,
            'available_protocols' => $availableProtocols,
            'online_window' => ServerMonitoring::onlineWindow(),
        ]);
    } catch (Exception $e) {
        error_log('Server view error: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
        http_response_code(404);
        echo 'Server not found: ' . htmlspecialchars($e->getMessage());
    }
});



// Server monitoring page
Router::get('/servers/{id}/monitoring', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        // Clients connect to the ACTIVE member of a pool, not the identity-donor
        // home server — so show the pool's clients only on the active member;
        // a standby member has none live.
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        if ($poolId > 0) {
            $stmt = DB::conn()->prepare('SELECT active_server_id FROM server_pools WHERE id = ?');
            $stmt->execute([$poolId]);
            $activeId = (int) $stmt->fetchColumn();
            $clients = ($serverId === $activeId) ? VpnClient::listByPool($poolId) : [];
        } else {
            $clients = VpnClient::listByServer($serverId);
        }

        View::render('servers/monitoring.twig', [
            'server' => VpnServer::redactServerSecrets($serverData),
            // Only what the speed widget needs — the full rows carried key
            // material, configs and QR blobs into the page source.
            'clients' => array_map(static fn($c) => ['id' => (int) $c['id'], 'name' => (string) $c['name']], $clients),
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Server not found';
    }
});

// Create client for server
Router::post('/servers/{id}/clients/create', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];
    if (rejectFrontServer($serverId, false)) {
        return;
    }
    $clientName = trim($_POST['name'] ?? '');
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $login = isset($_POST['login']) ? trim($_POST['login']) : '';

    // Handle expiration: either from dropdown (days) or custom input (seconds)
    $expiresInDays = null;
    if (!empty($_POST['expires_in_seconds'])) {
        // Convert seconds to days (round up)
        $expiresInDays = (int) ceil((int) $_POST['expires_in_seconds'] / 86400);
    } elseif (!empty($_POST['expires_in_days']) && $_POST['expires_in_days'] !== 'custom') {
        $expiresInDays = (int) $_POST['expires_in_days'];
    }

    // Handle traffic limit: either from dropdown (GB) or custom input (MB)
    $trafficLimitBytes = null;
    if (!empty($_POST['traffic_limit_mb'])) {
        // Convert MB to bytes
        $trafficLimitBytes = (int) ((float) $_POST['traffic_limit_mb'] * 1048576);
    } elseif (!empty($_POST['traffic_limit_gb']) && $_POST['traffic_limit_gb'] !== 'custom') {
        // Convert GB to bytes
        $trafficLimitBytes = (int) ((float) $_POST['traffic_limit_gb'] * 1073741824);
    }

    if (empty($clientName)) {
        redirect('/clients?server_id=' . $serverId . '&error=Client+name+is+required');
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $protocolId = isset($_POST['protocol_id']) && $_POST['protocol_id'] !== '' ? (int) $_POST['protocol_id'] : null;
        if ($protocolId) {
            try {
                $pdo = DB::conn();
                $chk = $pdo->prepare('SELECT 1 FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
                $chk->execute([$serverId, $protocolId]);
                if (!$chk->fetchColumn()) {
                    $protocolId = null;
                }
            } catch (Exception $e) {
                $protocolId = null;
            }
        }
        $clientId = VpnClient::create($serverId, $user['id'], $clientName, $expiresInDays, $protocolId, $username, $login);

        // Set traffic limit if specified
        if ($trafficLimitBytes !== null && $trafficLimitBytes > 0) {
            $client = new VpnClient($clientId);
            $client->setTrafficLimit($trafficLimitBytes);
        }

        redirect('/clients/' . $clientId);
    } catch (Exception $e) {
        redirect('/clients?server_id=' . $serverId . '&error=' . urlencode($e->getMessage()));
    }
});

// View client
Router::get('/clients/{id}', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        $server = new VpnServer((int) $clientData['server_id']);
        $serverData = $server->getData();
        $protocolOutput = '';
        $isAwg2 = false;
        $protocolSlug = '';
        $clientEndpoints = [];
        $clientProfiles = [];
        $selectedEndpointPoolId = 0;
        try {
            $pdo = DB::conn();
            $protocol = null;
            if (!empty($clientData['protocol_id'])) {
                $stmt = $pdo->prepare('SELECT * FROM protocols WHERE id = ? LIMIT 1');
                $stmt->execute([(int) $clientData['protocol_id']]);
                $protocol = $stmt->fetch();
            } else {
                $stmt = $pdo->prepare('SELECT * FROM protocols WHERE slug = ? LIMIT 1');
                $stmt->execute([$serverData['install_protocol'] ?? '']);
                $protocol = $stmt->fetch();
            }

            if ($protocol) {
                $clientData['show_text_content'] = !empty($protocol['show_text_content']);
                $protocolSlug = (string) ($protocol['slug'] ?? '');
                $isAwg2 = ($protocolSlug === 'awg2');
            }
            if ($protocol && ($protocol['output_template'] ?? '') !== '') {
                $slug = $protocol['slug'] ?? '';
                $isWireguard = in_array($slug, ['awg2'], true);
                if ($isWireguard) {
                    // For WG, we don't render protocol_output; config is downloadable
                    $protocolOutput = '';
                } else {
                    // For non-WG protocols, reuse stored generated output in config
                    $protocolOutput = $clientData['config'] ?? '';
                }
            }
            
        } catch (Exception $e) {
            $protocolOutput = '';
        }
        $homePoolId = (int) ($serverData['pool_id'] ?? 0);
        if ($homePoolId > 0) {
            $isAwg31Client = (string) ($clientData['awg_version'] ?? '2.0') === '3.1';
            $requestedPoolId = (int) ($_GET['pool_id'] ?? 0);
            $groupPoolIds = ServerPool::peerGroupPoolIds($homePoolId);
            $selectedEndpointPoolId = in_array($requestedPoolId, $groupPoolIds, true) ? $requestedPoolId : $homePoolId;
            foreach ($groupPoolIds as $endpointPoolId) {
                $ep = ServerPool::get($endpointPoolId);
                if ($ep && trim((string) ($ep['domain'] ?? '')) !== '') {
                    $endpointFront = PoolFront::forPool($endpointPoolId);
                    $viaFront = $endpointFront
                        && (int) ($endpointFront['enabled'] ?? 0) === 1
                        && ($endpointFront['dns_mode'] ?? '') === 'front';
                    $clientEndpoints[] = [
                        'pool_id' => $endpointPoolId,
                        'name' => $ep['name'],
                        'domain' => trim((string) $ep['domain']),
                        'port' => ServerPool::endpointPort($ep, $isAwg31Client ? '3.1' : '2.0'),
                        'current' => $endpointPoolId === $homePoolId,
                        'selected' => $endpointPoolId === $selectedEndpointPoolId,
                        'via_front' => $viaFront,
                        'front_name' => $viaFront ? (string) ($endpointFront['server_name'] ?? 'RU-фронт') : '',
                        'front_host' => $viaFront ? (string) ($endpointFront['server_host'] ?? '') : '',
                    ];
                }
            }
        }

        // Each pool endpoint needs its own encoded payload: changing only the
        // download URL is not enough because both QR formats and vpn:// embed
        // the Endpoint line inside the payload.
        $profileEndpoints = $clientEndpoints;
        if (!$profileEndpoints) {
            $storedEndpoint = '';
            if (preg_match('/^\s*Endpoint\s*=\s*(.+)\s*$/mi', (string) ($clientData['config'] ?? ''), $match)) {
                $storedEndpoint = trim($match[1]);
            }
            $profileEndpoints[] = [
                'pool_id' => 0,
                'name' => (string) ($serverData['name'] ?? 'Server'),
                'domain' => $storedEndpoint,
                'port' => '',
                'selected' => true,
            ];
        }

        foreach ($profileEndpoints as $endpoint) {
            $profileConfig = (string) ($clientData['config'] ?? '');
            $poolId = (int) ($endpoint['pool_id'] ?? 0);
            $endpointAddress = '';
            if ($poolId > 0) {
                $endpointAddress = trim((string) ($endpoint['domain'] ?? '')) . ':' . (int) ($endpoint['port'] ?? 0);
                $profileConfig = preg_replace(
                    '/^(\s*Endpoint\s*=\s*).+$/mi',
                    '$1' . $endpointAddress,
                    $profileConfig,
                    1
                ) ?? $profileConfig;
            } else {
                $endpointAddress = trim((string) ($endpoint['domain'] ?? ''));
            }

            $profile = $endpoint;
            $profile['key'] = $poolId > 0 ? 'pool-' . $poolId : 'server-' . (int) $clientData['server_id'];
            $profile['endpoint'] = $endpointAddress;
            $profile['simple_qr'] = '';
            $profile['vpn_qr'] = '';
            $profile['vpn_url'] = '';
            if ($profileConfig !== '') {
                $profile['simple_qr'] = VpnClient::generateQRCode($profileConfig, $protocolSlug);
                if ($isAwg2) {
                    try {
                        require_once __DIR__ . '/../../inc/QrUtil.php';
                        $profile['vpn_qr'] = VpnClient::generateQRCodeVpnUrl($profileConfig, 'awg2');
                        $profile['vpn_url'] = 'vpn://' . QrUtil::encodeVpnUrlConf($profileConfig, 'awg2');
                    } catch (Throwable $e) {
                        error_log('Failed to build endpoint profile for client ' . $clientId . ': ' . $e->getMessage());
                    }
                }
            }
            $clientProfiles[] = $profile;
        }

        View::render('clients/view.twig', [
            'client' => $clientData,
            'protocol_output' => $protocolOutput,
            'is_awg2' => $isAwg2,
            'client_endpoints' => $clientEndpoints,
            'client_profiles' => $clientProfiles,
            'selected_endpoint_pool_id' => $selectedEndpointPoolId,
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Client not found';
    }
});

// Download client config
Router::get('/clients/{id}/download', function ($params) {
    requireAuth();

    // Clean any output buffer to prevent header issues
    while (ob_get_level()) {
        ob_end_clean();
    }

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $config = $client->getConfig();
        $forceRefresh = isset($_GET['refresh']) && in_array(strtolower((string) $_GET['refresh']), ['1', 'true', 'yes'], true);

        // Fast path: downloads serve the persisted config. Regeneration is expensive
        // because it talks to the remote server; use ?refresh=1 or the API endpoint when needed.
        if ($forceRefresh || trim($config) === '') {
            try {
                $regen = $client->regenerateConfigFromServer(true);
                if (is_array($regen) && empty($regen['success']) && ($regen['error'] ?? '') === 'awg_params_missing') {
                    http_response_code(500);
                    echo 'AWG params are missing on server; cannot generate a valid config. Reinstall/repair AWG or check /opt/amnezia/awg/wg0.conf on the server.';
                    return;
                }
                $config = $client->getConfig();
            } catch (Throwable $e) {
                error_log('Failed to regenerate client config: ' . $e->getMessage());
            }
        }

        if (trim($config) === '') {
            http_response_code(500);
            echo 'Client config is empty. Try regenerating the config first.';
            return;
        }

        // A linked pool has the same AWG identity and peers but another direct
        // endpoint. Generate a variant by changing only Endpoint; client keys,
        // address and obfuscation parameters remain byte-for-byte identical.
        $targetPoolId = (int) ($_GET['pool_id'] ?? 0);
        $targetPoolName = '';
        if ($targetPoolId > 0) {
            $serverData = (new VpnServer((int) $clientData['server_id']))->getData();
            $homePoolId = (int) ($serverData['pool_id'] ?? 0);
            if ($homePoolId <= 0 || !in_array($targetPoolId, ServerPool::peerGroupPoolIds($homePoolId), true)) {
                http_response_code(400);
                echo 'Target pool does not share this client identity.';
                return;
            }
            $targetPool = ServerPool::get($targetPoolId);
            $targetDomain = trim((string) ($targetPool['domain'] ?? ''));
            if (!$targetPool || $targetDomain === '') {
                http_response_code(400);
                echo 'Target pool has no domain.';
                return;
            }
            // Linked-pool downloads only replace Endpoint. Keep the protocol
            // generation's listener: legacy AWG 2.0 is on vpn_port (443), while
            // AWG 3.1 is deliberately isolated on awg31_port (444) because a
            // HeaderProtectionKey cannot share the legacy interface.
            $targetPort = ServerPool::endpointPort(
                $targetPool,
                (string) ($clientData['awg_version'] ?? '2.0')
            );
            $endpoint = $targetDomain . ':' . $targetPort;
            $replaced = 0;
            $config = preg_replace_callback('/^(\s*Endpoint\s*=\s*).+$/mi', static function ($m) use ($endpoint) {
                return $m[1] . $endpoint;
            }, $config, 1, $replaced);
            if ($replaced !== 1) {
                http_response_code(500);
                echo 'Endpoint line was not found in the client config.';
                return;
            }
            $targetPoolName = (string) $targetPool['name'];
        }

        // Use login if available, fallback to name
        $baseName = !empty($clientData['login']) ? $clientData['login'] : $clientData['name'];

        // Sanitize filename: remove non-safe characters
        $safeName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $baseName);

        // If sanitization resulted in empty string, use fallback
        if (empty($safeName)) {
            $safeName = 'user_' . $clientData['id'] . '_s' . $clientData['server_id'];
        }

        $suffix = $targetPoolName !== '' ? '-' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $targetPoolName) : '';
        $filename = $safeName . $suffix . '.conf';

        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($config));
        echo $config;
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Client not found';
    }
});

// Debug: one-shot AWG advanced smoke test (requires session auth)
// Usage example (while logged in): /debug/awg-smoke?server_id=5&client_name=olegnew14&duration_seconds=10
Router::get('/debug/awg-smoke', function () {
    requireDebugEnabledOrAdmin();
    header('Content-Type: application/json');

    $serverId = (int) ($_GET['server_id'] ?? 0);
    $clientId = (int) ($_GET['client_id'] ?? 0);
    $clientName = trim((string) ($_GET['client_name'] ?? ''));
    $duration = (int) ($_GET['duration_seconds'] ?? 10);
    if ($duration < 0)
        $duration = 0;
    if ($duration > 30)
        $duration = 30;

    if ($serverId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'server_id is required']);
        return;
    }
    if ($clientId <= 0 && $clientName === '') {
        http_response_code(400);
        echo json_encode(['error' => 'client_id or client_name is required']);
        return;
    }

    try {
        $user = Auth::user();

        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        if (!$serverData) {
            http_response_code(404);
            echo json_encode(['error' => 'Server not found']);
            return;
        }
        if (($serverData['user_id'] ?? null) != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($clientId <= 0) {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND name = ? ORDER BY id DESC LIMIT 1');
            $stmt->execute([$serverId, $clientName]);
            $clientId = (int) $stmt->fetchColumn();
        }

        if ($clientId <= 0) {
            http_response_code(404);
            echo json_encode(['error' => 'Client not found']);
            return;
        }

        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        if (!$clientData) {
            http_response_code(404);
            echo json_encode(['error' => 'Client not found']);
            return;
        }
        if (($clientData['user_id'] ?? null) != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        // Regenerate config from live server state (critical after reinstall)
        $regen = $client->regenerateConfigFromServer(true);

        $server->refresh();
        $serverData = $server->getData();

        $containerName = $serverData['container_name'] ?? 'amnezia-awg';
        $vpnPort = (int) ($serverData['vpn_port'] ?? 0);

        $cmdShow = sprintf('docker exec %s wg show wg0 2>/dev/null || true', escapeshellarg($containerName));
        $cmdDump = sprintf('docker exec %s wg show wg0 dump 2>/dev/null || true', escapeshellarg($containerName));
        $cmdAwgConfParams = sprintf(
            'docker exec %s sh -c "grep -E \"^[[:space:]]*(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4)[[:space:]]*=\" /opt/amnezia/awg/wg0.conf 2>/dev/null || true"',
            escapeshellarg($containerName)
        );
        $cmdListen = $vpnPort > 0
            ? sprintf('docker exec %s sh -c "ss -lunp 2>/dev/null | grep -E \"[:.]%d\\b\" || true"', escapeshellarg($containerName), $vpnPort)
            : '';

        // Host-level checks (outside container)
        // Use sed (not awk) to avoid shell-quoting pitfalls.
        $cmdHostIps = 'sh -c "ip -4 -o addr show scope global 2>/dev/null | sed -E \"s/^[0-9]+: ([^ ]+) +inet ([0-9\\./]+).*/\\1 \\2/\" || true"';
        $cmdDockerPort = $vpnPort > 0
            ? sprintf('sh -c "docker port %s %d/udp 2>/dev/null || true"', escapeshellarg($containerName), $vpnPort)
            : sprintf('sh -c "docker port %s 2>/dev/null || true"', escapeshellarg($containerName));
        $cmdHostSs = $vpnPort > 0
            ? sprintf('sh -c "ss -lunp 2>/dev/null | grep -E \"[:.]%d\\b\" || true"', $vpnPort)
            : 'sh -c "ss -lunp 2>/dev/null || true"';
        $cmdNftFiltered = $vpnPort > 0
            ? sprintf('sh -c "nft list ruleset 2>/dev/null | grep -E \"(dport|udp).*(%d)\" | head -200 || true"', $vpnPort)
            : 'sh -c "nft list ruleset 2>/dev/null | head -200 || true"';
        $cmdIptFiltered = $vpnPort > 0
            ? sprintf('sh -c "iptables -vnL 2>/dev/null | grep -E \"(udp|%d)\" | head -200 || true"', $vpnPort)
            : 'sh -c "iptables -vnL 2>/dev/null | head -200 || true"';

        // BEFORE snapshots
        $wgShowBefore = (string) $server->executeCommand($cmdShow, true);
        $wgDumpBefore = (string) $server->executeCommand($cmdDump, true);
        $awgConfLines = (string) $server->executeCommand($cmdAwgConfParams, true);
        $listenLines = $cmdListen !== '' ? (string) $server->executeCommand($cmdListen, true) : '';
        $hostIps = (string) $server->executeCommand($cmdHostIps, true);
        $dockerPort = (string) $server->executeCommand($cmdDockerPort, true);
        $hostSsBefore = (string) $server->executeCommand($cmdHostSs, true);
        $nftBefore = (string) $server->executeCommand($cmdNftFiltered, true);
        $iptablesBefore = (string) $server->executeCommand($cmdIptFiltered, true);

        // Extract this peer line from dump (before)
        $peerLineBefore = '';
        foreach (preg_split('/\r?\n/', trim($wgDumpBefore)) as $ln) {
            if ($ln !== '' && strpos($ln, ($clientData['public_key'] ?? '') . "\t") === 0) {
                $peerLineBefore = $ln;
                break;
            }
        }

        if ($duration > 0) {
            sleep($duration);
        }

        // AFTER snapshots
        $wgShowAfter = (string) $server->executeCommand($cmdShow, true);
        $wgDumpAfter = (string) $server->executeCommand($cmdDump, true);
        $hostSsAfter = (string) $server->executeCommand($cmdHostSs, true);
        $nftAfter = (string) $server->executeCommand($cmdNftFiltered, true);
        $iptablesAfter = (string) $server->executeCommand($cmdIptFiltered, true);

        // Parse firewall counters for this UDP port (best-effort)
        $nftPacketsBefore = null;
        $nftBytesBefore = null;
        if ($vpnPort > 0 && preg_match('/udp dport\s+' . preg_quote((string) $vpnPort, '/') . '\s+counter\s+packets\s+(\d+)\s+bytes\s+(\d+)/', $nftBefore, $m)) {
            $nftPacketsBefore = (int) $m[1];
            $nftBytesBefore = (int) $m[2];
        }
        $nftPacketsAfter = null;
        $nftBytesAfter = null;
        if ($vpnPort > 0 && preg_match('/udp dport\s+' . preg_quote((string) $vpnPort, '/') . '\s+counter\s+packets\s+(\d+)\s+bytes\s+(\d+)/', $nftAfter, $m)) {
            $nftPacketsAfter = (int) $m[1];
            $nftBytesAfter = (int) $m[2];
        }

        $iptPacketsBefore = null;
        $iptBytesBefore = null;
        if (preg_match('/^\s*(\d+)\s+(\d+)\s+ACCEPT\b/m', $iptablesBefore, $m)) {
            $iptPacketsBefore = (int) $m[1];
            $iptBytesBefore = (int) $m[2];
        }
        $iptPacketsAfter = null;
        $iptBytesAfter = null;
        if (preg_match('/^\s*(\d+)\s+(\d+)\s+ACCEPT\b/m', $iptablesAfter, $m)) {
            $iptPacketsAfter = (int) $m[1];
            $iptBytesAfter = (int) $m[2];
        }

        // Extract this peer line from dump (after)
        $peerLineAfter = '';
        foreach (preg_split('/\r?\n/', trim($wgDumpAfter)) as $ln) {
            if ($ln !== '' && strpos($ln, ($clientData['public_key'] ?? '') . "\t") === 0) {
                $peerLineAfter = $ln;
                break;
            }
        }

        // Compare PSK in client config vs wg dump (redacted)
        $configText = $client->getConfig();
        $configPsk = '';
        if (preg_match('/^PresharedKey\s*=\s*(\S+)/mi', $configText, $m)) {
            $configPsk = (string) $m[1];
        }
        $dumpPskAfter = '';
        if ($peerLineAfter !== '') {
            $parts = explode("\t", $peerLineAfter);
            if (count($parts) >= 2) {
                $dumpPskAfter = (string) $parts[1];
            }
        }
        $pskMatches = ($configPsk !== '' && $dumpPskAfter !== '' && $configPsk === $dumpPskAfter);

        echo json_encode([
            'success' => true,
            'server' => [
                'id' => (int) $serverId,
                'host' => (string) ($serverData['host'] ?? ''),
                'container_name' => (string) $containerName,
                'vpn_port' => $vpnPort,
                'awg_params_db' => json_decode($serverData['awg_params'] ?? '{}', true),
            ],
            'client' => [
                'id' => (int) $clientId,
                'name' => (string) ($clientData['name'] ?? ''),
                'public_key' => (string) ($clientData['public_key'] ?? ''),
                'client_ip' => (string) ($clientData['client_ip'] ?? ''),
            ],
            'regen' => $regen,
            'awg_conf_param_lines' => $awgConfLines,
            'container_listen' => $listenLines,
            'host_global_ips' => $hostIps,
            'docker_port_publish' => $dockerPort,
            'host_ss_udp_before' => $hostSsBefore,
            'host_ss_udp_after' => $hostSsAfter,
            'nft_filtered_before' => $nftBefore,
            'nft_filtered_after' => $nftAfter,
            'iptables_filtered_before' => $iptablesBefore,
            'iptables_filtered_after' => $iptablesAfter,
            'nft_counter_packets_before' => $nftPacketsBefore,
            'nft_counter_packets_after' => $nftPacketsAfter,
            'nft_counter_packets_delta' => ($nftPacketsBefore !== null && $nftPacketsAfter !== null) ? ($nftPacketsAfter - $nftPacketsBefore) : null,
            'nft_counter_bytes_before' => $nftBytesBefore,
            'nft_counter_bytes_after' => $nftBytesAfter,
            'nft_counter_bytes_delta' => ($nftBytesBefore !== null && $nftBytesAfter !== null) ? ($nftBytesAfter - $nftBytesBefore) : null,
            'iptables_counter_packets_before' => $iptPacketsBefore,
            'iptables_counter_packets_after' => $iptPacketsAfter,
            'iptables_counter_packets_delta' => ($iptPacketsBefore !== null && $iptPacketsAfter !== null) ? ($iptPacketsAfter - $iptPacketsBefore) : null,
            'iptables_counter_bytes_before' => $iptBytesBefore,
            'iptables_counter_bytes_after' => $iptBytesAfter,
            'iptables_counter_bytes_delta' => ($iptBytesBefore !== null && $iptBytesAfter !== null) ? ($iptBytesAfter - $iptBytesBefore) : null,
            'peer_dump_line_before' => $peerLineBefore,
            'peer_dump_line_after' => $peerLineAfter,
            'psk_match' => $pskMatches,
            'client_config_psk_prefix' => $configPsk !== '' ? substr($configPsk, 0, 8) : '',
            'dump_psk_prefix' => $dumpPskAfter !== '' ? substr($dumpPskAfter, 0, 8) : '',
            'wg_show_before' => $wgShowBefore,
            'wg_dump_before' => $wgDumpBefore,
            'wg_show_after' => $wgShowAfter,
            'wg_dump_after' => $wgDumpAfter,
            'duration_seconds' => $duration,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Revoke client access
Router::post('/clients/{id}/revoke', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        if ($client->revoke()) {
            redirect('/clients?server_id=' . $clientData['server_id'] . '&success=Client+revoked');
        } else {
            redirect('/clients?server_id=' . $clientData['server_id'] . '&error=Failed+to+revoke+client');
        }
    } catch (Exception $e) {
        redirect('/clients?error=' . urlencode($e->getMessage()));
    }
});

// Restore client access
Router::post('/clients/{id}/restore', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        if ($client->restore()) {
            redirect('/clients?server_id=' . $clientData['server_id'] . '&success=Client+restored');
        } else {
            redirect('/clients?server_id=' . $clientData['server_id'] . '&error=Failed+to+restore+client');
        }
    } catch (Exception $e) {
        redirect('/clients?error=' . urlencode($e->getMessage()));
    }
});

// Delete client
Router::post('/clients/{id}/delete', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $serverId = $clientData['server_id'];

        if ($client->delete()) {
            redirect('/clients?server_id=' . $serverId . '&success=Client+deleted');
        } else {
            redirect('/clients?server_id=' . $serverId . '&error=Failed+to+delete+client');
        }
    } catch (Exception $e) {
        redirect('/clients?error=' . urlencode($e->getMessage()));
    }
});

// Set client expiration (web session auth)
Router::post('/clients/{id}/set-expiration', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $clientId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $expiresAt = $data['expires_at'] ?? null;

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Forbidden']);
            return;
        }

        VpnClient::setExpiration($clientId, $expiresAt);
        echo json_encode(['success' => true, 'expires_at' => $expiresAt]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Set client traffic limit (web session auth)
Router::post('/clients/{id}/set-traffic-limit', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $clientId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $limitBytes = isset($data['traffic_limit']) ? (int) $data['traffic_limit'] : null;

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Forbidden']);
            return;
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET traffic_limit = ? WHERE id = ?');
        $stmt->execute([$limitBytes, $clientId]);
        echo json_encode(['success' => true, 'traffic_limit' => $limitBytes]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});
