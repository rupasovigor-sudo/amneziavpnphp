<?php
/**
 * Route module — required from public/index.php after the bootstrap
 * (global helpers, Config/Auth/View init). Uses the global helper functions
 * and Router:: registered there; registration order across modules is
 * preserved by the require order in index.php.
 */

// API: Create client
Router::post('/api/clients/create', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $serverId = (int) ($data['server_id'] ?? 0);
    $name = trim($data['name'] ?? '');
    $expiresInDays = isset($data['expires_in_days']) ? (int) $data['expires_in_days'] : null;
    $protocolId = isset($data['protocol_id']) ? (int) $data['protocol_id'] : null;
    $username = isset($data['username']) ? trim((string) $data['username']) : null;
    $login = isset($data['login']) ? trim((string) $data['login']) : null;

    if ($serverId <= 0 || empty($name)) {
        http_response_code(400);
        echo json_encode(['error' => 'server_id and name are required']);
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        if (($serverData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        // Validate protocol_id is installed on server (if provided)
        if ($protocolId !== null && $protocolId > 0) {
            $pdo = DB::conn();
            $chk = $pdo->prepare('SELECT 1 FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
            $chk->execute([$serverId, $protocolId]);
            if (!$chk->fetchColumn()) {
                http_response_code(400);
                echo json_encode(['error' => 'protocol_id is not installed on this server']);
                return;
            }
        } else {
            $protocolId = null;
        }

        $clientId = VpnClient::create($serverId, (int) $user['id'], $name, $expiresInDays, $protocolId, $username, $login);

        $client = new VpnClient($clientId);

        // For WireGuard/AWG protocols, immediately regenerate config from live server state
        // (AWG junk params + keys can change after reinstall/recreate).
        // For amnezia-wg-advanced, fail fast if we can't obtain AWG params.
        try {
            $regen = $client->regenerateConfigFromServer(true);
            if (is_array($regen) && empty($regen['success']) && ($regen['error'] ?? '') === 'awg_params_missing') {
                http_response_code(500);
                echo json_encode([
                    'error' => 'Failed to generate AWG-Advanced config: missing server AWG params',
                    'result' => $regen,
                ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
                return;
            }
        } catch (Throwable $e) {
            error_log('Failed to regenerate config after create: ' . $e->getMessage());
        }

        $clientData = $client->getData();

        // Return client data with config and QR code
        echo json_encode([
            'success' => true,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'expires_at' => $clientData['expires_at'],
                'created_at' => $clientData['created_at'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Force-regenerate client config/QR from current server state (WireGuard/AWG)
Router::post('/api/clients/{id}/regenerate-config', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) ($params['id'] ?? 0);
    if ($clientId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid client id']);
        return;
    }

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if (($clientData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $result = $client->regenerateConfigFromServer(true);
        $clientData = $client->getData();

        echo json_encode([
            'success' => !empty($result['success']),
            'result' => $result,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ],
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Set client expiration
Router::post('/api/clients/{id}/set-expiration', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $expiresAt = $data['expires_at'] ?? null; // Y-m-d H:i:s format or null

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        VpnClient::setExpiration($clientId, $expiresAt);

        echo json_encode([
            'success' => true,
            'expires_at' => $expiresAt
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Extend client expiration
Router::post('/api/clients/{id}/extend', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $days = (int) ($data['days'] ?? 30);

    if ($days <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'days must be positive']);
        return;
    }

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        VpnClient::extendExpiration($clientId, $days);

        // Get updated expiration
        $client = new VpnClient($clientId);
        $updated = $client->getData();

        echo json_encode([
            'success' => true,
            'expires_at' => $updated['expires_at'],
            'extended_days' => $days
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Get expiring clients
Router::get('/api/clients/expiring', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $days = (int) ($_GET['days'] ?? 7);

    try {
        $clients = VpnClient::getExpiringClients($days);

        // Filter by user if not admin
        if ($user['role'] !== 'admin') {
            $clients = array_filter($clients, function ($c) use ($user) {
                return $c['user_id'] == $user['id'];
            });
        }

        echo json_encode([
            'success' => true,
            'clients' => array_values($clients),
            'count' => count($clients)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Set client traffic limit
Router::post('/api/clients/{id}/set-traffic-limit', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    // limit_bytes can be null (unlimited) or positive integer
    $limitBytes = isset($data['limit_bytes']) ? (int) $data['limit_bytes'] : null;

    if ($limitBytes !== null && $limitBytes < 0) {
        http_response_code(400);
        echo json_encode(['error' => 'limit_bytes must be positive or null for unlimited']);
        return;
    }

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $client->setTrafficLimit($limitBytes);

        echo json_encode([
            'success' => true,
            'limit_bytes' => $limitBytes,
            'limit_gb' => $limitBytes ? round($limitBytes / 1073741824, 2) : null
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Check client traffic limit status
Router::get('/api/clients/{id}/traffic-limit-status', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $status = $client->getTrafficLimitStatus();

        echo json_encode([
            'success' => true,
            'status' => $status
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Get clients over traffic limit
Router::get('/api/clients/overlimit', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    try {
        $clients = VpnClient::getClientsOverLimit();

        // Filter by user if not admin
        if ($user['role'] !== 'admin') {
            $clients = array_filter($clients, function ($c) use ($user) {
                return $c['user_id'] == $user['id'];
            });
        }

        echo json_encode([
            'success' => true,
            'clients' => array_values($clients),
            'count' => count($clients)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

/**
 * SETTINGS ROUTES
 */

// Settings page
Router::get('/settings', function () {
    requireAuth();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->index();
});

// Consolidated pool health dashboard (admin-only). Built on ServerPool::status,
// which returns already-redacted data (no keys/PSK).
Router::get('/pools', function () {
    requireAdmin();
    $pools = [];
    foreach (ServerPool::list() as $row) {
        $st = ServerPool::status((int) $row['id']);
        if ($st) {
            $pools[] = $st;
        }
    }
    $fronts = [];
    foreach ($pools as $p) {
        $pid = (int) $p['pool']['id'];
        $fronts[$pid] = PoolFront::uiStatus($pid);
    }
    View::render('pools.twig', [
        'pools' => $pools,
        'fronts' => $fronts,
        'reputation' => IpReputation::latestByServer(),
    ]);
});

// ---- Pool front (entry relay) API (admin, JSON) ----------------------------
function poolFrontJson(callable $fn): void
{
    requireAdmin();
    session_write_close(); // front install / member-wide applies take a while
    header('Content-Type: application/json');
    try {
        $in = json_decode(file_get_contents('php://input'), true) ?: [];
        $res = $fn($in);
        if (empty($res['success'])) {
            http_response_code(400);
        }
        echo json_encode($res, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
}

Router::post('/pools/{id}/front/register', function ($params) {
    @set_time_limit(420);
    @ignore_user_abort(true); // apt install on the front can take minutes
    poolFrontJson(fn($in) => PoolFront::register((int) $params['id'], (int) (Auth::user()['id'] ?? 0), $in));
});
Router::post('/pools/{id}/front/sync', function ($params) {
    poolFrontJson(fn($in) => PoolFront::sync((int) $params['id'], true));
});
Router::post('/pools/{id}/front/detect', function ($params) {
    @set_time_limit(180);
    poolFrontJson(function ($in) use ($params) {
        $det = PoolFront::detectAll((int) $params['id']);
        $sync = PoolFront::sync((int) $params['id'], true);
        $parts = [];
        foreach ($det as $sid => $d) {
            $parts[] = "#{$sid}: " . ($d['country'] ?? '?');
        }
        return ['success' => true, 'message' => 'Страны выхода: ' . implode(', ', $parts) . '. ' . ($sync['message'] ?? '')];
    });
});
Router::post('/pools/{id}/front/domain', function ($params) {
    poolFrontJson(fn($in) => ($in['target'] ?? '') === 'front'
        ? PoolFront::pointDomainToFront((int) $params['id'])
        : PoolFront::pointDomainToMember((int) $params['id'], 'manual_ui'));
});
Router::post('/pools/{id}/front/country', function ($params) {
    poolFrontJson(fn($in) => PoolFront::setPrimaryCountry((int) $params['id'], (string) ($in['country'] ?? '')));
});
Router::post('/pools/{id}/front/group', function ($params) {
    poolFrontJson(fn($in) => PoolFront::setRelayGroup((int) ($in['server_id'] ?? 0), (string) ($in['group'] ?? '')));
});
Router::post('/pools/{id}/front/reinstall', function ($params) {
    @set_time_limit(420);
    poolFrontJson(function ($in) use ($params) {
        $f = PoolFront::forPool((int) $params['id']);
        if (!$f) {
            return ['success' => false, 'message' => 'Фронт не подключён'];
        }
        $r = PoolFront::install((int) $f['server_id']);
        if (!empty($r['success'])) {
            PoolFront::sync((int) $params['id'], true);
        }
        return $r;
    });
});
// End-to-end check from Russia, on demand (no auto-rotation from the UI).
Router::post('/pools/{id}/front/e2e', function ($params) {
    @set_time_limit(120);
    poolFrontJson(function () use ($params) {
        $r = FrontProbe::checkPool((int) $params['id'], false);
        return ['success' => !empty($r['ok']), 'message' => 'Синтетический тест AWG 2.0: ' . ($r['message'] ?? '')];
    });
});

Router::post('/pools/{id}/front/auto-port', function ($params) {
    poolFrontJson(function ($in) use ($params) {
        $front = PoolFront::forPool((int) $params['id']);
        if (!$front) {
            return ['success' => false, 'message' => 'Фронт не подключён'];
        }
        $on = !empty($in['enabled']) ? 1 : 0;
        DB::conn()->prepare('UPDATE pool_fronts SET auto_port = ? WHERE id = ?')->execute([$on, (int) $front['id']]);
        return ['success' => true, 'message' => $on ? 'Автосмена порта включена' : 'Автосмена порта выключена'];
    });
});

Router::post('/pools/{id}/front/backend-port', function ($params) {
    @set_time_limit(180);
    ignore_user_abort(true);
    poolFrontJson(function ($in) use ($params) {
        $raw = trim((string) ($in['port'] ?? ''));
        return PoolFront::setBackendPort((int) $params['id'], $raw === '' ? null : (int) $raw);
    });
});

Router::post('/pools/{id}/front/front-only', function ($params) {
    @set_time_limit(180);
    ignore_user_abort(true);
    poolFrontJson(fn($in) => PoolFront::setFrontOnly((int) $params['id'], !empty($in['enabled'])));
});

// Live clients of the pool: through the front vs connected directly (AJAX).
Router::get('/pools/{id}/front/clients', function ($params) {
    requireAdmin();
    session_write_close();
    header('Content-Type: application/json');
    try {
        echo json_encode(['success' => true] + PoolFront::clientPaths((int) $params['id']), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
});

Router::post('/pools/{id}/front/remove', function ($params) {
    poolFrontJson(fn($in) => PoolFront::remove((int) $params['id']));
});

// Router AllowedIPs for a pool: full tunnel minus every member's (and the
// front's) ingress IP plus caller-supplied local exclusions, so a router config
// survives an in-pool failover. (AJAX, admin)
Router::get('/pools/{id}/allowed-ips', function ($params) {
    requireAdmin();
    header('Content-Type: application/json');
    $poolId = (int) $params['id'];
    try {
        if (!ServerPool::get($poolId)) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'Пул не найден'], JSON_UNESCAPED_UNICODE);
            return;
        }
        // Extra exclusions: split on commas, whitespace and newlines.
        $raw = is_string($_GET['exclude'] ?? null) ? $_GET['exclude'] : '';
        $extra = array_filter(array_map('trim', preg_split('/[,\s]+/', $raw) ?: []));
        echo json_encode(['success' => true] + ServerPool::allowedIpsExcludingPool($poolId, $extra), JSON_UNESCAPED_SLASHES);
    } catch (Throwable $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
});

// Pool egress: Google directly from each member's IP instead of WARP.
Router::post('/pools/{id}/warp-bypass', function ($params) {
    poolFrontJson(function ($in) use ($params) {
        $poolId = (int) $params['id'];
        if (!ServerPool::get($poolId)) {
            return ['success' => false, 'message' => 'Пул не найден'];
        }
        @set_time_limit(300);
        ignore_user_abort(true);
        $on = !empty($in['enabled']) ? 1 : 0;
        DB::conn()->prepare('UPDATE server_pools SET warp_bypass_google = ? WHERE id = ?')->execute([$on, $poolId]);
        $st = DB::conn()->prepare("SELECT id, name FROM vpn_servers WHERE pool_id = ? AND status = 'active' ORDER BY id");
        $st->execute([$poolId]);
        $lines = [];
        $allOk = true;
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $m) {
            $r = ServerUpdateManager::applyWarpSettings((int) $m['id']);
            $allOk = $allOk && !empty($r['success']);
            $lines[] = "{$m['name']}: " . ($r['message'] ?? '');
        }
        return [
            'success' => $allOk,
            'message' => ($on ? 'Google напрямую включён. ' : 'Google снова через WARP. ') . implode('; ', $lines),
        ];
    });
});

// Audit trail of state-changing admin actions (admin-only).
Router::get('/audit', function () {
    requireAdmin();
    $page = max(1, (int) ($_GET['page'] ?? 1));
    $perPage = 200;
    $entries = AuditLog::recent($perPage, ($page - 1) * $perPage);
    View::render('audit.twig', ['entries' => $entries, 'page' => $page, 'per_page' => $perPage]);
});

Router::get('/settings/protocols', function () {
    requireAdmin();
    $params = [];
    if (isset($_GET['id'])) {
        $params[] = 'id=' . urlencode($_GET['id']);
    }
    if (isset($_GET['new'])) {
        $params[] = 'new=1';
    }
    $query = empty($params) ? '' : ('?' . implode('&', $params));
    redirect('/settings' . $query . '#protocols');
});

// Legacy protocol routes removed in favor of ProtocolManagementController and /api/protocols endpoints

// NEW PROTOCOL MANAGEMENT ROUTES
Router::get('/settings/protocols-management', function () {
    requireAdmin();
    redirect('/settings#protocols');
});
Router::get('/settings/protocols/new', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $_GET['new'] = 1;
    $controller->index();
});

Router::get('/settings/protocols/{id}/edit', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $_GET['id'] = $params['id'];
    $controller->index();
});

Router::get('/settings/protocols/{id}/template', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    // This will render the template editor component
    $_GET['id'] = $params['id'];
    $_GET['template'] = 1;
    $controller->index();
});

// POST route to save/update protocol
Router::post('/settings/protocols/save', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->save();
});

// API ROUTES FOR PROTOCOLS
Router::get('/api/protocols', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiGetProtocols();
});

Router::get('/api/protocols/{id}', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiGetProtocol((int) $params['id']);
});

Router::post('/api/protocols', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiCreateProtocol();
});

Router::put('/api/protocols/{id}', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiUpdateProtocol((int) $params['id']);
});

Router::delete('/api/protocols/{id}', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiDeleteProtocol((int) $params['id']);
});

Router::post('/api/protocols/{id}/test-install', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiTestInstallProtocol((int) $params['id']);
});

Router::get('/api/protocols/{id}/test-install/stream', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiTestInstallProtocolStream((int) $params['id']);
});

Router::get('/api/protocols/{id}/test-uninstall/stream', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiTestUninstallProtocolStream((int) $params['id']);
});


// Save API key
Router::post('/settings/api-key', function () {
    requireAdmin();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->saveApiKey();
});

Router::post('/settings/alerts/save', function () {
    requireAdmin();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->saveAlerts();
});

Router::post('/settings/alerts/test', function () {
    requireAdmin();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->testAlerts();
});

// Change password
Router::post('/settings/change-password', function () {
    requireAuth();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->changePassword();
});

// Update profile
Router::post('/settings/profile', function () {
    requireAuth();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->updateProfile();
});

// Add user
Router::post('/settings/add-user', function () {
    requireAdmin();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->addUser();
});

// Delete user
Router::post('/settings/delete-user/{id}', function ($params) {
    requireAdmin();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->deleteUser($params['id']);
});


/**
 * LANGUAGE ROUTES
 */

// Change language
Router::post('/language/change', function () {
    requireAuth();
    $lang = $_POST['language'] ?? '';

    if (Translator::setLanguage($lang)) {
        $_SESSION['success'] = 'Language changed successfully';
    } else {
        $_SESSION['error'] = 'Invalid language';
    }

    // Only same-site paths: taking the target straight from POST turned this
    // into an open redirect — a link on the panel's own domain that lands the
    // victim on an attacker's page.
    $redirect = (string) ($_POST['redirect'] ?? '/dashboard');
    if ($redirect === '' || $redirect[0] !== '/' || str_starts_with($redirect, '//')) {
        $redirect = '/dashboard';
    }
    redirect($redirect);
});

Router::get('/language/change', function () {
    redirect('/dashboard');
});

// ===== Logs Management Routes (Admin Only) =====

// List and view logs
Router::get('/admin/logs', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->index();
});

// Download log file
Router::get('/admin/logs/download', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->download();
});

// Delete log file
Router::post('/admin/logs/delete', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->delete();
});

// Clear all logs
Router::post('/admin/logs/clear-all', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->clearAll();
});

// Search logs
Router::post('/admin/logs/search', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->search();
});

// Get log statistics
Router::post('/admin/logs/stats', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->stats();
});

