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

// AI ASSISTANT ROUTES
Router::post('/api/ai/assist', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/AIController.php';
    $controller = new AIController();
    $controller->assist();
});

Router::get('/api/ai/models', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/AIController.php';
    $controller = new AIController();
    $controller->getModels();
});

Router::post('/api/ai/test-model', function () {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/AIController.php';
    $controller = new AIController();
    $controller->testModel();
});

Router::get('/api/protocols/{id}/ai-history', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/AIController.php';
    $controller = new AIController();
    $controller->getGenerationHistory((int) $params['id']);
});

Router::post('/api/ai/generations/{id}/apply', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/AIController.php';
    $controller = new AIController();
    $controller->applyGeneration((int) $params['id']);
});

Router::get('/ai/preview/{id}', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../../controllers/AIController.php';
    $controller = new AIController();
    $controller->previewGeneration((int) $params['id']);
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

// LDAP settings page
Router::get('/settings/ldap', function () {
    requireAdmin();
    redirect('/settings#ldap');
});

// Save LDAP settings
Router::post('/settings/ldap/save', function () {
    requireAdmin();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    require_once __DIR__ . '/../../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->saveLdapSettings();
});

// Test LDAP connection
Router::post('/settings/ldap/test', function () {
    requireAdmin();

    require_once __DIR__ . '/../../controllers/SettingsController.php';
    require_once __DIR__ . '/../../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->testLdapConnection();
});

/**
 * LANGUAGE ROUTES
 */

// Change language
Router::post('/language/change', function () {
    $lang = $_POST['language'] ?? '';

    if (Translator::setLanguage($lang)) {
        $_SESSION['success'] = 'Language changed successfully';
    } else {
        $_SESSION['error'] = 'Invalid language';
    }

    $redirect = $_POST['redirect'] ?? '/dashboard';
    redirect($redirect);
});

Router::get('/language/change', function () {
    redirect('/dashboard');
});

// API: Get translation statistics
Router::get('/api/translations/stats', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $stats = Translator::getStatistics();
    echo json_encode(['stats' => $stats]);
});

// API: Auto-translate missing keys
Router::post('/api/translations/auto-translate', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $targetLang = $data['language'] ?? '';

    if (empty($targetLang)) {
        http_response_code(400);
        echo json_encode(['error' => 'Language is required']);
        return;
    }

    try {
        $stats = Translator::translateMissingKeys($targetLang);
        echo json_encode([
            'success' => true,
            'stats' => $stats
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Export translations
Router::get('/api/translations/export/{lang}', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $lang = $params['lang'];

    try {
        $json = Translator::exportToJson($lang);
        header('Content-Disposition: attachment; filename="translations_' . $lang . '.json"');
        echo $json;
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// ===== Scenario Management Routes (Admin Only) =====

// List scenarios
Router::get('/admin/scenarios', function () {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->listScenarios();
});

// Create scenario form
Router::get('/admin/scenario/create', function () {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->createScenarioForm();
});

// View scenario
Router::get('/admin/scenario/{id}', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->viewScenario((int) $params['id']);
});

// Edit scenario form
Router::get('/admin/scenario/{id}/edit', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->editScenarioForm((int) $params['id']);
});

// Save scenario (create/update)
Router::post('/admin/scenario', function () {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->saveScenario();
});

// Delete scenario
Router::post('/admin/scenario/{id}/delete', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->deleteScenario((int) $params['id']);
});

// Test scenario
Router::post('/admin/scenario/{id}/test', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->testScenario((int) $params['id']);
});

// Export scenario
Router::get('/admin/scenario/{id}/export', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->exportScenario((int) $params['id']);
});

// Import scenario
Router::post('/admin/scenario/import', function () {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->importScenario();
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

