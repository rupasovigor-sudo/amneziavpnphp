<?php

class SettingsController {
    private $pdo;
    private $translator;
    
    public function __construct() {
        $this->pdo = DB::conn();
        $this->translator = new Translator();
    }
    
    public function index() {
        $users = $this->getAllUsers();
        $timewebKey = $this->getApiKey('timeweb');

        // Protocols data for embedded tab (new management)
        $protocols = ProtocolService::getAllProtocolsWithStats();
        $selectedId = isset($_GET['id']) ? (int)$_GET['id'] : null;
        $isNew = isset($_GET['new']);
        $editing = null;
        if (!$isNew) {
            if ($selectedId) {
                try {
                    $editing = ProtocolService::getProtocolWithDetails($selectedId);
                } catch (Exception $e) {
                    $editing = null;
                }
            }
            if (!$editing && !empty($protocols)) {
                $firstId = (int)($protocols[0]['id'] ?? 0);
                if ($firstId) {
                    try { $editing = ProtocolService::getProtocolWithDetails($firstId); } catch (Exception $e) { $editing = null; }
                }
            }
        }
        $definitionPretty = json_encode([], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $data = [
            'users' => $users,
            'timeweb_key' => $timewebKey,
            'alert_settings' => $this->getAlertSettings(),
            'alert_states' => $this->getAlertStates(),
            // Protocols
            'protocols' => $protocols,
            'editing' => $editing,
            'definition_json' => $definitionPretty,
            'is_new' => $isNew,
            'default_slug' => isset($editing['slug']) ? $editing['slug'] : (isset($protocols[0]['slug']) ? $protocols[0]['slug'] : 'awg2'),
        ];
        
        // Check for session messages
        if (isset($_SESSION['settings_success'])) {
            $data['success'] = $_SESSION['settings_success'];
            unset($_SESSION['settings_success']);
        }
        if (isset($_SESSION['settings_error'])) {
            $data['error'] = $_SESSION['settings_error'];
            unset($_SESSION['settings_error']);
        }
        // Also pick up protocol messages if present
        if (isset($_SESSION['protocol_success']) && !isset($data['success'])) {
            $data['success'] = $_SESSION['protocol_success'];
            unset($_SESSION['protocol_success']);
        }
        if (isset($_SESSION['protocol_error']) && !isset($data['error'])) {
            $data['error'] = $_SESSION['protocol_error'];
            unset($_SESSION['protocol_error']);
        }
        
        View::render('settings.twig', $data);
    }
    
    public function changePassword() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /settings');
            exit;
        }
        
        $user = Auth::user();
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
            $_SESSION['settings_error'] = 'All fields are required';
            header('Location: /settings#profile');
            exit;
        }
        
        if ($newPassword !== $confirmPassword) {
            $_SESSION['settings_error'] = 'New passwords do not match';
            header('Location: /settings#profile');
            exit;
        }
        
        if (strlen($newPassword) < 6) {
            $_SESSION['settings_error'] = 'Password must be at least 6 characters';
            header('Location: /settings#profile');
            exit;
        }
        
        // Verify current password
        if (!password_verify($currentPassword, $user['password_hash'])) {
            $_SESSION['settings_error'] = 'Current password is incorrect';
            header('Location: /settings#profile');
            exit;
        }
        
        // Update password
        $newHash = password_hash($newPassword, PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $stmt->execute([$newHash, $user['id']]);
        
        $_SESSION['settings_success'] = 'Password changed successfully';
        header('Location: /settings#profile');
        exit;
    }
    
    public function updateProfile() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /settings');
            exit;
        }
        
        $user = Auth::user();
        $displayName = trim($_POST['display_name'] ?? '');
        
        if ($displayName === '') {
            $_SESSION['settings_error'] = 'Display name cannot be empty';
            header('Location: /settings#profile');
            exit;
        }
        
        $stmt = $this->pdo->prepare("UPDATE users SET display_name = ? WHERE id = ?");
        $stmt->execute([$displayName, $user['id']]);
        
        $_SESSION['settings_success'] = 'Profile updated';
        header('Location: /settings#profile');
        exit;
    }
    
    public function addUser() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /settings');
            exit;
        }
        
        $user = Auth::user();
        if ($user['role'] !== 'admin') {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? 'user';
        
        if (empty($name) || empty($email) || empty($password)) {
            $_SESSION['settings_error'] = 'All fields are required';
            header('Location: /settings#users');
            exit;
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $_SESSION['settings_error'] = 'Invalid email address';
            header('Location: /settings#users');
            exit;
        }
        
        if (strlen($password) < 6) {
            $_SESSION['settings_error'] = 'Password must be at least 6 characters';
            header('Location: /settings#users');
            exit;
        }
        
        // Check if email already exists
        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $_SESSION['settings_error'] = 'Email already exists';
            header('Location: /settings#users');
            exit;
        }
        
        // Create user
        $passwordHash = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)");
        $stmt->execute([$name, $email, $passwordHash, $role]);
        
        $_SESSION['settings_success'] = 'User added successfully';
        header('Location: /settings#users');
        exit;
    }
    
    public function deleteUser($userId) {
        $user = Auth::user();
        if ($user['role'] !== 'admin') {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        if ($userId == $user['id']) {
            $_SESSION['settings_error'] = 'Cannot delete yourself';
            header('Location: /settings#users');
            exit;
        }
        
        $stmt = $this->pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        
        $_SESSION['settings_success'] = 'User deleted successfully';
        header('Location: /settings#users');
        exit;
    }
    
    private function getAllUsers() {
        $stmt = $this->pdo->query("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC");
        return $stmt->fetchAll();
    }
    
    private function getApiKey($service) {
        $stmt = $this->pdo->prepare("SELECT api_key FROM api_keys WHERE service_name = ? AND is_active = 1");
        $stmt->execute([$service]);
        $result = $stmt->fetch();
        return $result ? $result['api_key'] : null;
    }

    private function getAlertSettings(): array {
        $get = fn(string $key, string $default = '') => (string) Config::get($key, $default);

        return [
            'ALERTS_ENABLED' => $get('ALERTS_ENABLED', '0'),
            'ALERTS_FAILURE_THRESHOLD' => $get('ALERTS_FAILURE_THRESHOLD', '2'),
            'ALERT_RESOURCE_FAILURE_THRESHOLD' => $get('ALERT_RESOURCE_FAILURE_THRESHOLD', '5'),
            'ALERTS_COOLDOWN_SECONDS' => $get('ALERTS_COOLDOWN_SECONDS', '1800'),
            'ALERT_CPU_WARNING_PERCENT' => $get('ALERT_CPU_WARNING_PERCENT', '80'),
            'ALERT_CPU_CRITICAL_PERCENT' => $get('ALERT_CPU_CRITICAL_PERCENT', '95'),
            'ALERT_RAM_WARNING_PERCENT' => $get('ALERT_RAM_WARNING_PERCENT', '80'),
            'ALERT_RAM_CRITICAL_PERCENT' => $get('ALERT_RAM_CRITICAL_PERCENT', '95'),
            'ALERT_DISK_WARNING_PERCENT' => $get('ALERT_DISK_WARNING_PERCENT', '80'),
            'ALERT_DISK_CRITICAL_PERCENT' => $get('ALERT_DISK_CRITICAL_PERCENT', '90'),
            'ALERT_WATCHDOG_RESTART_LOOKBACK_SECONDS' => $get('ALERT_WATCHDOG_RESTART_LOOKBACK_SECONDS', '900'),
            'ALERT_HANDSHAKE_STALE_SECONDS' => $get('ALERT_HANDSHAKE_STALE_SECONDS', '1800'),
            'ALERT_HANDSHAKE_STALE_PERCENT' => $get('ALERT_HANDSHAKE_STALE_PERCENT', '70'),
            'ALERT_HANDSHAKE_MIN_PEERS' => $get('ALERT_HANDSHAKE_MIN_PEERS', '3'),
            'TELEGRAM_ALERTS_ENABLED' => $get('TELEGRAM_ALERTS_ENABLED', '0'),
            'TELEGRAM_CHAT_ID' => $get('TELEGRAM_CHAT_ID', ''),
            'telegram_token_set' => trim($get('TELEGRAM_BOT_TOKEN', '')) !== '',
            'EMAIL_ALERTS_ENABLED' => $get('EMAIL_ALERTS_ENABLED', '0'),
            'ALERT_EMAIL_TO' => $get('ALERT_EMAIL_TO', ''),
            'SMTP_HOST' => $get('SMTP_HOST', ''),
            'SMTP_PORT' => $get('SMTP_PORT', '587'),
            'SMTP_USERNAME' => $get('SMTP_USERNAME', ''),
            'SMTP_FROM' => $get('SMTP_FROM', ''),
            'SMTP_FROM_NAME' => $get('SMTP_FROM_NAME', 'Amnezia VPN Panel'),
            'SMTP_TLS' => $get('SMTP_TLS', '1'),
            'smtp_password_set' => trim($get('SMTP_PASSWORD', '')) !== '',
        ];
    }

    private function getAlertStates(): array {
        try {
            $stmt = $this->pdo->query("
                SELECT a.*, s.name AS server_name
                FROM alert_states a
                LEFT JOIN vpn_servers s ON s.id = a.server_id
                ORDER BY COALESCE(a.last_seen_at, a.first_seen_at, a.created_at) DESC
                LIMIT 50
            ");
            return $stmt->fetchAll();
        } catch (Throwable $e) {
            return [];
        }
    }

    public function saveAlerts(): void {
        $user = Auth::user();
        if (($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $envPath = __DIR__ . '/../.env';
        if (!is_file($envPath) || !is_writable($envPath)) {
            $_SESSION['settings_error'] = '.env недоступен для записи';
            header('Location: /settings#alerts');
            exit;
        }

        $checkboxKeys = [
            'ALERTS_ENABLED',
            'TELEGRAM_ALERTS_ENABLED',
            'EMAIL_ALERTS_ENABLED',
            'SMTP_TLS',
        ];
        $textKeys = [
            'ALERTS_FAILURE_THRESHOLD',
            'ALERT_RESOURCE_FAILURE_THRESHOLD',
            'ALERTS_COOLDOWN_SECONDS',
            'ALERT_CPU_WARNING_PERCENT',
            'ALERT_CPU_CRITICAL_PERCENT',
            'ALERT_RAM_WARNING_PERCENT',
            'ALERT_RAM_CRITICAL_PERCENT',
            'ALERT_DISK_WARNING_PERCENT',
            'ALERT_DISK_CRITICAL_PERCENT',
            'ALERT_WATCHDOG_RESTART_LOOKBACK_SECONDS',
            'ALERT_HANDSHAKE_STALE_SECONDS',
            'ALERT_HANDSHAKE_STALE_PERCENT',
            'ALERT_HANDSHAKE_MIN_PEERS',
            'TELEGRAM_CHAT_ID',
            'ALERT_EMAIL_TO',
            'SMTP_HOST',
            'SMTP_PORT',
            'SMTP_USERNAME',
            'SMTP_FROM',
            'SMTP_FROM_NAME',
        ];
        $secretKeys = [
            'TELEGRAM_BOT_TOKEN',
            'SMTP_PASSWORD',
        ];

        $updates = [];
        foreach ($checkboxKeys as $key) {
            $updates[$key] = isset($_POST[$key]) ? '1' : '0';
        }
        foreach ($textKeys as $key) {
            $updates[$key] = trim((string) ($_POST[$key] ?? ''));
        }
        foreach ($secretKeys as $key) {
            $value = trim((string) ($_POST[$key] ?? ''));
            if ($value !== '') {
                $updates[$key] = $value;
            }
        }

        try {
            $this->writeEnvValues($envPath, $updates);
            foreach ($updates as $key => $value) {
                @putenv($key . '=' . $value);
            }
            $this->restartMetricsCollector();
        } catch (Throwable $e) {
            $_SESSION['settings_error'] = $e->getMessage();
            header('Location: /settings#alerts');
            exit;
        }

        $_SESSION['settings_success'] = 'Настройки оповещений сохранены';
        header('Location: /settings#alerts');
        exit;
    }

    public function testAlerts(): void {
        header('Content-Type: application/json');

        $user = Auth::user();
        if (($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Forbidden']);
            return;
        }

        $payload = json_decode(file_get_contents('php://input'), true);
        $channel = is_array($payload) ? (string) ($payload['channel'] ?? 'all') : (string) ($_POST['channel'] ?? 'all');
        if (!in_array($channel, ['telegram', 'email', 'all'], true)) {
            $channel = 'all';
        }

        try {
            $alerts = new AlertManager($this->pdo);
            $ok = $alerts->sendTest($channel);
            echo json_encode([
                'success' => $ok,
                'message' => $ok ? 'Тестовое уведомление отправлено' : 'Не удалось отправить уведомление. Проверьте настройки канала.',
            ]);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    private function writeEnvValues(string $envPath, array $updates): void {
        $lines = file($envPath, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            throw new RuntimeException('Не удалось прочитать .env');
        }

        $seen = [];
        foreach ($lines as $i => $line) {
            if (!preg_match('/^([A-Z0-9_]+)=/', trim($line), $m)) {
                continue;
            }
            $key = $m[1];
            if (!array_key_exists($key, $updates)) {
                continue;
            }
            $lines[$i] = $key . '=' . $this->encodeEnvValue((string) $updates[$key]);
            $seen[$key] = true;
        }

        foreach ($updates as $key => $value) {
            if (!isset($seen[$key])) {
                $lines[] = $key . '=' . $this->encodeEnvValue((string) $value);
            }
        }

        $content = implode("\n", $lines) . "\n";
        if (file_put_contents($envPath, $content, LOCK_EX) === false) {
            throw new RuntimeException('Не удалось записать .env');
        }
    }

    private function encodeEnvValue(string $value): string {
        if ($value === '') {
            return '';
        }
        if (preg_match('/[\s#"\'\\\\]/', $value)) {
            return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
        }
        return $value;
    }

    private function restartMetricsCollector(): void {
        $monitorScript = realpath(__DIR__ . '/../bin/monitor_metrics.sh');
        if (!$monitorScript || !is_file($monitorScript)) {
            return;
        }

        $cmd = sprintf(
            '(pkill -f %s >/dev/null 2>&1 || true; sleep 1; bash %s >/dev/null 2>&1) &',
            escapeshellarg('^/usr/local/bin/php /var/www/html/bin/collect_metrics.php$'),
            escapeshellarg($monitorScript)
        );
        @exec($cmd);
    }
    
    public function saveApiKey() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /settings');
            exit;
        }
        
        $service = $_POST['service'] ?? '';
        $apiKey = trim($_POST['api_key'] ?? '');
        $skipTest = isset($_POST['skip_test']); // Allow saving without testing
        
        if (empty($service) || empty($apiKey)) {
            $_SESSION['settings_error'] = $this->translator->translate('settings.error_empty_key');
            header('Location: /settings#api');
            exit;
        }

        // Validate a DNS provider token against the provider API before saving,
        // so a broken token is caught here and not during a deploy.
        if ($service === DnsManager::provider()) {
            $testResult = DnsManager::verifyToken($apiKey);
            if (!$testResult['success']) {
                $_SESSION['settings_error'] = $testResult['message'];
                header('Location: /settings#api');
                exit;
            }
            $saved = $this->translator->saveApiKey($service, $apiKey);
            $_SESSION[$saved ? 'settings_success' : 'settings_error'] =
                $saved ? $testResult['message'] : $this->translator->translate('message.error');
            header('Location: /settings#api');
            exit;
        }

        // Save the key
        $saved = $this->translator->saveApiKey($service, $apiKey);

        if ($saved) {
            $_SESSION['settings_success'] = $this->translator->translate('settings.key_saved');
            header('Location: /settings#api');
            exit;
        } else {
            $_SESSION['settings_error'] = $this->translator->translate('message.error');
            header('Location: /settings#api');
            exit;
        }
    }
}
