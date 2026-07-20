<?php
/**
 * Amnezia VPN Web Panel
 * Main entry point
 */

// Suppress errors for API endpoints to prevent HTML output
if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/api/') !== false) {
    @ini_set('display_errors', '0');
    error_reporting(0);
}

// Load early dependencies/config before session initialization.
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../inc/Config.php';

// Load environment configuration
Config::load(__DIR__ . '/../.env');

// Work in UTC everywhere; the DB session is also pinned to UTC (inc/DB.php).
date_default_timezone_set('UTC');

$secureCookieRaw = Config::get('SESSION_COOKIE_SECURE');
$secureCookie = $secureCookieRaw === null
    ? ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'))
    : in_array(strtolower((string) $secureCookieRaw), ['1', 'true', 'yes', 'on'], true);

@ini_set('session.use_strict_mode', '1');
session_name(Config::get('SESSION_NAME', 'amnezia_panel_session'));
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $secureCookie,
    'httponly' => true,
    'samesite' => Config::get('SESSION_COOKIE_SAMESITE', 'Lax'),
]);
session_start();

// Security response headers. Sent early, before any output, so they apply to
// every response (HTML, JSON, downloads). CSP intentionally allows the CDNs and
// inline scripts the current UI depends on (Tailwind Play, Font Awesome, Chart.js,
// inline CSRF bootstrap, data: QR images); tightening to nonces is future work.
if (in_array(strtolower((string) Config::get('AMNEZIA_SECURITY_HEADERS', '1')), ['1', 'true', 'yes', 'on'], true)) {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header('Cross-Origin-Opener-Policy: same-origin');

    // HSTS only over HTTPS to avoid locking out plain-HTTP deployments.
    if (!empty($secureCookie)) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }

    if (in_array(strtolower((string) Config::get('AMNEZIA_CSP_ENABLED', '1')), ['1', 'true', 'yes', 'on'], true)) {
        header(
            "Content-Security-Policy: "
            . "default-src 'self'; "
            . "base-uri 'self'; "
            . "object-src 'none'; "
            . "frame-ancestors 'none'; "
            . "img-src 'self' data: blob:; "
            . "font-src 'self' https://cdnjs.cloudflare.com data:; "
            . "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
            . "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            . "connect-src 'self'; "
            . "form-action 'self'"
        );
    }
}

// Load dependencies
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/SecretBox.php';
require_once __DIR__ . '/../inc/Auth.php';
require_once __DIR__ . '/../inc/Router.php';
require_once __DIR__ . '/../inc/View.php';
require_once __DIR__ . '/../inc/VpnServer.php';
require_once __DIR__ . '/../inc/VpnClient.php';
require_once __DIR__ . '/../inc/Translator.php';
require_once __DIR__ . '/../inc/JWT.php';
require_once __DIR__ . '/../inc/ServerMonitoring.php';
require_once __DIR__ . '/../inc/AlertManager.php';
require_once __DIR__ . '/../inc/InstallProtocolManager.php';
require_once __DIR__ . '/../inc/ProtocolService.php';
require_once __DIR__ . '/../inc/TimewebDnsService.php';

// Test database connection
try {
    DB::conn();
} catch (Throwable $e) {
    die('Database connection error: ' . $e->getMessage());
}

// Seed admin user if not exists
try {
    $adminEmail = Config::get('ADMIN_EMAIL');
    $adminPass = Config::get('ADMIN_PASSWORD');
    if ($adminEmail && $adminPass) {
        Auth::seedAdmin($adminEmail, $adminPass);
    }
} catch (Throwable $e) {
    // Ignore errors
}

// Initialize translator
Translator::init();
InstallProtocolManager::ensureDefaults();

// Initialize template engine
$user = Auth::user();
$appName = Config::get('APP_NAME', 'Amnezia VPN Panel');

/**
 * Helper function to authenticate user from JWT or session
 * Returns user array or null if unauthorized
 */
function authenticateRequest(): ?array
{
    // Check JWT token in Authorization header
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        $token = $matches[1];
        $user = JWT::verify($token);
        if ($user) {
            return $user;
        }
    }

    // Fallback to session
    if (isset($_SESSION['user_id'])) {
        return Auth::user();
    }

    return null;
}

function jsonError(string $message, int $status = 400): void
{
    http_response_code($status);
    echo json_encode(['success' => false, 'error' => $message]);
}

function canAccessServer(array $serverData, array $user): bool
{
    return (int) ($serverData['user_id'] ?? 0) === (int) ($user['id'] ?? 0) || ($user['role'] ?? '') === 'admin';
}

function canAccessClient(array $clientData, array $user): bool
{
    return (int) ($clientData['user_id'] ?? 0) === (int) ($user['id'] ?? 0) || ($user['role'] ?? '') === 'admin';
}

function getClientProtocolSlug(array $clientData): string
{
    $protocolId = (int) ($clientData['protocol_id'] ?? 0);
    if ($protocolId <= 0) {
        return '';
    }

    $stmt = DB::conn()->prepare('SELECT slug FROM protocols WHERE id = ? LIMIT 1');
    $stmt->execute([$protocolId]);
    return (string) ($stmt->fetchColumn() ?: '');
}

function resolveClientContainer(array $serverData, array $clientData): string
{
    $containerName = trim((string) ($serverData['container_name'] ?? ''));
    $protocolId = (int) ($clientData['protocol_id'] ?? 0);
    if ($protocolId > 0) {
        try {
            $stmt = DB::conn()->prepare('SELECT config_data FROM server_protocols WHERE server_id = ? AND protocol_id = ? LIMIT 1');
            $stmt->execute([(int) $clientData['server_id'], $protocolId]);
            $raw = (string) ($stmt->fetchColumn() ?: '');
            $config = $raw !== '' ? json_decode($raw, true) : null;
            if (is_array($config) && !empty($config['container_name'])) {
                $containerName = trim((string) $config['container_name']);
            }
        } catch (Throwable $e) {
            error_log('Failed to resolve client container: ' . $e->getMessage());
        }
    }

    $slug = getClientProtocolSlug($clientData);
    if ($containerName === '' && $slug === 'awg2') {
        $containerName = 'amnezia-awg2';
    }

    return $containerName;
}

function getWireGuardPeerDiagnostics(VpnServer $server, string $containerName, array $clientData): array
{
    $clientPublicKey = trim((string) ($clientData['public_key'] ?? ''));
    $clientIp = trim((string) ($clientData['client_ip'] ?? ''));
    $checks = [];

    if ($containerName === '') {
        return [
            'checks' => [[
                'name' => 'container',
                'ok' => false,
                'severity' => 'critical',
                'message' => 'Не найдено имя контейнера для протокола клиента',
            ]],
            'peer' => null,
        ];
    }

    if ($clientPublicKey === '') {
        return [
            'checks' => [[
                'name' => 'client_public_key',
                'ok' => false,
                'severity' => 'critical',
                'message' => 'У клиента нет public key в базе',
            ]],
            'peer' => null,
        ];
    }

    $script = <<<'SH'
CONTAINER="$1"
PUBLIC_KEY="$2"
running="$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo missing)"
echo "container_running=${running}"
if [ "$running" != "true" ]; then
  exit 0
fi
iface=""
for candidate in awg0 wg0; do
  if docker exec "$CONTAINER" sh -lc "ip link show '$candidate' >/dev/null 2>&1"; then
    iface="$candidate"
    break
  fi
done
echo "wg_iface=${iface}"
if [ -z "$iface" ]; then
  exit 0
fi
docker exec "$CONTAINER" sh -lc "awg show '$iface' dump 2>/dev/null || wg show '$iface' dump 2>/dev/null || true" \
  | awk -v key="$PUBLIC_KEY" 'NR > 1 && $1 == key {print "peer_line="$0}'
SH;
    $cmd = 'bash -s -- ' . escapeshellarg($containerName) . ' ' . escapeshellarg($clientPublicKey)
        . ' <<' . "'AMNEZIA_CLIENT_DIAG_SH'\n" . $script . "\nAMNEZIA_CLIENT_DIAG_SH";
    $output = $server->executeCommand($cmd);
    $values = [];
    foreach (preg_split('/\R/', (string) $output) as $line) {
        if (strpos($line, '=') === false) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $values[trim($key)] = trim($value);
    }

    $running = ($values['container_running'] ?? '') === 'true';
    $checks[] = [
        'name' => 'container',
        'ok' => $running,
        'severity' => 'critical',
        'message' => $running ? "Контейнер {$containerName} запущен" : "Контейнер {$containerName} не запущен или не найден",
    ];

    $iface = trim((string) ($values['wg_iface'] ?? ''));
    $checks[] = [
        'name' => 'wireguard_interface',
        'ok' => $iface !== '',
        'severity' => 'critical',
        'message' => $iface !== '' ? "Интерфейс {$iface} найден" : 'Интерфейс awg0/wg0 не найден',
    ];

    $peerLine = trim((string) ($values['peer_line'] ?? ''));
    $parts = $peerLine !== '' ? preg_split('/\s+/', $peerLine) : [];
    $peer = null;
    if (is_array($parts) && count($parts) >= 8) {
        $latest = (int) ($parts[4] ?? 0);
        $peer = [
            'endpoint' => (string) ($parts[2] ?? ''),
            'allowed_ips' => (string) ($parts[3] ?? ''),
            'latest_handshake' => $latest,
            'latest_handshake_age_seconds' => $latest > 0 ? max(0, time() - $latest) : null,
            'rx_bytes' => (int) ($parts[5] ?? 0),
            'tx_bytes' => (int) ($parts[6] ?? 0),
        ];
    }

    $checks[] = [
        'name' => 'peer_exists',
        'ok' => $peer !== null,
        'severity' => 'critical',
        'message' => $peer ? 'Peer с public key клиента найден в контейнере' : 'Peer с public key клиента не найден в контейнере',
    ];

    if ($peer) {
        $expectedIp = $clientIp !== '' ? $clientIp . '/32' : '';
        $allowedOk = $expectedIp !== '' && str_contains($peer['allowed_ips'], $expectedIp);
        $checks[] = [
            'name' => 'allowed_ips',
            'ok' => $allowedOk,
            'severity' => 'critical',
            'message' => $allowedOk ? "AllowedIPs содержит {$expectedIp}" : "AllowedIPs={$peer['allowed_ips']}, ожидалось {$expectedIp}",
        ];

        $staleSeconds = max(60, (int) Config::get('ALERT_HANDSHAKE_STALE_SECONDS', '1800'));
        $age = $peer['latest_handshake_age_seconds'];
        $recentOk = is_int($age) && $age <= $staleSeconds;
        $checks[] = [
            'name' => 'recent_handshake',
            'ok' => $recentOk,
            'severity' => 'warning',
            'message' => $recentOk
                ? "Последний handshake {$age}s назад"
                : ($age === null ? 'Handshake еще не был зафиксирован' : "Последний handshake {$age}s назад, порог {$staleSeconds}s"),
        ];

        $endpoint = (string) ($peer['endpoint'] ?? '');
        $endpointOk = $endpoint !== '' && $endpoint !== '(none)';
        $checks[] = [
            'name' => 'endpoint',
            'ok' => $endpointOk,
            'severity' => 'warning',
            'message' => $endpointOk ? "Endpoint клиента: {$endpoint}" : 'Endpoint клиента пока не появился',
        ];
    }

    return ['checks' => $checks, 'peer' => $peer];
}

View::init(__DIR__ . '/../templates', [
    'app_name' => $appName,
    'user' => $user,
    'csrf_token' => csrfToken(),
    'current_language' => Translator::getCurrentLanguage(),
    'languages' => Translator::getSupportedLanguages(),
    'current_uri' => $_SERVER['REQUEST_URI'] ?? '/dashboard',
    't' => function ($key, $params = []) {
        return Translator::t($key, $params);
    }
]);

// Helper function for redirects
function redirect(string $to): void
{
    header('Location: ' . $to);
    exit;
}

// Helper function to require authentication
function requireAuth(): void
{
    if (!Auth::check()) {
        redirect('/login');
    }
}

// Helper function to require admin
function requireAdmin(): void
{
    requireAuth();
    if (!Auth::isAdmin()) {
        http_response_code(403);
        echo 'Forbidden: Admin access required';
        exit;
    }
}

function debugRoutesEnabled(): bool
{
    $val = strtolower((string) (getenv('ENABLE_DEBUG_ROUTES') ?: ''));
    return in_array($val, ['1', 'true', 'yes', 'on'], true);
}

function registrationEnabled(): bool
{
    $val = strtolower((string) (getenv('ALLOW_REGISTRATION') ?: ''));
    return in_array($val, ['1', 'true', 'yes', 'on'], true);
}

function configInt(string $key, int $default): int
{
    $value = Config::get($key, (string) $default);
    if (!is_numeric($value)) {
        return $default;
    }

    return (int) $value;
}

function clientIp(): string
{
    $trustProxy = in_array(strtolower((string) Config::get('TRUST_PROXY_HEADERS', '0')), ['1', 'true', 'yes', 'on'], true);
    $forwardedFor = $trustProxy ? trim((string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '')) : '';
    if ($forwardedFor !== '') {
        $parts = array_map('trim', explode(',', $forwardedFor));
        return $parts[0] ?: ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    }

    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function rateLimitPath(string $scope, string $identity): string
{
    $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'amnezia_panel_rate_limits';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }

    return $dir . DIRECTORY_SEPARATOR . hash('sha256', $scope . ':' . $identity) . '.json';
}

function rateLimitExceeded(string $scope, string $identity, int $limit, int $windowSeconds): array
{
    if ($limit <= 0 || $windowSeconds <= 0) {
        return ['limited' => false, 'retry_after' => 0];
    }

    $path = rateLimitPath($scope, $identity);
    $now = time();
    $timestamps = [];
    if (is_file($path)) {
        $decoded = json_decode((string) @file_get_contents($path), true);
        if (is_array($decoded)) {
            $timestamps = array_values(array_filter(array_map('intval', $decoded), static fn($ts) => $ts > $now - $windowSeconds));
        }
    }

    if (count($timestamps) < $limit) {
        return ['limited' => false, 'retry_after' => 0];
    }

    $oldest = min($timestamps);
    return ['limited' => true, 'retry_after' => max(1, $windowSeconds - ($now - $oldest))];
}

function recordRateLimitFailure(string $scope, string $identity, int $windowSeconds): void
{
    if ($windowSeconds <= 0) {
        return;
    }

    $path = rateLimitPath($scope, $identity);
    $now = time();
    $fp = @fopen($path, 'c+');
    if (!$fp) {
        return;
    }

    try {
        @flock($fp, LOCK_EX);
        $contents = stream_get_contents($fp);
        $decoded = json_decode((string) $contents, true);
        $timestamps = is_array($decoded) ? array_map('intval', $decoded) : [];
        $timestamps = array_values(array_filter($timestamps, static fn($ts) => $ts > $now - $windowSeconds));
        $timestamps[] = $now;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($timestamps));
    } finally {
        @flock($fp, LOCK_UN);
        fclose($fp);
    }
}

function clearRateLimit(string $scope, string $identity): void
{
    @unlink(rateLimitPath($scope, $identity));
}

function uploadMaxBytes(): int
{
    return max(1, configInt('AMNEZIA_UPLOAD_MAX_BYTES', 20 * 1024 * 1024));
}

function validateUploadedFileSize(array $file, string $label): void
{
    $size = (int) ($file['size'] ?? 0);
    $maxBytes = uploadMaxBytes();
    if ($size > $maxBytes) {
        $maxMb = round($maxBytes / 1024 / 1024, 1);
        throw new Exception($label . ' is too large. Maximum allowed size is ' . $maxMb . ' MB.');
    }
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function csrfProtectedRequest(string $method, string $uri): bool
{
    if (!in_array(strtolower((string) Config::get('AMNEZIA_CSRF_ENABLED', '1')), ['1', 'true', 'yes', 'on'], true)) {
        return false;
    }

    if (!in_array(strtoupper($method), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        return false;
    }

    $path = parse_url($uri, PHP_URL_PATH) ?: '/';
    if ($path === '/api/auth/token') {
        return false;
    }

    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer\s+\S+/i', (string) $authHeader)) {
        return false;
    }

    return true;
}

function verifyCsrfRequest(): bool
{
    $expected = csrfToken();
    $provided = $_POST['_csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    return is_string($provided) && hash_equals($expected, $provided);
}

function rejectInvalidCsrf(): void
{
    // 403, not 419: 419 is a non-standard code that Apache re-emits as 500,
    // so clients (and our own fetch wrapper) saw a server error instead of a
    // clear "forbidden" for a missing/invalid CSRF token.
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Invalid or missing CSRF token';
}

function requireDebugEnabledOrAdmin(): void
{
    requireAuth();

    if (Auth::isAdmin()) {
        return;
    }

    if (!debugRoutesEnabled()) {
        http_response_code(404);
        echo 'Not Found';
        exit;
    }
}

// Helper function to get authenticated user (JWT or session)
function getAuthUser(): ?array
{
    // Try JWT first
    $token = JWT::getTokenFromHeader();
    if ($token !== null) {
        $user = JWT::verify($token);
        if ($user !== null) {
            return $user;
        }
    }

    // Fall back to session
    if (Auth::check()) {
        return Auth::user();
    }

    return null;
}

// Helper function to require authentication (JWT or session) for API
function requireApiAuth(): ?array
{
    $user = getAuthUser();

    if ($user === null) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Authentication required']);
        return null;
    }

    return $user;
}

/**
 * PUBLIC ROUTES
 */

// Home page

// ---------------------------------------------------------------------------
// Route modules. Split out of this front controller for readability; they are
// required here in order so Router:: registration order is unchanged.
// ---------------------------------------------------------------------------
require __DIR__ . '/routes/web.php';
require __DIR__ . '/routes/api.php';
require __DIR__ . '/routes/admin_settings.php';
require __DIR__ . '/routes/backups.php';
// Dispatch router
if (csrfProtectedRequest($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI']) && !verifyCsrfRequest()) {
    rejectInvalidCsrf();
    exit;
}

Router::dispatch($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI']);
