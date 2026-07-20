<?php
require_once __DIR__ . '/SecretBox.php';

/**
 * VPN Server Management Class
 * Handles deployment and management of Amnezia VPN servers
 * Based on amnezia_deploy_v2.php
 */
class VpnServer
{
    private $serverId;
    private $data;
    
    /**
     * Cache for docker sudo requirements per server.
     * null = not tested, true = needs sudo, false = no sudo needed
     * @var array<int, bool|null>
     */
    private static $dockerSudoCache = [];

    public function __construct(?int $serverId = null)
    {
        $this->serverId = $serverId;
        if ($serverId) {
            $this->load();
        }
    }

    public function getId(): int
    {
        return (int) $this->serverId;
    }

    public function refresh(): void
    {
        if ($this->serverId === null) {
            throw new Exception('Server ID is not set');
        }
        $this->load();
    }

    /**
     * Load server data from database
     */
    private function load(): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE id = ?');
        $stmt->execute([$this->serverId]);
        $this->data = $stmt->fetch();
        if (!$this->data) {
            throw new Exception('Server not found');
        }
        $this->data = self::decryptServerSecrets($this->data);
        // Single choke point for the container name. It is interpolated into
        // ~50 shell commands across the codebase; sanitising it here means none
        // of those can be turned into command injection, instead of trusting
        // every one of them to remember escapeshellarg. Docker names are
        // [a-zA-Z0-9][a-zA-Z0-9_.-]* anyway, so nothing legitimate is lost.
        if (isset($this->data['container_name'])) {
            $this->data['container_name'] = self::sanitizeContainerName((string) $this->data['container_name']);
        }
    }

    /** Strip anything a Docker container name may not contain. */
    public static function sanitizeContainerName(string $name): string
    {
        $clean = preg_replace('/[^a-zA-Z0-9_.-]/', '', trim($name)) ?? '';
        // A leading separator is illegal for Docker too.
        $clean = ltrim($clean, '_.-');
        if ($clean !== '' && $clean !== trim($name)) {
            error_log('VpnServer: container name sanitised: ' . json_encode(trim($name)) . ' -> ' . json_encode($clean));
        }
        return $clean;
    }

    /**
     * Normalize SSH private key: fix line endings, trim whitespace, ensure trailing newline.
     * Fixes "error in libcrypto" when keys are pasted from Windows or browsers.
     */
    private static function normalizeSshKey(string $key): string
    {
        // Remove \r (Windows line endings)
        $key = str_replace("\r\n", "\n", $key);
        $key = str_replace("\r", "\n", $key);
        // Trim each line (remove trailing spaces)
        $lines = explode("\n", $key);
        $lines = array_map('rtrim', $lines);
        // Remove empty lines at start/end but keep internal structure
        while (!empty($lines) && trim($lines[0]) === '') array_shift($lines);
        while (!empty($lines) && trim(end($lines)) === '') array_pop($lines);
        $key = implode("\n", $lines);
        // PEM/OpenSSH keys MUST end with a newline
        if ($key !== '' && substr($key, -1) !== "\n") {
            $key .= "\n";
        }
        return $key;
    }

    /**
     * Create new VPN server in database
     */
    public static function create(array $data): int
    {
        $pdo = DB::conn();

        // Validate required fields
        $required = ['user_id', 'name', 'host', 'port', 'username'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("Field {$field} is required");
            }
        }

        if (empty($data['password']) && empty($data['ssh_key'])) {
            throw new Exception("Either password or SSH key is required");
        }

        $protocolSlug = trim((string) ($data['install_protocol'] ?? ''));
        if ($protocolSlug === '') {
            throw new Exception('Install protocol must be selected');
        }
        $installOptions = $data['install_options'] ?? null;

        if (is_array($installOptions)) {
            $installOptions = json_encode($installOptions);
        } elseif (is_string($installOptions)) {
            $installOptions = trim($installOptions) === '' ? null : $installOptions;
        }

        $domain = isset($data['domain']) ? trim((string) $data['domain']) : '';
        $domain = $domain !== '' ? ltrim($domain, '@') : null;

        $stmt = $pdo->prepare('
            INSERT INTO vpn_servers
            (user_id, name, host, domain, port, username, password, ssh_key, container_name, install_protocol, install_options, vpn_subnet, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');

        $stmt->execute([
            $data['user_id'],
            $data['name'],
            $data['host'],
            $domain,
            $data['port'],
            $data['username'],
            self::encryptSecret($data['password'] ?? null),
            !empty($data['ssh_key']) ? self::encryptSecret(self::normalizeSshKey($data['ssh_key'])) : null,
            $data['container_name'] ?? 'amnezia-awg',
            $protocolSlug,
            $installOptions,
            $data['vpn_subnet'] ?? '10.8.1.0/24',
            'deploying'
        ]);

        return (int) $pdo->lastInsertId();
    }

    /**
     * Deploy VPN server using amnezia_deploy_v2.php logic
     */
    public function deploy(array $options = []): array
    {
        return InstallProtocolManager::deploy($this, $options);
    }

    /**
     * Legacy AmneziaWG deployment routine kept for backward compatibility.
     */
    public function runAwgInstall(array $options = []): array
    {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        $pdo = DB::conn();
        $errors = [];

        try {
            // Update status to deploying
            $pdo->prepare('UPDATE vpn_servers SET status = ? WHERE id = ?')
                ->execute(['deploying', $this->serverId]);

            // Test SSH connection
            if (!$this->testConnection()) {
                throw new Exception('SSH connection failed');
            }

            // Install Docker if needed
            $this->installDocker();

            // Create directories
            $this->executeCommand('mkdir -p /opt/amnezia/amnezia-awg', true);

            // Find free UDP port
            $vpnPort = $this->findFreeUdpPort();

            // Create Dockerfile
            $this->createDockerfile();

            // Create start script
            $this->createStartScript();

            // Build Docker image
            $this->buildDockerImage();

            // Run container
            $this->runContainer($vpnPort);

            // Initialize server config
            $keys = $this->initializeServerConfig($vpnPort);

            // Update database with deployment info
            $stmt = $pdo->prepare('
                UPDATE vpn_servers 
                SET vpn_port = ?, 
                    server_public_key = ?, 
                    preshared_key = ?, 
                    awg_params = ?,
                    status = ?,
                    deployed_at = NOW(),
                    error_message = NULL
                WHERE id = ?
            ');

            $stmt->execute([
                $vpnPort,
                $keys['public_key'],
                $keys['preshared_key'],
                json_encode($keys['awg_params']),
                'active',
                $this->serverId
            ]);

            // Reload data
            $this->load();

            return [
                'success' => true,
                'vpn_port' => $vpnPort,
                'public_key' => $keys['public_key']
            ];

        } catch (Exception $e) {
            // Update status to error
            $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = ? WHERE id = ?')
                ->execute(['error', $e->getMessage(), $this->serverId]);

            throw $e;
        }
    }

    /**
     * Test SSH connection to server
     */
    public function testConnection(): bool
    {
        $result = Ssh::exec($this->data, 'echo test', ['timeout' => 20, 'stderr' => 'discard']);
        return trim($result->output) === 'test';
    }

    /**
     * Execute command on remote server.
     *
     * @param string $command The command to execute
     * @param bool|null $sudo True = use sudo, false = no sudo, null = auto-detect for docker commands
     * @return string The command output
     */
    public function executeCommand(string $command, bool $sudo = null): string
    {
        $baseCommand = $command;
        $pathPrefix = 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; ';
        $isDockerCommand = preg_match('/(^|\\n)docker(\\s|$)/', ltrim($baseCommand));

        // Auto-detect sudo requirement for docker commands when $sudo is null
        if ($sudo === null && $isDockerCommand) {
            $sudo = $this->detectDockerSudoRequirement();
        }

        // sudo wrapping only applies to password sessions; key-based sessions
        // historically run commands as-is (root or docker-group user).
        $needsSudo = ($sudo ?? false)
            && empty($this->data['ssh_key'])
            && strtolower((string) ($this->data['username'] ?? '')) !== 'root';
        $prepared = $needsSudo ? Ssh::wrapSudo($this->data, $command) : $command;

        $result = Ssh::exec($this->data, $pathPrefix . $prepared, ['timeout' => 900]);
        $output = $result->output;

        // If sudo auth fails but user can run docker without sudo, retry docker commands directly.
        if ($needsSudo && $isDockerCommand && Ssh::isSudoAuthFailure($output)) {
            // Update cache: this server doesn't need sudo for docker
            if ($this->serverId !== null) {
                self::$dockerSudoCache[$this->serverId] = false;
            }
            $result = Ssh::exec($this->data, $pathPrefix . $baseCommand, ['timeout' => 900]);
            $output = $result->output;
        }

        // The command's exit code is intentionally NOT surfaced — plenty of
        // callers run commands that legitimately fail. But a failure to CONNECT
        // is different: nothing ran, and returning ssh's diagnostic as "output"
        // made callers act on it as data (a refused host key read as a server
        // reporting no containers, an unreachable host as an empty peer list).
        if (Ssh::isConnectionFailure($result)) {
            $first = trim(strtok(trim($output), "\n") ?: '');
            throw new Exception(sprintf(
                'SSH connection to %s failed: %s',
                (string) ($this->data['host'] ?? '?'),
                $first !== '' ? $first : 'exit code 255'
            ));
        }

        return $output;
    }

    public function uploadContent(string $remotePath, string $content, int $mode = 0600): void
    {
        $last = null;
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $last = Ssh::upload($this->data, $remotePath, $content, $mode);
            if ($last->ok()) {
                return;
            }
            if ($attempt < 3) {
                sleep(2);
            }
        }
        throw new RuntimeException('Upload failed: ' . trim($last ? $last->output : ''));
    }

    /**
     * Detect whether docker commands require sudo on this server.
     * Uses a simple test command to check if docker works without sudo.
     * Results are cached per server instance.
     *
     * @return bool True if sudo is needed, false if docker works without sudo
     */
    private function detectDockerSudoRequirement(): bool
    {
        // Return cached result if available
        if ($this->serverId !== null && array_key_exists($this->serverId, self::$dockerSudoCache)) {
            return self::$dockerSudoCache[$this->serverId];
        }

        // Test if docker works without sudo using a simple version check
        $pathPrefix = 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; ';
        $output = Ssh::exec($this->data, $pathPrefix . 'docker --version 2>&1', ['timeout' => 30])->output;

        // Check if docker command succeeded (output contains "version")
        $dockerWorks = stripos($output, 'version') !== false;
        
        // Cache the result
        if ($this->serverId !== null) {
            self::$dockerSudoCache[$this->serverId] = !$dockerWorks;
        }

        return !$dockerWorks;
    }

    /**
     * Install Docker on remote server
     */
    private function installDocker(): void
    {
        $dockerVersion = $this->executeCommand('docker --version');
        if (stripos($dockerVersion, 'version') !== false) {
            return; // Docker already installed
        }

        $this->executeCommand('curl -fsSL https://get.docker.com | sh', true);
        $this->executeCommand('systemctl enable --now docker', true);
    }

    /**
     * Find free UDP port on remote server
     */
    private function findFreeUdpPort(): int
    {
        $min = 30000;
        $max = 65000;

        for ($attempt = 0; $attempt < 30; $attempt++) {
            $candidate = random_int($min, $max);
            $cmd = "ss -lun | awk '{print \$4}' | grep -E ':(" . $candidate . ")($| )' || true";
            $out = $this->executeCommand($cmd, false);
            if (trim($out) === '') {
                return $candidate;
            }
        }

        throw new Exception('Could not find free UDP port');
    }

    /**
     * Create Dockerfile on remote server
     */
    private function createDockerfile(): void
    {
        $dockerfile = <<<'DOCKERFILE'
FROM amneziavpn/amnezia-wg:latest

LABEL maintainer="AmneziaVPN"

RUN apk add --no-cache bash curl dumb-init
RUN apk --update upgrade --no-cache

RUN mkdir -p /opt/amnezia
RUN echo -e "#!/bin/bash\ntail -f /dev/null" > /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
CMD [ "" ]
DOCKERFILE;

        $escaped = addslashes(trim($dockerfile));
        $this->executeCommand("echo \"{$escaped}\" > /opt/amnezia/amnezia-awg/Dockerfile", true);
    }

    /**
     * Create start script on remote server
     */
    private function createStartScript(): void
    {
        $script = <<<'BASH'
#!/bin/bash

echo "Container startup"

# Wait for config if not exists yet
for i in {1..30}; do
    if [ -f /opt/amnezia/awg/wg0.conf ]; then
        break
    fi
    sleep 1
done

# Kill daemons in case of restart
wg-quick down /opt/amnezia/awg/wg0.conf 2>/dev/null || true

# Start daemons if configured
if [ -f /opt/amnezia/awg/wg0.conf ]; then
    wg-quick up /opt/amnezia/awg/wg0.conf
    echo "WireGuard started"
else
    echo "No wg0.conf found, skipping WireGuard startup"
fi

# Allow traffic on the TUN interface
iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true

# Allow forwarding traffic only from the VPN
iptables -A FORWARD -i wg0 -o eth0 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i wg0 -o eth1 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth1 -j MASQUERADE 2>/dev/null || true

tail -f /dev/null
BASH;

        $escaped = addslashes(trim($script));
        $this->executeCommand("echo \"{$escaped}\" > /opt/amnezia/amnezia-awg/start.sh", true);
        $this->executeCommand("chmod +x /opt/amnezia/amnezia-awg/start.sh", true);
    }

    /**
     * Build Docker image
     */
    private function buildDockerImage(): void
    {
        $containerName = $this->data['container_name'];

        // Cleanup old container/image
        $this->executeCommand("docker stop {$containerName} 2>/dev/null || true", true);
        $this->executeCommand("docker rm -fv {$containerName} 2>/dev/null || true", true);
        $this->executeCommand("docker rmi {$containerName} 2>/dev/null || true", true);

        // Build new image
        $buildCmd = sprintf(
            'docker build --no-cache --pull -t %s /opt/amnezia/amnezia-awg',
            $containerName
        );
        $this->executeCommand($buildCmd, true);
    }

    /**
     * Run Docker container
     */
    private function runContainer(int $vpnPort): void
    {
        $containerName = $this->data['container_name'];

        $runCmd = sprintf(
            'docker run -d --log-driver none --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p %d:%d/udp -v /lib/modules:/lib/modules --name %s %s',
            $vpnPort,
            $vpnPort,
            $containerName,
            $containerName
        );

        $this->executeCommand($runCmd, true);
        sleep(3); // Wait for container to start
    }

    /**
     * Initialize server configuration with AWG parameters
     */
    private function initializeServerConfig(int $vpnPort): array
    {
        $containerName = $this->data['container_name'];

        // Create directory
        $this->executeCommand("docker exec -i {$containerName} mkdir -p /opt/amnezia/awg", true);

        // Generate keys
        $this->executeCommand("docker exec -i {$containerName} sh -c 'cd /opt/amnezia/awg && umask 077 && wg genkey | tee server_private.key | wg pubkey > wireguard_server_public_key.key'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'cd /opt/amnezia/awg && wg genpsk > wireguard_psk.key'", true);
        $this->executeCommand("docker exec -i {$containerName} chmod 600 /opt/amnezia/awg/server_private.key /opt/amnezia/awg/wireguard_psk.key /opt/amnezia/awg/wireguard_server_public_key.key", true);

        // Get keys
        $privKey = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/server_private.key", true));
        $pubKey = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/wireguard_server_public_key.key", true));
        $psk = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/wireguard_psk.key", true));

        // Generate AWG parameters
        $awgParams = [
            'Jc' => 3,
            'Jmin' => 10,
            'Jmax' => 50,
            'S1' => rand(50, 250),
            'S2' => rand(50, 250),
            'H1' => rand(100000, 2000000000),
            'H2' => rand(100000, 2000000000),
            'H3' => rand(100000, 2000000000),
            'H4' => rand(100000, 2000000000)
        ];

        // Create wg0.conf
        $wgConfig = "[Interface]\n";
        $wgConfig .= "PrivateKey = {$privKey}\n";
        $wgConfig .= "Address = {$this->data['vpn_subnet']}\n";
        $wgConfig .= "ListenPort = {$vpnPort}\n";
        foreach ($awgParams as $key => $value) {
            $wgConfig .= "{$key} = {$value}\n";
        }
        $wgConfig .= "\n";

        $escaped = addslashes($wgConfig);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'echo \"{$escaped}\" > /opt/amnezia/awg/wg0.conf'", true);
        $this->executeCommand("docker exec -i {$containerName} chmod 600 /opt/amnezia/awg/wg0.conf", true);

        // Create clientsTable
        $this->executeCommand("docker exec -i {$containerName} sh -c 'echo \"[]\" > /opt/amnezia/awg/clientsTable'", true);

        // Start WireGuard
        $this->executeCommand("docker exec -i {$containerName} wg-quick up /opt/amnezia/awg/wg0.conf 2>&1", true);

        // Apply firewall rules
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A FORWARD -i wg0 -o eth0 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true'", true);

        // Ensure host-level forwarding/NAT for AWG subnet as well (required on some Docker host setups).
        $vpnSubnet = (string) ($this->data['vpn_subnet'] ?? '10.8.1.0/24');
        $vpnSubnetEsc = escapeshellarg($vpnSubnet);
        $hostNatCmd = "bash -lc 'IFACE=\\$(ip route | awk \"{if (\\$1==\\\"default\\\") {print \\$5; exit}}\"); " .
            "iptables -t nat -C POSTROUTING -s " . $vpnSubnetEsc . " -o \\\"\\\$IFACE\\\" -j MASQUERADE 2>/dev/null || " .
            "iptables -t nat -I POSTROUTING 1 -s " . $vpnSubnetEsc . " -o \\\"\\\$IFACE\\\" -j MASQUERADE; " .
            "iptables -C FORWARD -s " . $vpnSubnetEsc . " -o \\\"\\\$IFACE\\\" -j ACCEPT 2>/dev/null || " .
            "iptables -I FORWARD 1 -s " . $vpnSubnetEsc . " -o \\\"\\\$IFACE\\\" -j ACCEPT; " .
            "iptables -C FORWARD -d " . $vpnSubnetEsc . " -m conntrack --ctstate RELATED,ESTABLISHED -i \\\"\\\$IFACE\\\" -j ACCEPT 2>/dev/null || " .
            "iptables -I FORWARD 1 -d " . $vpnSubnetEsc . " -m conntrack --ctstate RELATED,ESTABLISHED -i \\\"\\\$IFACE\\\" -j ACCEPT; " .
            "sysctl -w net.ipv4.ip_forward=1 >/dev/null'";
        $this->executeCommand($hostNatCmd, true);

        sleep(2);

        return [
            'public_key' => $pubKey,
            'preshared_key' => $psk,
            'awg_params' => $awgParams
        ];
    }

    /**
     * Get server status from database
     */
    public function getStatus(): string
    {
        return $this->data['status'] ?? 'unknown';
    }

    /**
     * Get all servers for a user
     */
    public static function listByUser(int $userId, bool $decryptSecrets = true): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute([$userId]);
        $rows = $stmt->fetchAll();
        // Display/list contexts redact secrets anyway — skip the per-row SecretBox
        // decrypt (pass $decryptSecrets=false) to avoid N wasted sodium ops.
        return $decryptSecrets ? array_map([self::class, 'decryptServerSecrets'], $rows) : $rows;
    }

    /**
     * Get all servers (admin only)
     */
    public static function listAll(bool $decryptSecrets = true): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->query('SELECT s.*, u.email as user_email FROM vpn_servers s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC');
        $rows = $stmt->fetchAll();
        return $decryptSecrets ? array_map([self::class, 'decryptServerSecrets'], $rows) : $rows;
    }

    /**
     * Annotate each server row with its pool membership for list views:
     * pool_name (or null) and pool_role ('active' | 'standby' | null).
     */
    public static function attachPoolInfo(array $servers): array
    {
        $pools = [];
        foreach (DB::conn()->query('SELECT id, name, active_server_id FROM server_pools') as $p) {
            $pools[(int) $p['id']] = $p;
        }
        foreach ($servers as &$sv) {
            $pid = (int) ($sv['pool_id'] ?? 0);
            if ($pid > 0 && isset($pools[$pid])) {
                $sv['pool_name'] = (string) $pools[$pid]['name'];
                $sv['pool_role'] = ((int) ($sv['id'] ?? 0) === (int) $pools[$pid]['active_server_id']) ? 'active' : 'standby';
            } else {
                $sv['pool_name'] = null;
                $sv['pool_role'] = null;
            }
        }
        unset($sv);
        return $servers;
    }

    /**
     * Delete server
     */
    public function delete(): bool
    {
        $pdo = DB::conn();
        $serverId = (int) $this->serverId;

        // Drop the pinned host key: the IP is very likely to be reused by a new
        // machine, and a stale pin would make every future connection to it look
        // like a MITM and be refused.
        if (!empty($this->data['host'])) {
            Ssh::forgetHost((string) $this->data['host'], (int) ($this->data['port'] ?? 22));
        }
        $poolId = (int) ($this->data['pool_id'] ?? 0);

        // Pool cleanup BEFORE removing the row (the DELETE cascades this server's
        // vpn_clients rows). Two things must happen or the pool is left broken:
        if ($poolId > 0) {
            // 0) Clients in a pool are logically SHARED — the same config works
            //    against any member — but each row is bound by server_id to the
            //    member it happened to be created on. Cascading that delete wiped
            //    those clients from the whole pool and stripped their peers off
            //    the survivors: users silently lost access even though the pool
            //    was still alive. Hand them to a surviving member instead; their
            //    peers are already present there, so nothing else has to change.
            $stmtS = $pdo->prepare(
                'SELECT id FROM vpn_servers WHERE pool_id = ? AND id <> ? ORDER BY pool_priority ASC, id ASC LIMIT 1'
            );
            $stmtS->execute([$poolId, $serverId]);
            $heir = (int) $stmtS->fetchColumn();
            if ($heir > 0) {
                $stmtR = $pdo->prepare('UPDATE vpn_clients SET server_id = ? WHERE server_id = ?');
                $stmtR->execute([$heir, $serverId]);
                $moved = $stmtR->rowCount();
                if ($moved > 0) {
                    error_log("VpnServer::delete: reassigned {$moved} client(s) from server {$serverId} to pool member {$heir}");
                }
            }

            // 1) Any peers still bound to THIS server (none, if the step above
            //    found an heir) were synced to every other member. Strip those
            //    from the survivors, otherwise they linger as orphans holding
            //    pool IPs. With an heir this loop finds nothing, which is the
            //    point: surviving clients keep working.
            try {
                $stmtC = $pdo->prepare('SELECT public_key FROM vpn_clients WHERE server_id = ?');
                $stmtC->execute([$serverId]);
                $pubKeys = array_filter($stmtC->fetchAll(PDO::FETCH_COLUMN));
                if ($pubKeys) {
                    $stmtM = $pdo->prepare('SELECT id FROM vpn_servers WHERE pool_id = ? AND id <> ?');
                    $stmtM->execute([$poolId, $serverId]);
                    foreach ($stmtM->fetchAll(PDO::FETCH_COLUMN) as $mid) {
                        try {
                            $md = (new VpnServer((int) $mid))->getData();
                            if ($md && ($md['status'] ?? '') === 'active') {
                                foreach ($pubKeys as $pk) {
                                    try {
                                        VpnClient::removeClientFromServer($md, (string) $pk);
                                    } catch (Throwable $e) {
                                        error_log("delete: strip peer from server {$mid} failed: " . $e->getMessage());
                                    }
                                }
                            }
                        } catch (Throwable $e) {
                            error_log("delete: load member {$mid} failed: " . $e->getMessage());
                        }
                    }
                }
            } catch (Throwable $e) {
                error_log('delete: pool peer cleanup failed: ' . $e->getMessage());
            }

            // 2) If this was the active member, fail over to a healthy standby
            //    (repoints DNS) BEFORE dropping it — otherwise the domain keeps
            //    resolving to the deleted host. If no standby / DNS fails, at
            //    least clear the pointer so the pool doesn't reference a dead id.
            try {
                $stmtA = $pdo->prepare('SELECT active_server_id FROM server_pools WHERE id = ?');
                $stmtA->execute([$poolId]);
                if ((int) $stmtA->fetchColumn() === $serverId) {
                    $fo = ServerPool::failover($poolId, $serverId);
                    if (empty($fo['success'])) {
                        error_log("delete: active member {$serverId} — no failover ({$fo['message']}); clearing pointer");
                        $pdo->prepare('UPDATE server_pools SET active_server_id = NULL WHERE id = ?')->execute([$poolId]);
                    }
                }
            } catch (Throwable $e) {
                error_log('delete: pool failover-on-delete failed: ' . $e->getMessage());
            }
        }

        // Stop and remove the container (best effort).
        try {
            $containerName = $this->data['container_name'];
            $this->executeCommand("docker stop {$containerName} 2>/dev/null || true", true);
            $this->executeCommand("docker rm -fv {$containerName} 2>/dev/null || true", true);
            $this->executeCommand("rm -rf /opt/amnezia/amnezia-awg", true);
        } catch (Exception $e) {
            // Ignore errors during cleanup
        }

        // Belt-and-suspenders: clear any pool still pointing here (non-pool path
        // or a race), then delete the row (cascades this server's clients).
        try {
            $pdo->prepare('UPDATE server_pools SET active_server_id = NULL WHERE active_server_id = ?')
                ->execute([$serverId]);
        } catch (Throwable $e) {
            // server_pools may not exist on older schemas; ignore.
        }

        $stmt = $pdo->prepare('DELETE FROM vpn_servers WHERE id = ?');
        return $stmt->execute([$serverId]);
    }

    /**
     * Get server data
     */
    public function getData(): ?array
    {
        return $this->data;
    }

    /**
     * Live client summary from the awg2 interface: how many peers have handshaked
     * recently. A real handshake proves the server actually receives client UDP
     * (unlike a synthetic server-to-server probe), so this is the honest
     * "is this node serving clients" signal.
     *
     * @return array{total_peers:int, active_peers:int, last_handshake_age:?int}
     */
    public function liveClientSummary(int $recentSeconds = 180): array
    {
        $container = trim((string) ($this->data['container_name'] ?? 'amnezia-awg2')) ?: 'amnezia-awg2';
        $dump = (string) $this->executeCommand(
            'docker exec ' . escapeshellarg($container) . ' awg show awg0 dump 2>/dev/null '
            . '|| docker exec ' . escapeshellarg($container) . ' wg show wg0 dump 2>/dev/null',
            true
        );
        $lines = array_values(array_filter(explode("\n", trim($dump)), static fn($l) => trim($l) !== ''));

        $now = time();
        $total = 0;
        $active = 0;
        $lastHs = 0;
        foreach ($lines as $i => $line) {
            if ($i === 0) {
                continue; // interface line (private/public key, listen-port, fwmark)
            }
            $f = explode("\t", $line);
            if (count($f) < 5) {
                continue;
            }
            $total++;
            $hs = (int) $f[4];
            if ($hs > 0) {
                $lastHs = max($lastHs, $hs);
                if (($now - $hs) <= $recentSeconds) {
                    $active++;
                }
            }
        }

        return [
            'total_peers' => $total,
            'active_peers' => $active,
            'last_handshake_age' => $lastHs > 0 ? ($now - $lastHs) : null,
        ];
    }

    /**
     * Live per-peer state from awg0, keyed by public key:
     * [pubkey => ['handshake_age' => int|null, 'rx' => int, 'tx' => int]].
     * Used to drive a live online indicator that doesn't wait for the
     * metrics-collector cycle.
     */
    public function liveClientPeers(int $cacheSeconds = 30): array
    {
        // This is polled by every open server-view tab; cache the SSH dump
        // briefly so N tabs don't each drive an exec to the VPN box.
        $sid = (int) ($this->data['id'] ?? 0);
        $cacheFile = sys_get_temp_dir() . '/amnezia_live_peers_' . $sid . '.json';
        clearstatcache(true, $cacheFile);
        if ($cacheSeconds > 0 && $sid > 0 && is_file($cacheFile) && (time() - (int) @filemtime($cacheFile)) < $cacheSeconds) {
            $cached = json_decode((string) @file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $container = trim((string) ($this->data['container_name'] ?? 'amnezia-awg2')) ?: 'amnezia-awg2';
        $dump = (string) $this->executeCommand(
            'docker exec ' . escapeshellarg($container) . ' awg show awg0 dump 2>/dev/null '
            . '|| docker exec ' . escapeshellarg($container) . ' wg show wg0 dump 2>/dev/null',
            true
        );
        $lines = array_values(array_filter(explode("\n", trim($dump)), static fn($l) => trim($l) !== ''));
        $now = time();
        $peers = [];
        foreach ($lines as $i => $line) {
            if ($i === 0) {
                continue; // interface line
            }
            $f = explode("\t", $line);
            if (count($f) < 7) {
                continue;
            }
            $pub = trim($f[0]);
            $hs = (int) $f[4];
            if ($pub === '') {
                continue;
            }
            $peers[$pub] = [
                'handshake_age' => $hs > 0 ? ($now - $hs) : null,
                'rx' => (int) $f[5],
                'tx' => (int) $f[6],
            ];
        }
        if ($sid > 0) {
            @file_put_contents($cacheFile, json_encode($peers));
        }
        return $peers;
    }

    public static function decryptServerSecrets(array $serverData): array
    {
        foreach (['password', 'ssh_key'] as $field) {
            if (array_key_exists($field, $serverData)) {
                $serverData[$field] = SecretBox::decryptNullable($serverData[$field]);
            }
        }

        return $serverData;
    }

    public static function redactServerSecrets(array $serverData): array
    {
        $serverData['has_password'] = !empty($serverData['password']);
        $serverData['has_ssh_key'] = !empty($serverData['ssh_key']);
        unset($serverData['password'], $serverData['ssh_key']);
        return $serverData;
    }

    public static function redactServerList(array $servers): array
    {
        return array_map([self::class, 'redactServerSecrets'], $servers);
    }

    public static function encryptSecret(?string $value): ?string
    {
        return SecretBox::encryptNullable($value);
    }

}
