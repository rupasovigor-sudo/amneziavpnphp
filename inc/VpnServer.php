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
     * Import existing VPN server from backup payload without deployment.
     */
    public static function importFromBackup(int $userId, array $serverData): int
    {
        $pdo = DB::conn();

        $name = trim($serverData['name'] ?? '');
        $host = trim($serverData['host'] ?? '');
        if ($name === '' || $host === '') {
            throw new Exception('Backup is missing server name or host');
        }

        $port = isset($serverData['ssh_port']) ? (int) $serverData['ssh_port'] : 22;
        $username = trim($serverData['ssh_username'] ?? 'root') ?: 'root';
        $password = (string) ($serverData['ssh_password'] ?? '');
        $containerName = $serverData['container_name'] ?? 'amnezia-awg';
        $vpnPort = isset($serverData['vpn_port']) && $serverData['vpn_port'] !== null
            ? (int) $serverData['vpn_port']
            : null;
        $vpnSubnet = $serverData['vpn_subnet'] ?? '10.8.1.0/24';
        $serverPublicKey = $serverData['server_public_key'] ?? null;
        $presharedKey = $serverData['preshared_key'] ?? null;

        $awgParams = $serverData['awg_params'] ?? null;
        if (is_array($awgParams)) {
            $awgParams = json_encode($awgParams);
        }

        $installProtocol = $serverData['install_protocol'] ?? 'amnezia-wg';
        $installOptions = $serverData['install_options'] ?? null;
        if (is_array($installOptions)) {
            $installOptions = json_encode($installOptions);
        }

        $stmt = $pdo->prepare('
            INSERT INTO vpn_servers 
            (user_id, name, host, port, username, password, container_name, install_protocol, install_options, vpn_port, vpn_subnet, 
             server_public_key, preshared_key, awg_params, status, deployed_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NULL)
        ');

        $stmt->execute([
            $userId,
            $name,
            $host,
            $port,
            $username,
            self::encryptSecret($password),
            $containerName,
            $installProtocol,
            $installOptions,
            $vpnPort,
            $vpnSubnet,
            $serverPublicKey,
            $presharedKey,
            $awgParams,
            'active'
        ]);

        return (int) $pdo->lastInsertId();
    }

    /**
     * Apply server configuration from backup payload to an existing record.
     */
    public function applyBackupData(array $serverData, int $userId, bool $replaceClients = true): array
    {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        $pdo = DB::conn();
        $updates = [];
        $params = [];
        $updatedFields = [];

        $mapString = function (?string $value): ?string {
            $value = trim((string) $value);
            return $value === '' ? null : $value;
        };

        $stringFields = [
            'name' => $mapString($serverData['name'] ?? null),
            'host' => $mapString($serverData['host'] ?? null),
            'username' => $mapString($serverData['ssh_username'] ?? null),
            'password' => isset($serverData['ssh_password']) ? self::encryptSecret((string) $serverData['ssh_password']) : null,
            'container_name' => $mapString($serverData['container_name'] ?? null),
            'vpn_subnet' => $mapString($serverData['vpn_subnet'] ?? null),
            'server_public_key' => $mapString($serverData['server_public_key'] ?? null),
            'preshared_key' => isset($serverData['preshared_key']) ? (string) $serverData['preshared_key'] : null,
            'install_protocol' => $mapString($serverData['install_protocol'] ?? null),
        ];

        foreach ($stringFields as $column => $value) {
            if ($value !== null) {
                $updates[] = $column . ' = ?';
                $params[] = $value;
                $updatedFields[] = $column;
            }
        }

        if (isset($serverData['ssh_port']) && $serverData['ssh_port'] !== null) {
            $port = (int) $serverData['ssh_port'];
            if ($port > 0) {
                $updates[] = 'port = ?';
                $params[] = $port;
                $updatedFields[] = 'port';
            }
        }

        if (isset($serverData['vpn_port']) && $serverData['vpn_port'] !== null) {
            $vpnPort = (int) $serverData['vpn_port'];
            if ($vpnPort > 0) {
                $updates[] = 'vpn_port = ?';
                $params[] = $vpnPort;
                $updatedFields[] = 'vpn_port';
            }
        }

        if (isset($serverData['awg_params'])) {
            $awgParams = $serverData['awg_params'];
            if (is_array($awgParams)) {
                $awgParams = json_encode($awgParams);
            }
            if (is_string($awgParams)) {
                $updates[] = 'awg_params = ?';
                $params[] = $awgParams;
                $updatedFields[] = 'awg_params';
            }
        }

        if (isset($serverData['install_options'])) {
            $installOptions = $serverData['install_options'];
            if (is_array($installOptions)) {
                $installOptions = json_encode($installOptions);
            }
            if (is_string($installOptions)) {
                $updates[] = 'install_options = ?';
                $params[] = $installOptions;
                $updatedFields[] = 'install_options';
            }
        }

        if ($updates) {
            $params[] = $this->serverId;
            $sql = 'UPDATE vpn_servers SET ' . implode(', ', $updates) . ' WHERE id = ?';
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $this->load();
        }

        $imported = 0;
        $failed = [];
        $clients = $serverData['clients'] ?? [];
        $shouldReplaceClients = $replaceClients && is_array($clients) && !empty($clients) && ($this->data['status'] ?? '') !== 'active';

        if ($shouldReplaceClients) {
            $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ?')->execute([$this->serverId]);
            $this->load();
        }

        if (is_array($clients) && !empty($clients)) {
            $serverRecord = $this->getData();
            foreach ($clients as $clientData) {
                try {
                    $id = VpnClient::importFromBackup($serverRecord, $userId, $clientData);
                    if ($id !== null) {
                        $imported++;
                    }
                } catch (Exception $e) {
                    $failed[] = $e->getMessage();
                }
            }
        }

        return [
            'updated_fields' => $updatedFields,
            'imported_clients' => $imported,
            'client_errors' => $failed,
        ];
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

        $output = Ssh::exec($this->data, $pathPrefix . $prepared, ['timeout' => 900])->output;

        // If sudo auth fails but user can run docker without sudo, retry docker commands directly.
        if ($needsSudo && $isDockerCommand && Ssh::isSudoAuthFailure($output)) {
            // Update cache: this server doesn't need sudo for docker
            if ($this->serverId !== null) {
                self::$dockerSudoCache[$this->serverId] = false;
            }
            $output = Ssh::exec($this->data, $pathPrefix . $baseCommand, ['timeout' => 900])->output;
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
    public static function listByUser(int $userId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute([$userId]);
        return array_map([self::class, 'decryptServerSecrets'], $stmt->fetchAll());
    }

    /**
     * Get all servers (admin only)
     */
    public static function listAll(): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->query('SELECT s.*, u.email as user_email FROM vpn_servers s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC');
        return array_map([self::class, 'decryptServerSecrets'], $stmt->fetchAll());
    }

    /**
     * Delete server
     */
    public function delete(): bool
    {
        // Stop and remove container
        try {
            $containerName = $this->data['container_name'];
            $this->executeCommand("docker stop {$containerName} 2>/dev/null || true", true);
            $this->executeCommand("docker rm -fv {$containerName} 2>/dev/null || true", true);
            $this->executeCommand("rm -rf /opt/amnezia/amnezia-awg", true);
        } catch (Exception $e) {
            // Ignore errors during cleanup
        }

        // Pool cleanup: if this server was a pool's active member, clear the
        // pointer so the pool doesn't reference a deleted server. Membership is
        // dropped automatically with the row.
        $pdo = DB::conn();
        try {
            $pdo->prepare('UPDATE server_pools SET active_server_id = NULL WHERE active_server_id = ?')
                ->execute([$this->serverId]);
        } catch (Throwable $e) {
            // server_pools may not exist on older schemas; ignore.
        }

        // Delete from database
        $stmt = $pdo->prepare('DELETE FROM vpn_servers WHERE id = ?');
        return $stmt->execute([$this->serverId]);
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
