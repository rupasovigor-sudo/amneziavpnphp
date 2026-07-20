<?php

/**
 * Ssh — the single SSH/SCP execution layer for the panel.
 *
 * Replaces the three historical implementations (VpnServer::executeCommand,
 * VpnClient::executeServerCommand, ServerMonitoring::execSSH) with one
 * proc_open-based runner that:
 *
 *  - multiplexes connections via ControlMaster/ControlPersist, so repeated
 *    commands to the same server reuse one authenticated TCP session
 *    (critical for the metrics collector, which runs several commands per
 *    server per cycle);
 *  - supports both key and password auth; the password is passed through the
 *    SSHPASS environment variable (sshpass -e), never on the command line,
 *    so it does not leak into the process list;
 *  - enforces timeouts (`timeout --kill-after`) and surfaces the exit code,
 *    so callers can distinguish "command failed" from "empty output";
 *  - provides content upload over scp sharing the same multiplexed session.
 *
 * A server is described by the usual vpn_servers row subset:
 * host, port, username, password (plaintext), ssh_key (plaintext).
 */
class SshResult
{
    public int $exitCode;
    public string $output;

    public function __construct(int $exitCode, string $output)
    {
        $this->exitCode = $exitCode;
        $this->output = $output;
    }

    public function ok(): bool
    {
        return $this->exitCode === 0;
    }

    /** True when the local `timeout` wrapper killed the command. */
    public function timedOut(): bool
    {
        return $this->exitCode === 124 || $this->exitCode === 137;
    }

    /** True when ssh itself failed to connect/authenticate (exit 255). */
    public function connectionFailed(): bool
    {
        return $this->exitCode === 255;
    }
}

class Ssh
{
    private const CONTROL_DIR = '/tmp/amnezia-ssh';
    private const DEFAULT_TIMEOUT = 60;

    /**
     * Execute a command on a remote server.
     *
     * @param array $server  vpn_servers row (host, port, username, password, ssh_key)
     * @param string $command remote command (parsed by the remote login shell)
     * @param array $opts    timeout: seconds (default 60);
     *                       stderr: 'merge' (default) or 'discard'
     */
    public static function exec(array $server, string $command, array $opts = []): SshResult
    {
        $timeout = max(5, (int) ($opts['timeout'] ?? self::DEFAULT_TIMEOUT));
        $mergeStderr = ($opts['stderr'] ?? 'merge') !== 'discard';

        [$argv, $env, $keyFile] = self::buildClientArgv('ssh', $server, $timeout);
        $argv[] = self::destination($server);
        $argv[] = $command;

        try {
            return self::runProcess($argv, $env, $mergeStderr);
        } finally {
            self::cleanupKeyFile($keyFile);
        }
    }

    /**
     * Upload $content to $remotePath over scp (shares the multiplexed
     * connection), then chmod it to $mode.
     */
    public static function upload(array $server, string $remotePath, string $content, int $mode = 0600): SshResult
    {
        $localFile = tempnam(sys_get_temp_dir(), 'amz_upload_');
        if ($localFile === false) {
            return new SshResult(1, 'Failed to create temporary upload file');
        }
        file_put_contents($localFile, $content);
        chmod($localFile, 0600);

        [$argv, $env, $keyFile] = self::buildClientArgv('scp', $server, 300);
        $argv[] = $localFile;
        $argv[] = self::destination($server) . ':' . $remotePath;

        try {
            $result = self::runProcess($argv, $env, true);
            if ($result->ok()) {
                $chmod = self::exec($server, sprintf('chmod %o %s', $mode, escapeshellarg($remotePath)), ['timeout' => 20]);
                if (!$chmod->ok()) {
                    return new SshResult($chmod->exitCode, 'Uploaded but chmod failed: ' . $chmod->output);
                }
            }
            return $result;
        } finally {
            self::cleanupKeyFile($keyFile);
            if (file_exists($localFile)) {
                unlink($localFile);
            }
        }
    }

    /**
     * Wrap a remote command in sudo when the SSH user is not root.
     * With password auth the password is piped to `sudo -S` safely quoted;
     * with key-only auth passwordless sudo (`sudo -n`) is assumed.
     */
    public static function wrapSudo(array $server, string $command): string
    {
        if (strtolower((string) ($server['username'] ?? '')) === 'root') {
            return $command;
        }
        $password = (string) ($server['password'] ?? '');
        if ($password === '') {
            return 'sudo -n ' . $command;
        }
        // -p '' keeps the prompt out of stdout so parsers see clean output.
        return "printf '%s\\n' " . escapeshellarg($password) . " | sudo -S -p '' " . $command;
    }

    /** True when sudo failed to authenticate (used for docker-group retries). */
    public static function isSudoAuthFailure(string $output): bool
    {
        return (bool) preg_match('/incorrect password attempts|sorry, try again|a password is required/i', $output);
    }

    /**
     * True when ssh itself failed to establish the session, i.e. the remote
     * command never ran and $output is an ssh diagnostic, not command output.
     *
     * Deliberately narrow: a remote command may legitimately exit non-zero (or
     * even 255), so we require ssh's own exit code AND a recognisable transport
     * error. Callers of VpnServer::executeCommand() would otherwise parse the
     * error banner as if it were the command's result — e.g. a refused host key
     * looked like a server happily reporting no containers.
     */
    public static function isConnectionFailure(SshResult $result): bool
    {
        if ($result->exitCode !== 255) {
            return false;
        }
        return (bool) preg_match(
            '/REMOTE HOST IDENTIFICATION HAS CHANGED'
            . '|Host key verification failed'
            . '|Permission denied'
            . '|Connection (refused|closed|timed out|reset)'
            . '|No route to host'
            . '|Could not resolve hostname'
            . '|Network is unreachable'
            . '|Too many authentication failures'
            . '|kex_exchange_identification/i',
            $result->output
        );
    }

    /**
     * Build the local argv prefix for ssh/scp: timeout wrapper, sshpass when
     * using password auth, connection options, multiplexing and auth options.
     *
     * @return array{0: array, 1: ?array, 2: string} [argv, env, keyFile]
     */
    private static function buildClientArgv(string $binary, array $server, int $timeout): array
    {
        $port = (int) ($server['port'] ?? 22);
        $argv = ['timeout', '--kill-after=5s', $timeout . 's'];
        $env = null;
        $keyFile = '';

        $usesKey = !empty($server['ssh_key']);
        if (!$usesKey) {
            $argv[] = 'sshpass';
            $argv[] = '-e';
            $env = array_merge(self::currentEnv(), ['SSHPASS' => (string) ($server['password'] ?? '')]);
        }

        $argv[] = $binary;
        $argv[] = $binary === 'scp' ? '-P' : '-p';
        $argv[] = (string) $port;

        foreach (self::commonOptions() as $opt) {
            $argv[] = '-o';
            $argv[] = $opt;
        }

        if ($usesKey) {
            $keyFile = (string) tempnam(sys_get_temp_dir(), 'sshkey');
            file_put_contents($keyFile, self::normalizeKey((string) $server['ssh_key']));
            chmod($keyFile, 0600);
            array_push(
                $argv,
                '-i', $keyFile,
                '-o', 'IdentitiesOnly=yes',
                '-o', 'PubkeyAuthentication=yes',
                '-o', 'PreferredAuthentications=publickey'
            );
        } else {
            array_push(
                $argv,
                '-o', 'PreferredAuthentications=password',
                '-o', 'PubkeyAuthentication=no',
                '-o', 'NumberOfPasswordPrompts=1'
            );
        }

        return [$argv, $env, $keyFile];
    }

    private static function commonOptions(): array
    {
        $options = [
            'LogLevel=ERROR',
            'ConnectTimeout=10',
            'ConnectionAttempts=1',
            'ServerAliveInterval=10',
            'ServerAliveCountMax=2',
        ];

        // Host key handling. This panel SSHes into VPN nodes as root, so a MITM
        // on that path harvests the server password and can feed us any output
        // we then persist. StrictHostKeyChecking=no accepted a changed key
        // silently, forever.
        //
        // 'accept-new' keeps first contact frictionless (the key is recorded)
        // but REFUSES to connect if a known host's key later changes — which is
        // exactly the MITM case. A legitimately reprovisioned host is handled by
        // forgetHost(), called on delete and before a deploy.
        //
        // If the store is unusable we fall back to the old behaviour rather than
        // locking the panel out of every server.
        $knownHosts = self::knownHostsFile();
        if ($knownHosts !== null) {
            $options[] = 'StrictHostKeyChecking=accept-new';
            $options[] = 'UserKnownHostsFile=' . $knownHosts;
        } else {
            error_log('Ssh: known_hosts store unavailable, falling back to StrictHostKeyChecking=no');
            $options[] = 'StrictHostKeyChecking=no';
            $options[] = 'UserKnownHostsFile=/dev/null';
        }

        $controlDir = self::controlDir();
        if ($controlDir !== null) {
            $options[] = 'ControlMaster=auto';
            $options[] = 'ControlPath=' . $controlDir . '/%C';
            // Outlive the 60s metrics cycle so the daemon reuses the master
            // on every pass instead of re-handshaking each time.
            $options[] = 'ControlPersist=120';
        }

        return $options;
    }

    /**
     * Ensure a writable ControlPath directory and return it; null disables
     * multiplexing (SSH still works, just without connection reuse).
     * The directory is per-UID: the panel runs SSH both as www-data (web
     * requests) and root (metrics daemon, CLI), and a shared directory would
     * be writable only by whoever created it first.
     */
    /**
     * Persistent known_hosts store. Lives in the bind-mounted app dir so pinned
     * keys survive container restarts — a store that resets on every restart
     * would re-trust whatever answers next time and defeat the point.
     */
    private static function knownHostsFile(): ?string
    {
        $dir = dirname(__DIR__) . '/storage/ssh';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        if (!is_dir($dir) || !is_writable($dir)) {
            return null;
        }
        $file = $dir . '/known_hosts';
        if (!file_exists($file)) {
            @touch($file);
            @chmod($file, 0600);
        }
        return is_writable($file) ? $file : null;
    }

    /**
     * Drop a host's pinned key. Required when a host is legitimately rebuilt
     * (same IP, fresh OS = new key): without this, every later connection would
     * be refused as a suspected MITM.
     */
    public static function forgetHost(string $host, int $port = 22): void
    {
        $file = self::knownHostsFile();
        $host = trim($host);
        if ($file === null || $host === '') {
            return;
        }
        $target = ($port !== 22) ? '[' . $host . ']:' . $port : $host;
        $proc = @proc_open(
            ['ssh-keygen', '-f', $file, '-R', $target],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes
        );
        if (is_resource($proc)) {
            proc_close($proc);
        }
    }

    private static function controlDir(): ?string
    {
        $uid = function_exists('posix_geteuid') ? posix_geteuid() : getmyuid();
        $dir = self::CONTROL_DIR . '-' . $uid;
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        return (is_dir($dir) && is_writable($dir)) ? $dir : null;
    }

    private static function destination(array $server): string
    {
        return $server['username'] . '@' . $server['host'];
    }

    private static function runProcess(array $argv, ?array $env, bool $mergeStderr): SshResult
    {
        $descriptors = [
            0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => $mergeStderr ? ['redirect', 1] : ['file', '/dev/null', 'w'],
        ];

        $process = proc_open($argv, $descriptors, $pipes, null, $env);
        if (!is_resource($process)) {
            return new SshResult(1, 'Failed to start ssh process');
        }

        $output = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $exitCode = proc_close($process);

        return new SshResult($exitCode, $output);
    }

    /** Fix \r\n line endings and ensure a trailing newline in private keys. */
    private static function normalizeKey(string $key): string
    {
        $key = str_replace(["\r\n", "\r"], "\n", $key);
        if ($key !== '' && substr($key, -1) !== "\n") {
            $key .= "\n";
        }
        return $key;
    }

    private static function cleanupKeyFile(string $keyFile): void
    {
        if ($keyFile !== '' && file_exists($keyFile)) {
            unlink($keyFile);
        }
    }

    private static function currentEnv(): array
    {
        $env = getenv();
        return is_array($env) ? $env : [];
    }
}
