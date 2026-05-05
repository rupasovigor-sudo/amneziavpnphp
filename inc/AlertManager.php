<?php

class AlertManager
{
    private PDO $db;
    private bool $enabled;
    private int $failureThreshold;
    private int $cooldownSeconds;
    private string $appName;

    public function __construct(?PDO $db = null)
    {
        $this->db = $db ?: DB::conn();
        $this->enabled = self::boolConfig('ALERTS_ENABLED', false);
        $this->failureThreshold = max(1, (int) Config::get('ALERTS_FAILURE_THRESHOLD', '2'));
        $this->cooldownSeconds = max(60, (int) Config::get('ALERTS_COOLDOWN_SECONDS', '1800'));
        $this->appName = (string) Config::get('APP_NAME', 'Amnezia VPN Panel');
        $this->ensureSchema();
    }

    public function recordCheck(
        ?int $serverId,
        string $serverName,
        string $checkName,
        bool $ok,
        string $message,
        string $severity = 'critical',
        ?int $failureThreshold = null
    ): void {
        if (!$this->enabled) {
            return;
        }

        $alertKey = $this->buildAlertKey($serverId, $checkName);
        $severity = $severity === 'warning' ? 'warning' : 'critical';
        $requiredFailures = max(1, $failureThreshold ?? $this->failureThreshold);

        if ($ok) {
            $this->resolveAlert($alertKey, $serverId, $serverName, $checkName);
            return;
        }

        $this->upsertProblem($alertKey, $serverId, $severity, $message);
        $state = $this->getState($alertKey);
        if (!$state) {
            return;
        }

        $failCount = (int) ($state['fail_count'] ?? 0);
        if ($failCount < $requiredFailures) {
            return;
        }

        $lastSentAt = $state['last_sent_at'] ?? null;
        if ($lastSentAt && (time() - strtotime((string) $lastSentAt)) < $this->cooldownSeconds) {
            return;
        }

        $subject = sprintf('[%s] %s: %s', strtoupper($severity), $serverName, $checkName);
        $body = implode("\n", [
            "{$this->appName}",
            "",
            "Status: " . strtoupper($severity),
            "Server: {$serverName}" . ($serverId !== null ? " (#{$serverId})" : ''),
            "Check: {$checkName}",
            "Failures: {$failCount}",
            "Message: {$message}",
            "Time: " . date('Y-m-d H:i:s T'),
        ]);

        if ($this->send($subject, $body)) {
            $stmt = $this->db->prepare('UPDATE alert_states SET last_sent_at = NOW() WHERE alert_key = ?');
            $stmt->execute([$alertKey]);
        }
    }

    public function recordProblem(?int $serverId, string $serverName, string $checkName, string $message, string $severity = 'critical'): void
    {
        $this->recordCheck($serverId, $serverName, $checkName, false, $message, $severity);
    }

    public function recordEvent(?int $serverId, string $serverName, string $eventName, string $message, string $severity = 'warning', ?string $dedupeKey = null): void
    {
        if (!$this->enabled) {
            return;
        }

        $severity = $severity === 'critical' ? 'critical' : 'warning';
        $eventKey = 'event:' . ($dedupeKey ?: $this->buildAlertKey($serverId, $eventName));
        $state = $this->getState($eventKey);
        $lastSentAt = $state['last_sent_at'] ?? null;
        if ($lastSentAt && (time() - strtotime((string) $lastSentAt)) < $this->cooldownSeconds) {
            return;
        }

        $subject = sprintf('[%s] %s: %s', strtoupper($severity), $serverName, $eventName);
        $body = implode("\n", [
            "{$this->appName}",
            "",
            "Event: " . strtoupper($severity),
            "Scope: {$serverName}" . ($serverId !== null ? " (#{$serverId})" : ''),
            "Name: {$eventName}",
            "Message: {$message}",
            "Time: " . date('Y-m-d H:i:s T'),
        ]);

        if ($this->send($subject, $body)) {
            $stmt = $this->db->prepare("
                INSERT INTO alert_states
                    (alert_key, server_id, severity, status, fail_count, message, first_seen_at, last_seen_at, last_sent_at)
                VALUES
                    (?, ?, ?, 'ok', 0, ?, NOW(), NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                    server_id = VALUES(server_id),
                    severity = VALUES(severity),
                    status = 'ok',
                    fail_count = 0,
                    message = VALUES(message),
                    last_seen_at = NOW(),
                    last_sent_at = NOW()
            ");
            $stmt->execute([$eventKey, $serverId, $severity, $message]);
        }
    }

    public function sendTest(string $channel = 'all'): bool
    {
        $subject = sprintf('[TEST] %s notifications', $this->appName);
        $body = implode("\n", [
            "{$this->appName}",
            "",
            "Это тестовое уведомление из настроек панели.",
            "Time: " . date('Y-m-d H:i:s T'),
        ]);

        if ($channel === 'telegram') {
            return $this->sendTelegram($subject, $body);
        }
        if ($channel === 'email') {
            return $this->sendEmail($subject, $body);
        }

        return $this->send($subject, $body);
    }

    private function resolveAlert(string $alertKey, ?int $serverId, string $serverName, string $checkName): void
    {
        $state = $this->getState($alertKey);
        if (!$state || ($state['status'] ?? '') !== 'open') {
            $this->upsertOk($alertKey, $serverId);
            return;
        }

        $alertWasSentForCurrentIncident = false;
        $lastSentAt = $state['last_sent_at'] ?? null;
        $firstSeenAt = $state['first_seen_at'] ?? null;
        if ($lastSentAt) {
            $lastSentTs = strtotime((string) $lastSentAt);
            $firstSeenTs = $firstSeenAt ? strtotime((string) $firstSeenAt) : null;
            $alertWasSentForCurrentIncident = $lastSentTs !== false
                && ($firstSeenTs === null || $firstSeenTs === false || $lastSentTs >= $firstSeenTs);
        }

        $stmt = $this->db->prepare("
            UPDATE alert_states
            SET status = 'ok',
                fail_count = 0,
                last_seen_at = NOW(),
                resolved_at = NOW(),
                message = NULL
            WHERE alert_key = ?
        ");
        $stmt->execute([$alertKey]);

        if (!$alertWasSentForCurrentIncident) {
            return;
        }

        $subject = sprintf('[RESOLVED] %s: %s', $serverName, $checkName);
        $body = implode("\n", [
            "{$this->appName}",
            "",
            "Status: RESOLVED",
            "Server: {$serverName}" . ($serverId !== null ? " (#{$serverId})" : ''),
            "Check: {$checkName}",
            "Time: " . date('Y-m-d H:i:s T'),
        ]);

        $this->send($subject, $body);
    }

    private function upsertProblem(string $alertKey, ?int $serverId, string $severity, string $message): void
    {
        $stmt = $this->db->prepare("
            INSERT INTO alert_states
                (alert_key, server_id, severity, status, fail_count, message, first_seen_at, last_seen_at)
            VALUES
                (?, ?, ?, 'open', 1, ?, NOW(), NOW())
            ON DUPLICATE KEY UPDATE
                server_id = VALUES(server_id),
                severity = VALUES(severity),
                fail_count = IF(alert_states.status = 'open', alert_states.fail_count + 1, 1),
                message = VALUES(message),
                first_seen_at = IF(alert_states.status = 'open' AND alert_states.first_seen_at IS NOT NULL, alert_states.first_seen_at, NOW()),
                last_sent_at = IF(alert_states.status = 'open', alert_states.last_sent_at, NULL),
                last_seen_at = NOW(),
                resolved_at = NULL,
                status = 'open'
        ");
        $stmt->execute([$alertKey, $serverId, $severity, $message]);
    }

    private function upsertOk(string $alertKey, ?int $serverId): void
    {
        $stmt = $this->db->prepare("
            INSERT INTO alert_states
                (alert_key, server_id, status, fail_count, last_seen_at)
            VALUES
                (?, ?, 'ok', 0, NOW())
            ON DUPLICATE KEY UPDATE
                server_id = VALUES(server_id),
                status = 'ok',
                fail_count = 0,
                last_seen_at = NOW()
        ");
        $stmt->execute([$alertKey, $serverId]);
    }

    private function getState(string $alertKey): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM alert_states WHERE alert_key = ? LIMIT 1');
        $stmt->execute([$alertKey]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function send(string $subject, string $body): bool
    {
        $sent = false;
        if (self::boolConfig('TELEGRAM_ALERTS_ENABLED', false)) {
            $sent = $this->sendTelegram($subject, $body) || $sent;
        }
        if (self::boolConfig('EMAIL_ALERTS_ENABLED', false)) {
            $sent = $this->sendEmail($subject, $body) || $sent;
        }
        return $sent;
    }

    private function sendTelegram(string $subject, string $body): bool
    {
        $token = trim((string) Config::get('TELEGRAM_BOT_TOKEN', ''));
        $chatId = trim((string) Config::get('TELEGRAM_CHAT_ID', ''));
        if ($token === '' || $chatId === '') {
            return false;
        }

        $text = $subject . "\n\n" . $body;
        $ch = curl_init('https://api.telegram.org/bot' . rawurlencode($token) . '/sendMessage');
        if (!$ch) {
            return false;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => [
                'chat_id' => $chatId,
                'text' => $text,
                'disable_web_page_preview' => '1',
            ],
            CURLOPT_TIMEOUT => 10,
        ]);

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false || $httpCode < 200 || $httpCode >= 300) {
            error_log('Telegram alert failed: HTTP ' . $httpCode . ' ' . $error . ' ' . substr((string) $response, 0, 200));
            return false;
        }

        return true;
    }

    private function sendEmail(string $subject, string $body): bool
    {
        $to = trim((string) Config::get('ALERT_EMAIL_TO', ''));
        $from = trim((string) Config::get('SMTP_FROM', ''));
        if ($to === '' || $from === '') {
            return false;
        }

        if (trim((string) Config::get('SMTP_HOST', '')) !== '') {
            return $this->sendSmtpEmail($to, $from, $subject, $body);
        }

        $headers = [
            'From: ' . $this->formatMailFrom(),
            'Content-Type: text/plain; charset=UTF-8',
            'X-Mailer: Amnezia Panel',
        ];

        if (function_exists('mb_encode_mimeheader')) {
            $subject = mb_encode_mimeheader($subject, 'UTF-8');
        }

        $ok = @mail($to, $subject, $body, implode("\r\n", $headers));
        if (!$ok) {
            error_log('Email alert failed via mail()');
        }
        return $ok;
    }

    private function sendSmtpEmail(string $to, string $from, string $subject, string $body): bool
    {
        $host = trim((string) Config::get('SMTP_HOST', ''));
        $port = (int) Config::get('SMTP_PORT', '587');
        $username = trim((string) Config::get('SMTP_USERNAME', ''));
        $password = (string) Config::get('SMTP_PASSWORD', '');
        $tls = self::boolConfig('SMTP_TLS', true);

        $remote = ($tls && $port === 465 ? 'ssl://' : '') . $host . ':' . $port;
        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client($remote, $errno, $errstr, 10, STREAM_CLIENT_CONNECT);
        if (!$fp) {
            error_log("SMTP alert connect failed: {$errno} {$errstr}");
            return false;
        }

        stream_set_timeout($fp, 10);

        try {
            $this->smtpExpect($fp, [220]);
            $this->smtpCommand($fp, 'EHLO ' . (gethostname() ?: 'localhost'), [250]);

            if ($tls && $port !== 465) {
                $this->smtpCommand($fp, 'STARTTLS', [220]);
                if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new RuntimeException('STARTTLS negotiation failed');
                }
                $this->smtpCommand($fp, 'EHLO ' . (gethostname() ?: 'localhost'), [250]);
            }

            if ($username !== '') {
                $this->smtpCommand($fp, 'AUTH LOGIN', [334]);
                $this->smtpCommand($fp, base64_encode($username), [334]);
                $this->smtpCommand($fp, base64_encode($password), [235]);
            }

            $this->smtpCommand($fp, 'MAIL FROM:<' . $from . '>', [250]);
            foreach (preg_split('/\s*,\s*/', $to) ?: [] as $recipient) {
                $recipient = trim($recipient);
                if ($recipient !== '') {
                    $this->smtpCommand($fp, 'RCPT TO:<' . $recipient . '>', [250, 251]);
                }
            }
            $this->smtpCommand($fp, 'DATA', [354]);

            $message = $this->buildMimeMessage($to, $from, $subject, $body);
            fwrite($fp, str_replace("\n.", "\n..", $message) . "\r\n.\r\n");
            $this->smtpExpect($fp, [250]);
            $this->smtpCommand($fp, 'QUIT', [221]);
            fclose($fp);
            return true;
        } catch (Throwable $e) {
            fclose($fp);
            error_log('SMTP alert failed: ' . $e->getMessage());
            return false;
        }
    }

    private function buildMimeMessage(string $to, string $from, string $subject, string $body): string
    {
        $encodedSubject = function_exists('mb_encode_mimeheader')
            ? mb_encode_mimeheader($subject, 'UTF-8')
            : $subject;

        $headers = [
            'Date: ' . date(DATE_RFC2822),
            'From: ' . $this->formatMailFrom(),
            'To: ' . $to,
            'Subject: ' . $encodedSubject,
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
        ];

        return implode("\r\n", $headers) . "\r\n\r\n" . str_replace(["\r\n", "\r"], "\n", $body);
    }

    /**
     * @param resource $fp
     * @param array<int, int> $expectedCodes
     */
    private function smtpCommand($fp, string $command, array $expectedCodes): string
    {
        fwrite($fp, $command . "\r\n");
        return $this->smtpExpect($fp, $expectedCodes);
    }

    /**
     * @param resource $fp
     * @param array<int, int> $expectedCodes
     */
    private function smtpExpect($fp, array $expectedCodes): string
    {
        $response = '';
        while (($line = fgets($fp, 2048)) !== false) {
            $response .= $line;
            if (preg_match('/^(\d{3})(\s|-)/', $line, $m) && $m[2] === ' ') {
                $code = (int) $m[1];
                if (!in_array($code, $expectedCodes, true)) {
                    throw new RuntimeException('Unexpected SMTP response: ' . trim($response));
                }
                return $response;
            }
        }

        throw new RuntimeException('Empty SMTP response');
    }

    private function formatMailFrom(): string
    {
        $from = trim((string) Config::get('SMTP_FROM', ''));
        $name = trim((string) Config::get('SMTP_FROM_NAME', $this->appName));
        if ($name === '') {
            return $from;
        }

        return sprintf('"%s" <%s>', addcslashes($name, '"\\'), $from);
    }

    private function ensureSchema(): void
    {
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS alert_states (
              id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
              alert_key VARCHAR(191) NOT NULL,
              server_id INT UNSIGNED NULL,
              severity ENUM('warning', 'critical') NOT NULL DEFAULT 'warning',
              status ENUM('ok', 'open') NOT NULL DEFAULT 'ok',
              fail_count INT UNSIGNED NOT NULL DEFAULT 0,
              message TEXT NULL,
              first_seen_at TIMESTAMP NULL DEFAULT NULL,
              last_seen_at TIMESTAMP NULL DEFAULT NULL,
              last_sent_at TIMESTAMP NULL DEFAULT NULL,
              resolved_at TIMESTAMP NULL DEFAULT NULL,
              created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
              UNIQUE KEY uniq_alert_key (alert_key),
              INDEX idx_alert_server_status (server_id, status),
              INDEX idx_alert_last_seen (last_seen_at),
              CONSTRAINT fk_alert_states_server_runtime
                FOREIGN KEY (server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");
    }

    private function buildAlertKey(?int $serverId, string $checkName): string
    {
        $scope = $serverId !== null ? 'server:' . $serverId : 'panel';
        return $scope . ':' . preg_replace('/[^a-z0-9_.-]/i', '_', $checkName);
    }

    private static function boolConfig(string $key, bool $default): bool
    {
        $value = Config::get($key, $default ? '1' : '0');
        return in_array(strtolower((string) $value), ['1', 'true', 'yes', 'on'], true);
    }
}
