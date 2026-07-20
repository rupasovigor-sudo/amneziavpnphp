<?php

/**
 * BackupManager — encrypted panel backups to S3-compatible storage.
 *
 * A backup is a full logical dump of the panel DB (all tables: servers with SSH
 * creds, pool identity, client keys, API tokens, users) plus the .env — gzipped
 * and encrypted with a passphrase (AES-256-GCM), then uploaded to an S3 bucket.
 * Because the dump contains secrets, encryption is mandatory: the passphrase is
 * the "second key" the operator keeps out of band.
 *
 * No external tools/SDK: the DB dump is done via PDO (portable, small DB) and S3
 * is spoken directly with hand-rolled AWS SigV4 (path-style).
 *
 * Settings live in the `settings` table (namespace 'backup', global user_id 0);
 * the S3 secret and passphrase are stored encrypted via SecretBox.
 */
class BackupManager
{
    private const NS = 'backup';
    private const PREFIX = 'panel-backup/';       // key prefix inside the bucket
    private const MAGIC = "AWGBAK1\n";            // file header (plaintext, pre-encryption marker not used)

    /* ------------------------------------------------------------------ */
    /* Settings                                                            */
    /* ------------------------------------------------------------------ */

    /** @return array<string,mixed> decrypted settings (secrets in the clear for use) */
    public static function getSettings(): array
    {
        $out = [
            's3_endpoint' => '', 's3_region' => '', 's3_bucket' => '',
            's3_key' => '', 's3_secret' => '', 'passphrase' => '',
            'retention' => 14, 'schedule' => 'off',
        ];
        try {
            $stmt = DB::conn()->prepare('SELECT `key`, `value` FROM settings WHERE namespace = ?');
            $stmt->execute([self::NS]);
            foreach ($stmt->fetchAll(PDO::FETCH_KEY_PAIR) as $k => $v) {
                // `value` is a JSON column.
                $decoded = json_decode((string) $v, true);
                $v = ($decoded === null && trim((string) $v) !== 'null') ? $v : $decoded;
                if (in_array($k, ['s3_secret', 'passphrase'], true)) {
                    $v = (string) SecretBox::decryptNullable((string) $v);
                }
                $out[$k] = $v;
            }
        } catch (Throwable $e) {
            error_log('BackupManager::getSettings: ' . $e->getMessage());
        }
        $out['retention'] = (int) $out['retention'] ?: 14;
        return $out;
    }

    /** Persist settings; s3_secret/passphrase encrypted. Empty secret = keep existing. */
    public static function saveSettings(array $in): void
    {
        $cur = self::getSettings();
        $pdo = DB::conn();
        $set = static function (string $k, $v) use ($pdo): void {
            // `value` is a JSON column — store JSON-encoded.
            $pdo->prepare(
                'INSERT INTO settings (user_id, namespace, `key`, `value`, created_at, updated_at)
                 VALUES (0, ?, ?, ?, NOW(), NOW())
                 ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_at = NOW()'
            )->execute([self::NS, $k, json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)]);
        };
        foreach (['s3_endpoint', 's3_region', 's3_bucket', 's3_key'] as $k) {
            if (array_key_exists($k, $in)) {
                $set($k, trim((string) $in[$k]));
            }
        }
        if (array_key_exists('retention', $in)) {
            $set('retention', max(1, (int) $in['retention']));
        }
        if (array_key_exists('schedule', $in)) {
            $sched = in_array($in['schedule'], ['off', 'daily', '12h', '6h'], true) ? $in['schedule'] : 'off';
            $set('schedule', $sched);
        }
        // Secrets: only overwrite when a non-empty value is supplied.
        foreach (['s3_secret', 'passphrase'] as $k) {
            if (array_key_exists($k, $in) && trim((string) $in[$k]) !== '') {
                $set($k, (string) SecretBox::encryptNullable(trim((string) $in[$k])));
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* S3 (AWS SigV4, path-style)                                          */
    /* ------------------------------------------------------------------ */

    /**
     * @return array{code:int, body:string, error:string, headers:string}
     */
    private static function s3(string $method, string $key, string $body, string $query, array $s): array
    {
        $endpoint = (string) $s['s3_endpoint'];
        $region   = (string) $s['s3_region'];
        $bucket   = (string) $s['s3_bucket'];
        $access   = (string) $s['s3_key'];
        $secret   = (string) $s['s3_secret'];
        $service  = 's3';

        $path = '/' . $bucket . ($key !== '' ? '/' . ltrim($key, '/') : '');
        $uri  = implode('/', array_map('rawurlencode', explode('/', $path)));

        $now  = gmdate('Ymd\THis\Z');
        $date = substr($now, 0, 8);
        $payloadHash = hash('sha256', $body);

        $canonicalHeaders = "host:{$endpoint}\nx-amz-content-sha256:{$payloadHash}\nx-amz-date:{$now}\n";
        $signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
        $canonicalRequest = "{$method}\n{$uri}\n{$query}\n{$canonicalHeaders}\n{$signedHeaders}\n{$payloadHash}";
        $scope = "{$date}/{$region}/{$service}/aws4_request";
        $stringToSign = "AWS4-HMAC-SHA256\n{$now}\n{$scope}\n" . hash('sha256', $canonicalRequest);
        $kDate    = hash_hmac('sha256', $date, 'AWS4' . $secret, true);
        $kRegion  = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        $signature = hash_hmac('sha256', $stringToSign, $kSigning);
        $auth = "AWS4-HMAC-SHA256 Credential={$access}/{$scope}, SignedHeaders={$signedHeaders}, Signature={$signature}";

        $url = "https://{$endpoint}{$uri}" . ($query !== '' ? '?' . $query : '');
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => 120,
            CURLOPT_HTTPHEADER => [
                "Host: {$endpoint}",
                "x-amz-date: {$now}",
                "x-amz-content-sha256: {$payloadHash}",
                "Authorization: {$auth}",
            ],
        ]);
        if ($method === 'PUT') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $raw = (string) curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hsize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $err = curl_error($ch);
        curl_close($ch);
        return ['code' => $code, 'body' => substr($raw, $hsize), 'error' => $err, 'headers' => substr($raw, 0, $hsize)];
    }

    /** Verify S3 access with a put/get/delete round-trip. */
    public static function testConnection(?array $s = null): array
    {
        $s = $s ?? self::getSettings();
        foreach (['s3_endpoint', 's3_region', 's3_bucket', 's3_key', 's3_secret'] as $f) {
            if (trim((string) ($s[$f] ?? '')) === '') {
                return ['success' => false, 'message' => "Не заполнено: {$f}"];
            }
        }
        $key = self::PREFIX . '_conn_test_' . gmdate('Ymd\THis\Z') . '.txt';
        $put = self::s3('PUT', $key, "ok\n", '', $s);
        if ($put['code'] !== 200) {
            return ['success' => false, 'message' => "PUT HTTP {$put['code']} " . ($put['error'] ?: substr(trim($put['body']), 0, 200))];
        }
        $get = self::s3('GET', $key, '', '', $s);
        self::s3('DELETE', $key, '', '', $s);
        if ($get['code'] !== 200 || trim($get['body']) !== 'ok') {
            return ['success' => false, 'message' => "GET HTTP {$get['code']} (проверка чтения не прошла)"];
        }
        return ['success' => true, 'message' => 'S3 доступ подтверждён (запись/чтение/удаление)'];
    }

    /* ------------------------------------------------------------------ */
    /* Crypto (AES-256-GCM, passphrase → PBKDF2)                           */
    /* ------------------------------------------------------------------ */

    private static function encrypt(string $data, string $passphrase): string
    {
        $salt = random_bytes(16);
        $iv   = random_bytes(12);
        $key  = hash_pbkdf2('sha256', $passphrase, $salt, 120000, 32, true);
        $tag  = '';
        $ct   = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($ct === false) {
            throw new RuntimeException('encrypt failed');
        }
        return "AGCM1" . $salt . $iv . $tag . $ct;
    }

    private static function decrypt(string $blob, string $passphrase): string
    {
        if (substr($blob, 0, 5) !== 'AGCM1') {
            throw new RuntimeException('Не формат бэкапа (bad magic)');
        }
        $salt = substr($blob, 5, 16);
        $iv   = substr($blob, 21, 12);
        $tag  = substr($blob, 33, 16);
        $ct   = substr($blob, 49);
        $key  = hash_pbkdf2('sha256', $passphrase, $salt, 120000, 32, true);
        $pt   = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($pt === false) {
            throw new RuntimeException('Расшифровка не удалась (неверный passphrase или повреждён файл)');
        }
        return $pt;
    }

    /* ------------------------------------------------------------------ */
    /* DB dump / restore (PDO-based)                                       */
    /* ------------------------------------------------------------------ */

    private static function dumpDatabase(): string
    {
        $pdo = DB::conn();
        $db  = (string) Config::get('DB_DATABASE');
        $sql = "-- amnezia-panel backup " . gmdate('c') . "\n";
        $sql .= "SET FOREIGN_KEY_CHECKS=0;\nSET NAMES utf8mb4;\n\n";
        $tables = $pdo->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
        foreach ($tables as $table) {
            $create = $pdo->query('SHOW CREATE TABLE `' . str_replace('`', '', $table) . '`')->fetch(PDO::FETCH_ASSOC);
            $createSql = $create['Create Table'] ?? ($create['Create View'] ?? null);
            if ($createSql === null) {
                continue;
            }
            $sql .= "DROP TABLE IF EXISTS `{$table}`;\n{$createSql};\n";
            $rows = $pdo->query('SELECT * FROM `' . str_replace('`', '', $table) . '`');
            $cols = null;
            $batch = [];
            foreach ($rows as $row) {
                if ($cols === null) {
                    $cols = '`' . implode('`,`', array_keys($row)) . '`';
                }
                $vals = [];
                foreach ($row as $v) {
                    $vals[] = $v === null ? 'NULL' : $pdo->quote((string) $v);
                }
                $batch[] = '(' . implode(',', $vals) . ')';
                if (count($batch) >= 200) {
                    $sql .= "INSERT INTO `{$table}` ({$cols}) VALUES\n" . implode(",\n", $batch) . ";\n";
                    $batch = [];
                }
            }
            if ($batch) {
                $sql .= "INSERT INTO `{$table}` ({$cols}) VALUES\n" . implode(",\n", $batch) . ";\n";
            }
            $sql .= "\n";
        }
        $sql .= "SET FOREIGN_KEY_CHECKS=1;\n";
        return $sql;
    }

    /** Execute a dump SQL string statement-by-statement. */
    private static function loadDatabase(string $sql): void
    {
        $pdo = DB::conn();
        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        // Split on ";\n" boundaries; good enough for our own dumps (values are
        // single-quoted via PDO::quote, and CREATE statements end with ";\n").
        $buffer = '';
        foreach (preg_split('/;\r?\n/', $sql) as $chunk) {
            $stmt = trim($buffer . $chunk);
            $buffer = '';
            if ($stmt === '' || str_starts_with($stmt, '--')) {
                continue;
            }
            try {
                $pdo->exec($stmt);
            } catch (Throwable $e) {
                // A statement may legitimately span the naive split (e.g. a value
                // containing ";\n"); re-buffer and continue.
                $buffer = $stmt . ";\n";
            }
        }
        $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
    }

    /* ------------------------------------------------------------------ */
    /* Backup / restore / list / delete                                   */
    /* ------------------------------------------------------------------ */

    /** Create a backup: dump DB (+.env) → gzip → encrypt → upload → rotate. */
    public static function createBackup(string $trigger = 'manual'): array
    {
        $s = self::getSettings();
        if (trim((string) $s['passphrase']) === '') {
            return ['success' => false, 'message' => 'Не задан passphrase шифрования (Настройки → Бэкап)'];
        }
        $t = self::testConnection($s);
        if (empty($t['success'])) {
            return ['success' => false, 'message' => 'S3 недоступен: ' . $t['message']];
        }

        // Bundle: a tiny tar-like container of dump.sql + .env (length-prefixed).
        $dump = self::dumpDatabase();
        $env = '';
        $envPath = dirname(__DIR__) . '/.env';
        if (is_readable($envPath)) {
            $env = (string) file_get_contents($envPath);
        }
        $bundle = json_encode([
            'v' => 1,
            'created' => gmdate('c'),
            'trigger' => $trigger,
            'db' => Config::get('DB_DATABASE'),
            'dump' => base64_encode($dump),
            'env' => base64_encode($env),
        ], JSON_UNESCAPED_SLASHES);

        $gz = gzencode($bundle, 6);
        $enc = self::encrypt($gz, (string) $s['passphrase']);

        $key = self::PREFIX . 'panel-' . gmdate('Ymd-His') . '.awgbak';
        $put = self::s3('PUT', $key, $enc, '', $s);
        if ($put['code'] !== 200) {
            return ['success' => false, 'message' => "Загрузка в S3 не удалась: HTTP {$put['code']} " . ($put['error'] ?: '')];
        }
        $rotated = self::rotate($s);
        return [
            'success' => true,
            'message' => 'Бэкап создан: ' . basename($key) . ' (' . self::human(strlen($enc)) . ')' . ($rotated ? ", удалено старых: {$rotated}" : ''),
            'key' => $key,
            'size' => strlen($enc),
        ];
    }

    /** List backups from S3 (newest first). */
    public static function listBackups(?array $s = null): array
    {
        $s = $s ?? self::getSettings();
        if (trim((string) $s['s3_bucket']) === '') {
            return [];
        }
        $query = 'list-type=2&prefix=' . rawurlencode(self::PREFIX);
        $res = self::s3('GET', '', '', $query, $s);
        if ($res['code'] !== 200) {
            return [];
        }
        $items = [];
        if (preg_match_all('#<Contents>(.*?)</Contents>#s', $res['body'], $m)) {
            foreach ($m[1] as $c) {
                if (!preg_match('#<Key>(.*?)</Key>#', $c, $mk)) {
                    continue;
                }
                $key = html_entity_decode($mk[1]);
                if (!str_ends_with($key, '.awgbak')) {
                    continue;
                }
                preg_match('#<Size>(\d+)</Size>#', $c, $ms);
                preg_match('#<LastModified>(.*?)</LastModified>#', $c, $md);
                $items[] = [
                    'key' => $key,
                    'name' => basename($key),
                    'size' => (int) ($ms[1] ?? 0),
                    'size_h' => self::human((int) ($ms[1] ?? 0)),
                    'modified' => $md[1] ?? '',
                ];
            }
        }
        usort($items, static fn($a, $b) => strcmp($b['key'], $a['key']));
        return $items;
    }

    /** Restore the panel DB from a backup key. */
    public static function restoreBackup(string $key): array
    {
        $s = self::getSettings();
        if (trim((string) $s['passphrase']) === '') {
            return ['success' => false, 'message' => 'Не задан passphrase (нужен тот, которым шифровали бэкап)'];
        }
        $res = self::s3('GET', $key, '', '', $s);
        if ($res['code'] !== 200) {
            return ['success' => false, 'message' => "Скачивание не удалось: HTTP {$res['code']}"];
        }
        try {
            $gz = self::decrypt($res['body'], (string) $s['passphrase']);
            $bundle = json_decode((string) gzdecode($gz), true);
            if (!is_array($bundle) || empty($bundle['dump'])) {
                return ['success' => false, 'message' => 'Повреждённый или несовместимый бэкап'];
            }
            $dump = (string) base64_decode((string) $bundle['dump']);
            self::loadDatabase($dump);
            return ['success' => true, 'message' => 'БД восстановлена из ' . basename($key) . ' (от ' . ($bundle['created'] ?? '?') . ')'];
        } catch (Throwable $e) {
            return ['success' => false, 'message' => 'Ошибка восстановления: ' . $e->getMessage()];
        }
    }

    /**
     * Read a backup's metadata WITHOUT touching the DB. Surfaces the
     * APP_ENCRYPTION_KEY stored in the backed-up .env and whether it matches the
     * current host — the key needed to decrypt the restored secrets on a new host (DR).
     */
    public static function inspectBackup(string $key): array
    {
        $s = self::getSettings();
        if (trim((string) $s['passphrase']) === '') {
            return ['success' => false, 'message' => 'Не задан passphrase'];
        }
        $res = self::s3('GET', $key, '', '', $s);
        if ($res['code'] !== 200) {
            return ['success' => false, 'message' => "Скачивание не удалось: HTTP {$res['code']}"];
        }
        try {
            $gz = self::decrypt($res['body'], (string) $s['passphrase']);
            $bundle = json_decode((string) gzdecode($gz), true);
            if (!is_array($bundle)) {
                return ['success' => false, 'message' => 'Повреждённый бэкап'];
            }
            $env = (string) base64_decode((string) ($bundle['env'] ?? ''));
            $backupKey = '';
            if (preg_match('/^APP_ENCRYPTION_KEY\s*=\s*(.+)$/m', $env, $mk)) {
                $backupKey = trim($mk[1], " \"'\r\t");
            }
            $curKey = trim((string) Config::get('APP_ENCRYPTION_KEY', ''));
            return [
                'success' => true,
                'name' => basename($key),
                'created' => $bundle['created'] ?? '?',
                'trigger' => $bundle['trigger'] ?? '?',
                'db' => $bundle['db'] ?? '?',
                'app_key' => $backupKey,
                'app_key_matches' => ($backupKey !== '' && $backupKey === $curKey),
            ];
        } catch (Throwable $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    /** Return the .env stored inside a backup (for DR: recover APP_ENCRYPTION_KEY). */
    public static function getBackupEnv(string $key, ?array $s = null): array
    {
        $s = $s ?? self::getSettings();
        if (trim((string) $s['passphrase']) === '') {
            return ['success' => false, 'message' => 'Не задан passphrase'];
        }
        $res = self::s3('GET', $key, '', '', $s);
        if ($res['code'] !== 200) {
            return ['success' => false, 'message' => "HTTP {$res['code']}"];
        }
        try {
            $gz = self::decrypt($res['body'], (string) $s['passphrase']);
            $bundle = json_decode((string) gzdecode($gz), true);
            return ['success' => true, 'env' => (string) base64_decode((string) ($bundle['env'] ?? '')), 'created' => $bundle['created'] ?? '?'];
        } catch (Throwable $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    public static function deleteBackup(string $key): array
    {
        $s = self::getSettings();
        $res = self::s3('DELETE', $key, '', '', $s);
        return ['success' => $res['code'] === 204 || $res['code'] === 200, 'message' => $res['code'] < 300 ? 'Удалён' : "HTTP {$res['code']}"];
    }

    /** Keep the newest N backups, delete the rest. Returns count removed. */
    public static function rotate(?array $s = null): int
    {
        $s = $s ?? self::getSettings();
        $keep = max(1, (int) $s['retention']);
        $list = self::listBackups($s);
        $removed = 0;
        foreach (array_slice($list, $keep) as $old) {
            $d = self::s3('DELETE', $old['key'], '', '', $s);
            if ($d['code'] < 300) {
                $removed++;
            }
        }
        return $removed;
    }

    private static function human(int $bytes): string
    {
        $u = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        $n = (float) $bytes;
        while ($n >= 1024 && $i < count($u) - 1) {
            $n /= 1024;
            $i++;
        }
        return round($n, $n < 10 && $i > 0 ? 1 : 0) . ' ' . $u[$i];
    }
}
