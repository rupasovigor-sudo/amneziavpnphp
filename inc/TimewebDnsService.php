<?php

/**
 * TimewebDnsService — manage the AmneziaWG endpoint domain's A-record via the
 * Timeweb Cloud DNS API (https://timeweb.cloud/api-docs#tag/Domeny).
 *
 * The panel points a third-level domain (e.g. awg.gptanalitika.com) at the
 * active VPN server. When a server is deployed we upsert an A-record so clients
 * can connect via <domain>:443 and the server can later be swapped by repointing
 * the record.
 *
 * The API token is stored in the `api_keys` table under service_name = 'timeweb'
 * (same place as the OpenRouter key), editable from Settings.
 */
class TimewebDnsService
{
    private const BASE_URL = 'https://api.timeweb.cloud';
    private const SERVICE = 'timeweb';

    /** Read the Timeweb API token from api_keys (service_name = 'timeweb'). */
    public static function getToken(): ?string
    {
        try {
            $stmt = DB::conn()->prepare("SELECT api_key FROM api_keys WHERE service_name = ? AND is_active = 1 LIMIT 1");
            $stmt->execute([self::SERVICE]);
            $token = $stmt->fetchColumn();
            $token = is_string($token) ? trim($token) : '';
            return $token !== '' ? $token : null;
        } catch (Throwable $e) {
            error_log('TimewebDnsService::getToken failed: ' . $e->getMessage());
            return null;
        }
    }

    public static function isConfigured(): bool
    {
        return self::getToken() !== null;
    }

    /**
     * Validate an API token by listing the account's domains. Pass null to
     * validate the stored token.
     *
     * @return array{success: bool, message: string, domains?: string[]}
     */
    public static function verifyToken(?string $token = null): array
    {
        $token = $token !== null ? trim($token) : self::getToken();
        if ($token === null || $token === '') {
            return ['success' => false, 'message' => 'Timeweb API token is empty'];
        }

        $res = self::request('GET', '/api/v1/domains', null, $token);
        if (!$res['ok']) {
            return ['success' => false, 'message' => "Token check failed: {$res['error']}"];
        }

        $domains = [];
        $list = is_array($res['body']) ? ($res['body']['domains'] ?? []) : [];
        if (is_array($list)) {
            foreach ($list as $d) {
                if (is_array($d) && !empty($d['fqdn'])) {
                    $domains[] = (string) $d['fqdn'];
                }
            }
        }

        return [
            'success' => true,
            'message' => 'Token is valid. Domains in account: ' . (count($domains) > 0 ? implode(', ', $domains) : '(none)'),
            'domains' => $domains,
        ];
    }

    /**
     * Split a full endpoint domain into its registered base domain and the
     * subdomain part. e.g. "awg.gptanalitika.com" => ["gptanalitika.com", "awg"].
     * Apex domains ("example.com") return an empty subdomain.
     *
     * Note: uses a simple "last two labels" heuristic, which is correct for the
     * common .com/.net/.ru style domains this panel targets. Multi-label public
     * suffixes (e.g. co.uk) would need a PSL; not handled here.
     */
    public static function splitDomain(string $fqdn): array
    {
        $fqdn = strtolower(trim($fqdn, ". \t\n"));
        $labels = array_values(array_filter(explode('.', $fqdn), fn($l) => $l !== ''));
        if (count($labels) <= 2) {
            return [$fqdn, ''];
        }
        $base = implode('.', array_slice($labels, -2));
        $sub = implode('.', array_slice($labels, 0, -2));
        return [$base, $sub];
    }

    /**
     * Create or update the A-record for $fqdn to point at $ip.
     *
     * @return array{success: bool, message: string, action?: string, record_id?: int, status?: int, response?: mixed}
     */
    public static function upsertARecord(string $fqdn, string $ip): array
    {
        $fqdn = strtolower(trim($fqdn, ". \t\n"));
        $ip = trim($ip);

        if ($fqdn === '') {
            return ['success' => false, 'message' => 'Domain is empty'];
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ['success' => false, 'message' => "Invalid IPv4 address: {$ip}"];
        }
        $token = self::getToken();
        if ($token === null) {
            return ['success' => false, 'message' => 'Timeweb API token is not configured (Settings → API)'];
        }

        [$baseDomain, $subdomain] = self::splitDomain($fqdn);

        // 1. Look for an existing matching A-record.
        $list = self::request('GET', "/api/v1/domains/{$baseDomain}/dns-records", null, $token);
        if (!$list['ok']) {
            return ['success' => false, 'message' => "Failed to list DNS records: {$list['error']}", 'status' => $list['status'], 'response' => $list['body']];
        }

        $existingId = self::findARecordId($list['body'], $subdomain);
        $payload = self::buildPayload($subdomain, $ip);

        if ($existingId !== null) {
            $res = self::request('PATCH', "/api/v1/domains/{$baseDomain}/dns-records/{$existingId}", $payload, $token);
            $action = 'updated';
        } else {
            $res = self::request('POST', "/api/v1/domains/{$baseDomain}/dns-records", $payload, $token);
            $action = 'created';
        }

        if (!$res['ok']) {
            return ['success' => false, 'message' => "Failed to {$action} A-record: {$res['error']}", 'status' => $res['status'], 'response' => $res['body']];
        }

        error_log("TimewebDnsService: A-record {$action} {$fqdn} -> {$ip}");
        return [
            'success' => true,
            'message' => "A-record {$action}: {$fqdn} → {$ip}",
            'action' => $action,
            'record_id' => $existingId ?? self::extractRecordId($res['body']),
        ];
    }

    private static function buildPayload(string $subdomain, string $ip): array
    {
        $payload = ['type' => 'A', 'value' => $ip];
        if ($subdomain !== '') {
            $payload['subdomain'] = $subdomain;
        }
        return $payload;
    }

    /** Find an A-record id matching $subdomain in a dns-records list response. */
    private static function findARecordId($body, string $subdomain): ?int
    {
        $records = [];
        if (is_array($body)) {
            $records = $body['dns_records'] ?? ($body['dns-records'] ?? (isset($body[0]) ? $body : []));
        }
        if (!is_array($records)) {
            return null;
        }
        foreach ($records as $rec) {
            if (!is_array($rec)) {
                continue;
            }
            $type = strtoupper((string) ($rec['type'] ?? ''));
            if ($type !== 'A') {
                continue;
            }
            $recSub = strtolower(trim((string) ($rec['subdomain'] ?? '')));
            if ($recSub === strtolower($subdomain)) {
                $id = $rec['id'] ?? ($rec['record_id'] ?? null);
                if ($id !== null) {
                    return (int) $id;
                }
            }
        }
        return null;
    }

    private static function extractRecordId($body): ?int
    {
        if (is_array($body)) {
            $rec = $body['dns_record'] ?? $body;
            if (is_array($rec) && isset($rec['id'])) {
                return (int) $rec['id'];
            }
        }
        return null;
    }

    /**
     * Perform a Timeweb API request.
     *
     * @return array{ok: bool, status: int, body: mixed, error: string}
     */
    private static function request(string $method, string $path, ?array $payload, string $token): array
    {
        $ch = curl_init(self::BASE_URL . $path);
        $headers = [
            'Authorization: Bearer ' . $token,
            'Accept: application/json',
        ];
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 20,
        ];
        if ($payload !== null) {
            $headers[] = 'Content-Type: application/json';
            $opts[CURLOPT_POSTFIELDS] = json_encode($payload, JSON_UNESCAPED_SLASHES);
        }
        $opts[CURLOPT_HTTPHEADER] = $headers;
        curl_setopt_array($ch, $opts);

        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            return ['ok' => false, 'status' => 0, 'body' => null, 'error' => 'curl error: ' . $curlErr];
        }

        $body = json_decode((string) $raw, true);
        $ok = $status >= 200 && $status < 300;
        $error = $ok ? '' : self::extractError($body, $status, (string) $raw);
        return ['ok' => $ok, 'status' => $status, 'body' => $body, 'error' => $error];
    }

    private static function extractError($body, int $status, string $raw): string
    {
        if (is_array($body)) {
            foreach (['message', 'error', 'detail'] as $k) {
                if (!empty($body[$k]) && is_string($body[$k])) {
                    return "HTTP {$status}: {$body[$k]}";
                }
            }
        }
        return "HTTP {$status}: " . substr($raw, 0, 200);
    }
}
