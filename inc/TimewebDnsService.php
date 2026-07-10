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
    // A-record TTL (seconds). Low so a failover repoint reaches clients fast.
    private const RECORD_TTL = 60;

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
     * Create or update the A-record for $fqdn to point at $ip, and remove any
     * duplicate A-records so the domain resolves to exactly one IP (required
     * for clean failover).
     *
     * Timeweb addresses records by the FULL domain path
     * (/api/v1/domains/{fqdn}/dns-records) — subdomains are their own resource,
     * not a `subdomain` field on the apex — and the value lives at data.value.
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

        $base = "/api/v1/domains/{$fqdn}/dns-records";

        // 1. List existing A-records for this fqdn.
        $list = self::request('GET', $base, null, $token);
        if (!$list['ok']) {
            return ['success' => false, 'message' => "Failed to list DNS records: {$list['error']}", 'status' => $list['status'], 'response' => $list['body']];
        }
        $aRecordIds = self::aRecordIds($list['body']);
        // Low TTL so failover (A-record repoint) propagates to clients quickly.
        $payload = ['type' => 'A', 'value' => $ip, 'ttl' => self::RECORD_TTL];

        if (empty($aRecordIds)) {
            $res = self::request('POST', $base, $payload, $token);
            if (!$res['ok']) {
                return ['success' => false, 'message' => "Failed to create A-record: {$res['error']}", 'status' => $res['status'], 'response' => $res['body']];
            }
            error_log("TimewebDnsService: A-record created {$fqdn} -> {$ip}");
            return ['success' => true, 'action' => 'created', 'message' => "A-record created: {$fqdn} → {$ip}", 'record_id' => self::extractRecordId($res['body'])];
        }

        // 2. Update the first, delete the rest (dedup to a single record).
        $keepId = array_shift($aRecordIds);
        $res = self::request('PATCH', "{$base}/{$keepId}", $payload, $token);
        if (!$res['ok']) {
            return ['success' => false, 'message' => "Failed to update A-record: {$res['error']}", 'status' => $res['status'], 'response' => $res['body']];
        }
        $removed = 0;
        foreach ($aRecordIds as $dupId) {
            $del = self::request('DELETE', "{$base}/{$dupId}", null, $token);
            if ($del['ok']) {
                $removed++;
            }
        }
        error_log("TimewebDnsService: A-record updated {$fqdn} -> {$ip}" . ($removed ? " (removed {$removed} duplicate(s))" : ''));
        return [
            'success' => true,
            'action' => 'updated',
            'message' => "A-record updated: {$fqdn} → {$ip}" . ($removed ? " (cleaned {$removed} duplicate(s))" : ''),
            'record_id' => $keepId,
        ];
    }

    /**
     * Current A-record IPs for $fqdn straight from the provider (authoritative,
     * not the local resolver cache). Empty array if unavailable.
     */
    public static function currentARecordIps(string $fqdn): array
    {
        $fqdn = strtolower(trim($fqdn, ". \t\n"));
        $token = self::getToken();
        if ($fqdn === '' || $token === null) {
            return [];
        }
        $res = self::request('GET', "/api/v1/domains/{$fqdn}/dns-records", null, $token);
        if (!$res['ok']) {
            return [];
        }
        $records = is_array($res['body']) ? ($res['body']['dns_records'] ?? []) : [];
        $ips = [];
        foreach ((is_array($records) ? $records : []) as $rec) {
            if (is_array($rec) && strtoupper((string) ($rec['type'] ?? '')) === 'A') {
                $ip = $rec['data']['value'] ?? ($rec['value'] ?? null);
                if ($ip) {
                    $ips[] = (string) $ip;
                }
            }
        }
        return $ips;
    }

    /** All A-record ids for the fqdn from a dns-records list response. */
    private static function aRecordIds($body): array
    {
        $records = is_array($body) ? ($body['dns_records'] ?? ($body['dns-records'] ?? (isset($body[0]) ? $body : []))) : [];
        if (!is_array($records)) {
            return [];
        }
        $ids = [];
        foreach ($records as $rec) {
            if (is_array($rec) && strtoupper((string) ($rec['type'] ?? '')) === 'A') {
                $id = $rec['id'] ?? ($rec['record_id'] ?? null);
                if ($id !== null) {
                    $ids[] = (int) $id;
                }
            }
        }
        return $ids;
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
