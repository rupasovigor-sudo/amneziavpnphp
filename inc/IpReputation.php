<?php

/**
 * Ingress-IP reputation checks for pool members.
 *
 * The root cause of "slow/blocked" for clients is usually the ingress IP's
 * reputation as seen by the operator, not the server (see the pool design).
 * There is no free signal that says "operator X throttles IP Y", so this is a
 * best-effort PROXY: membership in public DNS blocklists (spam/abuse/proxy
 * reputation). A listing does not prove throttling, but a burned IP showing up
 * on shared lists is an early warning worth surfacing before users complain.
 *
 * Dependency-free: DNSBL lookups use the system resolver (gethostbynamel).
 * An optional AbuseIPDB check runs only when ABUSEIPDB_API_KEY is configured.
 */
class IpReputation
{
    /** Free DNS blocklists queried without registration (low volume). */
    private const DNSBLS = [
        'dnsbl.dronebl.org',   // drones / open proxies
        'all.s5h.net',         // aggregated abuse
        'spam.dnsbl.sorbs.net' // spam sources
    ];

    /**
     * @return array{ip:string,listed_on:array<int,string>,lists_checked:int,abuse_score:?int,checked_at:int}
     */
    public static function check(string $ip): array
    {
        $result = [
            'ip' => $ip,
            'listed_on' => [],
            'lists_checked' => 0,
            'abuse_score' => null,
            'checked_at' => time(),
        ];

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return $result; // IPv6 / invalid: DNSBLs here are IPv4-only
        }

        $octets = explode('.', $ip);
        $reversed = implode('.', array_reverse($octets));

        foreach (self::DNSBLS as $zone) {
            $result['lists_checked']++;
            $answers = @gethostbynamel($reversed . '.' . $zone);
            if (is_array($answers)) {
                // A listing answers in 127.0.0.0/8; anything else is treated as
                // "not listed" to avoid false positives from wildcard resolvers.
                foreach ($answers as $a) {
                    if (str_starts_with((string) $a, '127.')) {
                        $result['listed_on'][] = $zone;
                        break;
                    }
                }
            }
        }

        $result['abuse_score'] = self::abuseIpDbScore($ip);

        return $result;
    }

    /** Optional AbuseIPDB confidence score (0-100), or null if not configured/unavailable. */
    private static function abuseIpDbScore(string $ip): ?int
    {
        $key = trim((string) Config::get('ABUSEIPDB_API_KEY', ''));
        if ($key === '') {
            return null;
        }
        try {
            $ch = curl_init('https://api.abuseipdb.com/api/v2/check?ipAddress=' . urlencode($ip) . '&maxAgeInDays=90');
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 8,
                CURLOPT_HTTPHEADER => ['Key: ' . $key, 'Accept: application/json'],
            ]);
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($code === 200 && is_string($body)) {
                $json = json_decode($body, true);
                $score = $json['data']['abuseConfidenceScore'] ?? null;
                return is_numeric($score) ? (int) $score : null;
            }
        } catch (Throwable $e) {
            error_log('IpReputation abuseIpDb failed: ' . $e->getMessage());
        }
        return null;
    }

    /** Persist a check result for a pool member (upsert by server_id). */
    public static function store(int $serverId, array $result): void
    {
        try {
            $stmt = DB::conn()->prepare(
                'INSERT INTO ip_reputation (server_id, ip, listed_on, lists_checked, abuse_score, checked_at)
                 VALUES (?, ?, ?, ?, ?, NOW())
                 ON DUPLICATE KEY UPDATE ip = VALUES(ip), listed_on = VALUES(listed_on),
                     lists_checked = VALUES(lists_checked), abuse_score = VALUES(abuse_score), checked_at = NOW()'
            );
            $stmt->execute([
                $serverId,
                (string) $result['ip'],
                json_encode(array_values($result['listed_on'])),
                (int) $result['lists_checked'],
                $result['abuse_score'] !== null ? (int) $result['abuse_score'] : null,
            ]);
        } catch (Throwable $e) {
            error_log('IpReputation::store failed: ' . $e->getMessage());
        }
    }

    /** @return array<int,array<string,mixed>> latest results keyed by server_id */
    public static function latestByServer(): array
    {
        try {
            $rows = DB::conn()->query('SELECT server_id, ip, listed_on, lists_checked, abuse_score, checked_at FROM ip_reputation')
                ->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $out = [];
            foreach ($rows as $r) {
                $r['listed_on'] = json_decode((string) ($r['listed_on'] ?? '[]'), true) ?: [];
                $out[(int) $r['server_id']] = $r;
            }
            return $out;
        } catch (Throwable $e) {
            return [];
        }
    }
}
