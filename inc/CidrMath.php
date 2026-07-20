<?php

/**
 * IPv4 CIDR arithmetic for building WireGuard/AmneziaWG "AllowedIPs" lists.
 *
 * WireGuard cannot express "everything except X" directly, so a full-tunnel
 * config that must NOT route certain destinations (the tunnel endpoints, the
 * client's own LAN, docker bridges) lists every CIDR block that together covers
 * 0.0.0.0/0 minus those exclusions. This class computes that complement.
 *
 * Used for the failover pool: excluding ALL pool member IPs (not just the
 * active one) so the router config survives a DNS failover to another member
 * without producing a routing loop.
 */
class CidrMath
{
    /**
     * Parse a CIDR / bare IPv4 into [ip_int, prefix_len]. Returns null on
     * anything that is not valid IPv4 (IPv6, garbage, empty).
     *
     * @return array{0:int,1:int}|null
     */
    public static function parse(string $cidr): ?array
    {
        $cidr = trim($cidr);
        if ($cidr === '') {
            return null;
        }
        $len = 32;
        if (strpos($cidr, '/') !== false) {
            [$ip, $lenStr] = explode('/', $cidr, 2);
            if (!ctype_digit(trim($lenStr))) {
                return null;
            }
            $len = (int) trim($lenStr);
        } else {
            $ip = $cidr;
        }
        $ip = trim($ip);
        if ($len < 0 || $len > 32) {
            return null;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return null;
        }
        $int = ip2long($ip) & 0xFFFFFFFF;
        // Normalise to the network address for the given prefix.
        $mask = self::mask($len);
        return [$int & $mask, $len];
    }

    /** 32-bit network mask for a prefix length. */
    private static function mask(int $len): int
    {
        if ($len <= 0) {
            return 0;
        }
        if ($len >= 32) {
            return 0xFFFFFFFF;
        }
        return (0xFFFFFFFF << (32 - $len)) & 0xFFFFFFFF;
    }

    /** True if block $a (network-normalised) fully contains block $b. */
    private static function contains(array $a, array $b): bool
    {
        [$aIp, $aLen] = $a;
        [$bIp, $bLen] = $b;
        if ($aLen > $bLen) {
            return false;
        }
        return ($bIp & self::mask($aLen)) === $aIp;
    }

    /**
     * Subtract block $b from block $a, assuming $a fully contains $b.
     * Returns the disjoint CIDR blocks covering $a minus $b.
     *
     * @return array<array{0:int,1:int}>
     */
    private static function subtract(array $a, array $b): array
    {
        [$aIp, $aLen] = $a;
        [$bIp, $bLen] = $b;
        if ($aLen === $bLen) {
            return []; // identical block
        }
        $result = [];
        $ip = $aIp;
        $len = $aLen;
        while ($len < $bLen) {
            $len++;
            $bit = ($len >= 32) ? 1 : (1 << (32 - $len));
            $half0 = $ip;
            $half1 = ($ip | $bit) & 0xFFFFFFFF;
            if (($bIp & $bit) === 0) {
                // $b lives in the lower half → keep the upper half whole.
                $result[] = [$half1, $len];
                $ip = $half0;
            } else {
                $result[] = [$half0, $len];
                $ip = $half1;
            }
        }
        return $result;
    }

    /**
     * Compute 0.0.0.0/0 minus the given exclusions, as a list of CIDR strings
     * ordered by address. Invalid / IPv6 entries in $excludes are ignored.
     *
     * @param string[] $excludes CIDRs or bare IPs to carve out.
     * @return string[]
     */
    public static function complement(array $excludes): array
    {
        // Normalise, drop invalids, dedupe.
        $parsed = [];
        foreach ($excludes as $e) {
            $p = self::parse((string) $e);
            if ($p !== null) {
                $parsed[$p[0] . '/' . $p[1]] = $p;
            }
        }
        $parsed = array_values($parsed);

        $allowed = [[0, 0]]; // 0.0.0.0/0
        foreach ($parsed as $ex) {
            $next = [];
            foreach ($allowed as $blk) {
                if (self::contains($blk, $ex)) {
                    // Exclusion sits inside this block → split it.
                    foreach (self::subtract($blk, $ex) as $piece) {
                        $next[] = $piece;
                    }
                } elseif (self::contains($ex, $blk)) {
                    // Whole block is covered by the exclusion → drop it.
                    continue;
                } else {
                    // Disjoint → keep as-is.
                    $next[] = $blk;
                }
            }
            $allowed = $next;
        }

        // Sort by base address then prefix for a stable, readable list.
        usort($allowed, static function ($x, $y) {
            return ($x[0] <=> $y[0]) ?: ($x[1] <=> $y[1]);
        });

        return array_map(static function ($blk) {
            return long2ip($blk[0]) . '/' . $blk[1];
        }, $allowed);
    }
}
