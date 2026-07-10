<?php

/**
 * DnsManager — provider-agnostic facade for managing the VPN endpoint
 * domain's A-record.
 *
 * The panel code (server create/deploy, the Domain/DNS widget on the server
 * page, Settings token validation) talks only to this class. The concrete
 * provider is selected by AMNEZIA_DNS_PROVIDER (default 'timeweb'); adding a
 * new provider means implementing the same four operations and adding a case
 * to the match() below — no call-site changes.
 */
class DnsManager
{
    public const DEFAULT_PROVIDER = 'timeweb';

    public static function provider(): string
    {
        $slug = strtolower(trim((string) Config::get('AMNEZIA_DNS_PROVIDER', self::DEFAULT_PROVIDER)));
        return $slug !== '' ? $slug : self::DEFAULT_PROVIDER;
    }

    /** True when the active provider has a usable API token. */
    public static function isConfigured(): bool
    {
        return match (self::provider()) {
            'timeweb' => TimewebDnsService::isConfigured(),
            default => false,
        };
    }

    /**
     * Create or update the A-record for $fqdn pointing at $ip.
     *
     * @return array{success: bool, message: string, action?: string}
     */
    public static function upsertARecord(string $fqdn, string $ip): array
    {
        return match (self::provider()) {
            'timeweb' => TimewebDnsService::upsertARecord($fqdn, $ip),
            default => ['success' => false, 'message' => 'Unknown DNS provider: ' . self::provider()],
        };
    }

    /**
     * Validate an API token against the provider (pass null to check the
     * stored one). Used by Settings before saving a token.
     *
     * @return array{success: bool, message: string}
     */
    public static function verifyToken(?string $token = null): array
    {
        return match (self::provider()) {
            'timeweb' => TimewebDnsService::verifyToken($token),
            default => ['success' => false, 'message' => 'Unknown DNS provider: ' . self::provider()],
        };
    }
}
