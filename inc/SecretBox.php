<?php

class SecretBox
{
    private const PREFIX = 'enc:v1:';

    public static function isEncrypted(?string $value): bool
    {
        return is_string($value) && str_starts_with($value, self::PREFIX);
    }

    public static function encryptNullable(?string $value): ?string
    {
        if ($value === null || $value === '' || self::isEncrypted($value)) {
            return $value;
        }

        $key = self::key();
        if ($key === null) {
            error_log('SecretBox: APP_ENCRYPTION_KEY is missing; storing server secret in plaintext');
            return $value;
        }

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($value, $nonce, $key);
        sodium_memzero($key);

        return self::PREFIX . base64_encode($nonce . $ciphertext);
    }

    public static function decryptNullable(?string $value): ?string
    {
        if ($value === null || $value === '' || !self::isEncrypted($value)) {
            return $value;
        }

        $key = self::key();
        if ($key === null) {
            throw new RuntimeException('APP_ENCRYPTION_KEY is required to decrypt server secrets');
        }

        $payload = base64_decode(substr($value, strlen(self::PREFIX)), true);
        if ($payload === false || strlen($payload) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new RuntimeException('Encrypted server secret has invalid format');
        }

        $nonce = substr($payload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($payload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
        sodium_memzero($key);

        if ($plaintext === false) {
            throw new RuntimeException('Failed to decrypt server secret');
        }

        return $plaintext;
    }

    private static function key(): ?string
    {
        $raw = trim((string) Config::get('APP_ENCRYPTION_KEY', ''));
        if ($raw === '') {
            return null;
        }

        if (preg_match('/^[0-9a-f]{64}$/i', $raw)) {
            return hex2bin($raw) ?: null;
        }

        $decoded = base64_decode($raw, true);
        if (is_string($decoded) && strlen($decoded) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return $decoded;
        }

        throw new RuntimeException('APP_ENCRYPTION_KEY must be base64-encoded 32 bytes or 64 hex characters');
    }
}
