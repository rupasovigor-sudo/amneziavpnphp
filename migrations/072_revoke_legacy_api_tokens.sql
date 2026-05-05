-- Revoke and destroy legacy plaintext API tokens.
-- New tokens are stored as SHA-256 hashes and are checked against api_tokens.
UPDATE api_tokens
SET
  token = SHA2(CONCAT('revoked:', id, ':', token), 256),
  revoked_at = COALESCE(revoked_at, NOW())
WHERE token IS NOT NULL
  AND token NOT REGEXP '^[0-9a-f]{64}$';
