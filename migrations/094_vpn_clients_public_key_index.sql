-- =====================================================================
-- Migration 094: index vpn_clients.public_key
-- =====================================================================
-- The metrics collector runs `UPDATE vpn_clients SET last_handshake=?
-- WHERE public_key=?` once per peer per cycle. public_key is TEXT with no
-- index, so each update is a full table scan (O(peers x clients) per cycle).
-- WireGuard/AWG public keys are 44-char base64, so a 44-char prefix index
-- covers the whole value. Idempotent (guarded on information_schema).
-- =====================================================================

SET @exists := (
    SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'vpn_clients'
      AND index_name = 'idx_public_key'
);
SET @sql := IF(@exists = 0,
    'ALTER TABLE vpn_clients ADD INDEX idx_public_key (public_key(44))',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
