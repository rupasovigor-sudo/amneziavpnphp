-- =====================================================================
-- Migration 102: when a client last SENT traffic
-- =====================================================================
-- "Online" was judged by the age of the last WireGuard handshake, but a
-- handshake only ages — it never signals a disconnect. A client that switched
-- its VPN off therefore read as online for the whole window (10 minutes).
--
-- Bytes RECEIVED FROM the client are the honest signal: with PersistentKeepalive
-- a connected client sends every ~25s even when idle, and a disconnected one
-- stops instantly. This records the moment that counter last moved.
-- Idempotent.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'client_traffic_counters' AND column_name = 'last_rx_at');
SET @sql := IF(@c = 0, 'ALTER TABLE client_traffic_counters ADD COLUMN last_rx_at DATETIME NULL DEFAULT NULL', 'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
