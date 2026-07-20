-- =====================================================================
-- Migration 100: per-server raw traffic counters for cumulative accounting
-- =====================================================================
-- WireGuard byte counters are PER SERVER and reset whenever the container is
-- recreated. In a failover pool a client's session moves between members, so
-- writing the owning member's raw counter straight into vpn_clients made the
-- stored total DROP on every migration — which also silently reset traffic
-- limits (bin/check_traffic_limits.php reads those columns).
--
-- This table remembers the last raw counter seen per (client, server). The
-- collector now adds only the DELTA to vpn_clients.bytes_sent/bytes_received,
-- making those columns monotonic totals across the whole pool and across
-- container restarts.
--
-- Idempotent.
-- =====================================================================

CREATE TABLE IF NOT EXISTS client_traffic_counters (
    client_id  INT NOT NULL,
    server_id  INT NOT NULL,
    last_sent      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_received  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, server_id),
    KEY idx_ctc_server (server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
