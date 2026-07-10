-- =====================================================================
-- Migration 088: pool self-heal state (repair-before-failover)
-- =====================================================================
-- When an active pool member's services fail, the panel first tries to
-- self-heal (restart the awg2 container) for up to N attempts before it
-- repoints the domain to a standby. This table remembers how many repair
-- attempts have been made for a given (pool, active server) so attempts
-- are counted across monitoring cycles and reset once the member recovers
-- or after a failover.
-- Idempotent: CREATE TABLE IF NOT EXISTS.
-- =====================================================================

CREATE TABLE IF NOT EXISTS pool_repair_state (
    pool_id         INT UNSIGNED NOT NULL,
    server_id       INT UNSIGNED NOT NULL,
    repair_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    last_repair_at  TIMESTAMP NULL DEFAULT NULL,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (pool_id, server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
