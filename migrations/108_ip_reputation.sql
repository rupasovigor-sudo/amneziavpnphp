-- =====================================================================
-- Migration 108: ip_reputation — per-member ingress-IP reputation cache
-- =====================================================================
-- Backs IpReputation (DNSBL + optional AbuseIPDB) checks run from the daily
-- audit cron for each pool member's public ingress IP. One row per server,
-- upserted; surfaced on the /pools dashboard and alerted on when listed.
-- Idempotent: CREATE TABLE IF NOT EXISTS.
-- =====================================================================

CREATE TABLE IF NOT EXISTS ip_reputation (
    server_id     INT NOT NULL,
    ip            VARCHAR(45) NULL,
    listed_on     TEXT NULL,          -- JSON array of DNSBL zones that listed the IP
    lists_checked INT NOT NULL DEFAULT 0,
    abuse_score   SMALLINT NULL,      -- AbuseIPDB confidence 0-100, or NULL if not configured
    checked_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
