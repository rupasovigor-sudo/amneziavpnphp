-- =====================================================================
-- Migration 107: audit_log — trail of every state-changing admin action
-- =====================================================================
-- The panel manages VPN infrastructure and secrets but kept no record of
-- who did what (create/revoke/delete a client, switch the active pool
-- member, change the DNS token/settings, add/remove a user). This table
-- backs a centralised audit hook (AuditLog::recordCurrentRequest, wired in
-- public/index.php) that logs every mutating request (POST/PUT/PATCH/
-- DELETE, minus a read-only skiplist) with the actor, IP and outcome.
-- Idempotent: CREATE TABLE IF NOT EXISTS.
-- =====================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id     INT NULL,
    user_email  VARCHAR(255) NULL,   -- denormalised so history stays readable after a user is deleted
    action      VARCHAR(96) NULL,    -- derived label, e.g. post.clients.revoke
    method      VARCHAR(8) NULL,
    path        VARCHAR(512) NULL,
    status      SMALLINT NULL,       -- final HTTP status
    ip          VARCHAR(45) NULL,
    PRIMARY KEY (id),
    KEY idx_audit_created (created_at),
    KEY idx_audit_user (user_id),
    KEY idx_audit_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
