-- =====================================================================
-- Migration 101: maintenance action history
-- =====================================================================
-- Every package/Docker/awg2/WARP/reboot run is recorded so the operator can
-- see what was done to a server and when, instead of digging through
-- logs/server_update_<id>.log. Written by bin/server_update_worker.php.
-- Idempotent.
-- =====================================================================

CREATE TABLE IF NOT EXISTS server_update_history (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    server_id   INT NOT NULL,
    action      VARCHAR(16) NOT NULL,
    state       VARCHAR(16) NOT NULL,
    message     VARCHAR(1000) NULL,
    forced      TINYINT(1) NOT NULL DEFAULT 0,
    started_at  DATETIME NULL,
    finished_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_suh_server (server_id, finished_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
