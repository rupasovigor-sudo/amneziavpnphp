-- Alert state table for server health notifications.

CREATE TABLE IF NOT EXISTS alert_states (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  alert_key VARCHAR(191) NOT NULL,
  server_id INT UNSIGNED NULL,
  severity ENUM('warning', 'critical') NOT NULL DEFAULT 'warning',
  status ENUM('ok', 'open') NOT NULL DEFAULT 'ok',
  fail_count INT UNSIGNED NOT NULL DEFAULT 0,
  message TEXT NULL,
  first_seen_at TIMESTAMP NULL DEFAULT NULL,
  last_seen_at TIMESTAMP NULL DEFAULT NULL,
  last_sent_at TIMESTAMP NULL DEFAULT NULL,
  resolved_at TIMESTAMP NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_alert_key (alert_key),
  INDEX idx_alert_server_status (server_id, status),
  INDEX idx_alert_last_seen (last_seen_at),
  CONSTRAINT fk_alert_states_server
    FOREIGN KEY (server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
