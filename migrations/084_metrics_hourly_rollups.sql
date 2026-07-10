-- =====================================================================
-- Migration 084: Hourly rollups for server/client metrics
-- =====================================================================
-- Raw metrics arrive every ~60s per server and per client; charts over a
-- long range would scan tens of thousands of rows per entity. The metrics
-- collector upserts hourly buckets (avg + max) into these tables, and
-- ServerMonitoring reads them instead of raw rows for ranges > 48 hours.
-- bytes_sent/bytes_received are cumulative counters, so the bucket stores
-- their MAX. Idempotent: CREATE TABLE IF NOT EXISTS.
-- =====================================================================

CREATE TABLE IF NOT EXISTS server_metrics_hourly (
  server_id INT UNSIGNED NOT NULL,
  bucket_start DATETIME NOT NULL,
  samples INT UNSIGNED NOT NULL DEFAULT 0,
  cpu_percent DECIMAL(5,2) NULL,
  cpu_percent_max DECIMAL(5,2) NULL,
  ram_used_mb INT UNSIGNED NULL,
  ram_total_mb INT UNSIGNED NULL,
  disk_used_gb DECIMAL(10,2) NULL,
  disk_total_gb DECIMAL(10,2) NULL,
  network_rx_mbps DECIMAL(10,2) NULL,
  network_tx_mbps DECIMAL(10,2) NULL,
  network_rx_mbps_max DECIMAL(10,2) NULL,
  network_tx_mbps_max DECIMAL(10,2) NULL,
  PRIMARY KEY (server_id, bucket_start),
  KEY idx_bucket (bucket_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS client_metrics_hourly (
  client_id INT UNSIGNED NOT NULL,
  bucket_start DATETIME NOT NULL,
  samples INT UNSIGNED NOT NULL DEFAULT 0,
  bytes_sent BIGINT UNSIGNED NULL,
  bytes_received BIGINT UNSIGNED NULL,
  speed_up_kbps DECIMAL(10,2) NULL,
  speed_down_kbps DECIMAL(10,2) NULL,
  speed_up_kbps_max DECIMAL(10,2) NULL,
  speed_down_kbps_max DECIMAL(10,2) NULL,
  PRIMARY KEY (client_id, bucket_start),
  KEY idx_bucket (bucket_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
