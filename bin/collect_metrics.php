#!/usr/bin/env php
<?php

/**
 * Metrics Collector
 * 
 * Runs continuously and collects metrics every 30 seconds
 * Usage: php bin/collect_metrics.php
 */

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../inc/Config.php';
Config::load(__DIR__ . '/../.env');
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/VpnServer.php';
require_once __DIR__ . '/../inc/VpnClient.php';
require_once __DIR__ . '/../inc/ServerMonitoring.php';
require_once __DIR__ . '/../inc/AlertManager.php';

// Set timezone
date_default_timezone_set('UTC');

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/metrics_collector_errors.log');

function shouldRunPeriodicTask(string $taskName, int $serverId, int $intervalSeconds): bool
{
    if ($intervalSeconds <= 0) {
        return false;
    }

    $dir = '/var/run/amnezia_panel';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }

    $stateFile = $dir . '/' . preg_replace('/[^a-z0-9_-]/i', '_', $taskName) . '_' . $serverId . '.last';
    $now = time();
    $lastRun = is_file($stateFile) ? (int) trim((string) @file_get_contents($stateFile)) : 0;

    if ($lastRun > 0 && ($now - $lastRun) < $intervalSeconds) {
        return false;
    }

    @file_put_contents($stateFile, (string) $now, LOCK_EX);
    return true;
}

function configFloat(string $key, float $default): float
{
    $value = Config::get($key, (string) $default);
    return is_numeric($value) ? (float) $value : $default;
}

function recordPercentThreshold(
    AlertManager $alertManager,
    array $server,
    string $checkName,
    ?float $value,
    float $warningThreshold,
    float $criticalThreshold,
    string $label,
    int $failureThreshold
): void {
    if ($value === null) {
        return;
    }

    $severity = $value >= $criticalThreshold ? 'critical' : 'warning';
    $ok = $value < $warningThreshold;
    $alertManager->recordCheck(
        (int) $server['id'],
        (string) $server['name'],
        $checkName,
        $ok,
        sprintf('%s: %.1f%% (warning %.1f%%, critical %.1f%%)', $label, $value, $warningThreshold, $criticalThreshold),
        $severity,
        $failureThreshold
    );
}

/**
 * Collect health checks, server metrics and client metrics for one server.
 * Used both by the sequential fallback and by --server-id child processes.
 */
function collectForServer(array $server, AlertManager $alertManager, array $cfg): void
{
    echo "[" . date('Y-m-d H:i:s') . "] Collecting metrics for server #{$server['id']} ({$server['name']})\n";

    $monitoring = new ServerMonitoring($server['id']);

    foreach ($monitoring->collectHealthChecks() as $checkName => $check) {
        $alertManager->recordCheck(
            (int) $server['id'],
            (string) $server['name'],
            (string) $checkName,
            (bool) $check['ok'],
            (string) $check['message'],
            (string) $check['severity']
        );
    }

    // Enforce single IP per peer for AWG servers
    $containerName = $server['container_name'] ?? '';
    if (strpos($containerName, 'awg') !== false || strpos($containerName, 'wireguard') !== false) {
        if ($cfg['awg_enforcement_interval'] > 0 && shouldRunPeriodicTask('awg_enforcement', (int) $server['id'], $cfg['awg_enforcement_interval'])) {
            $monitoring->enforceAwgSingleIpPerPeer();
        } elseif ($cfg['awg_enforcement_interval'] <= 0 && shouldRunPeriodicTask('awg_enforcement_cleanup', (int) $server['id'], 300)) {
            $monitoring->clearAwgSingleIpBlocks();
        }
    }

    // Collect server metrics
    $serverMetrics = $monitoring->collectMetrics();
    echo "  Server: CPU={$serverMetrics['cpu_percent']}% RAM={$serverMetrics['ram_used_mb']}/{$serverMetrics['ram_total_mb']}MB ";
    echo "Disk={$serverMetrics['disk_used_gb']}/{$serverMetrics['disk_total_gb']}GB ";
    echo "Net RX={$serverMetrics['network_rx_mbps']}Mbps TX={$serverMetrics['network_tx_mbps']}Mbps\n";

    $cpuPercent = isset($serverMetrics['cpu_percent']) ? (float) $serverMetrics['cpu_percent'] : null;
    $ramPercent = (!empty($serverMetrics['ram_total_mb']) && $serverMetrics['ram_total_mb'] > 0)
        ? ((float) $serverMetrics['ram_used_mb'] / (float) $serverMetrics['ram_total_mb'] * 100)
        : null;
    $diskPercent = (!empty($serverMetrics['disk_total_gb']) && $serverMetrics['disk_total_gb'] > 0)
        ? ((float) $serverMetrics['disk_used_gb'] / (float) $serverMetrics['disk_total_gb'] * 100)
        : null;

    recordPercentThreshold($alertManager, $server, 'cpu_usage_high', $cpuPercent, $cfg['cpu_warn'], $cfg['cpu_crit'], 'CPU', $cfg['resource_failure_threshold']);
    recordPercentThreshold($alertManager, $server, 'ram_usage_high', $ramPercent, $cfg['ram_warn'], $cfg['ram_crit'], 'RAM', $cfg['resource_failure_threshold']);
    recordPercentThreshold($alertManager, $server, 'disk_usage_high', $diskPercent, $cfg['disk_warn'], $cfg['disk_crit'], 'Disk', $cfg['resource_failure_threshold']);

    // Collect client metrics
    $clientMetrics = $monitoring->collectClientMetrics();

    if (!empty($clientMetrics)) {
        foreach ($clientMetrics as $cm) {
            echo "  Client #{$cm['client_id']} ({$cm['client_name']}): UP={$cm['speed_up_kbps']}Kbps DOWN={$cm['speed_down_kbps']}Kbps\n";
        }
    } else {
        echo "  No active clients\n";
    }
}

/**
 * Run one collection pass for each server in parallel child processes
 * (`php collect_metrics.php --server-id=N`), at most $limit at a time.
 * Child output is echoed as each child finishes.
 */
function runCollectorPool(array $servers, int $limit): void
{
    $queue = array_values($servers);
    $running = [];

    while ($queue || $running) {
        while ($queue && count($running) < $limit) {
            $server = array_shift($queue);
            $proc = proc_open(
                [PHP_BINARY, __FILE__, '--server-id=' . (int) $server['id']],
                [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
                $pipes
            );
            if (!is_resource($proc)) {
                echo "  ERROR: failed to spawn collector child for server #{$server['id']}\n";
                continue;
            }
            stream_set_blocking($pipes[1], false);
            $running[] = ['proc' => $proc, 'pipe' => $pipes[1], 'server' => $server, 'buf' => ''];
        }

        $read = array_column($running, 'pipe');
        if ($read) {
            $write = null;
            $except = null;
            @stream_select($read, $write, $except, 1);
        }

        foreach ($running as $i => $r) {
            $running[$i]['buf'] .= (string) stream_get_contents($r['pipe']);
            $status = proc_get_status($r['proc']);
            if (!$status['running']) {
                $running[$i]['buf'] .= (string) stream_get_contents($r['pipe']);
                fclose($r['pipe']);
                proc_close($r['proc']);
                echo $running[$i]['buf'];
                if ($status['exitcode'] !== 0) {
                    echo "  ERROR: collector child for server #{$r['server']['id']} exited with code {$status['exitcode']}\n";
                }
                unset($running[$i]);
            }
        }
        $running = array_values($running);
    }
}

$collectorCfg = [
    'awg_enforcement_interval' => (int) Config::get('AMNEZIA_AWG_ENFORCEMENT_INTERVAL_SECONDS', '0'),
    'cpu_warn' => configFloat('ALERT_CPU_WARNING_PERCENT', 90.0),
    'cpu_crit' => configFloat('ALERT_CPU_CRITICAL_PERCENT', 98.0),
    'ram_warn' => configFloat('ALERT_RAM_WARNING_PERCENT', 90.0),
    'ram_crit' => configFloat('ALERT_RAM_CRITICAL_PERCENT', 97.0),
    'disk_warn' => configFloat('ALERT_DISK_WARNING_PERCENT', 85.0),
    'disk_crit' => configFloat('ALERT_DISK_CRITICAL_PERCENT', 95.0),
    'resource_failure_threshold' => max(2, (int) Config::get('ALERT_RESOURCE_FAILURE_THRESHOLD', '5')),
];

// Child mode: collect one server and exit (no lock/pid, spawned by the daemon).
foreach (array_slice($argv ?? [], 1) as $arg) {
    if (preg_match('/^--server-id=(\d+)$/', $arg, $m)) {
        $childServerId = (int) $m[1];
        foreach (VpnServer::listAll() as $server) {
            if ((int) $server['id'] === $childServerId && $server['status'] === 'active') {
                try {
                    collectForServer($server, new AlertManager(), $collectorCfg);
                } catch (Throwable $e) {
                    echo "  ERROR: " . $e->getMessage() . "\n";
                    try {
                        (new AlertManager())->recordProblem($childServerId, (string) $server['name'], 'collector_exception', $e->getMessage(), 'critical');
                    } catch (Throwable $alertError) {
                        error_log('Failed to record collector alert: ' . $alertError->getMessage());
                    }
                    exit(1);
                }
                exit(0);
            }
        }
        echo "Server #{$childServerId} not found or not active\n";
        exit(0);
    }
}

// Prevent multiple instances using flock (#42)
$lockFile = '/var/run/collect_metrics.lock';
$lockFp = fopen($lockFile, 'w');
if (!$lockFp || !flock($lockFp, LOCK_EX | LOCK_NB)) {
    echo "[" . date('Y-m-d H:i:s') . "] Another collector instance is already running. Exiting.\n";
    exit(0);
}

// Write PID file for monitoring
$pidFile = '/var/run/collect_metrics.pid';
file_put_contents($pidFile, getmypid());

// Register shutdown function to clean up PID and lock files
register_shutdown_function(function() use ($pidFile, $lockFp, $lockFile) {
    if (file_exists($pidFile)) {
        unlink($pidFile);
    }
    if ($lockFp) {
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
    }
});

echo "[" . date('Y-m-d H:i:s') . "] Metrics collector started (PID: " . getmypid() . ")\n";

$collectionInterval = max(30, (int) Config::get('AMNEZIA_METRICS_INTERVAL_SECONDS', '60'));
echo "[" . date('Y-m-d H:i:s') . "] Metrics collection interval: {$collectionInterval}s\n";
echo "[" . date('Y-m-d H:i:s') . "] AWG enforcement interval: {$collectorCfg['awg_enforcement_interval']}s\n";
echo "[" . date('Y-m-d H:i:s') . "] Resource alert failure threshold: {$collectorCfg['resource_failure_threshold']}\n";

$alertManager = new AlertManager();

// Main loop
while (true) {
    try {
        $startTime = microtime(true);
        
        // Get all active servers
        $servers = array_values(array_filter(VpnServer::listAll(), function ($s) {
            return $s['status'] === 'active';
        }));

        $parallelism = max(1, (int) Config::get('AMNEZIA_METRICS_PARALLELISM', '4'));
        if ($parallelism > 1 && count($servers) > 1) {
            runCollectorPool($servers, $parallelism);
        } else {
            foreach ($servers as $server) {
                try {
                    collectForServer($server, $alertManager, $collectorCfg);
                } catch (Exception $e) {
                    echo "  ERROR: " . $e->getMessage() . "\n";
                    try {
                        $alertManager->recordProblem(
                            (int) $server['id'],
                            (string) $server['name'],
                            'collector_exception',
                            $e->getMessage(),
                            'critical'
                        );
                    } catch (Throwable $alertError) {
                        error_log('Failed to record collector alert: ' . $alertError->getMessage());
                    }
                }
            }
        }
        
        // Roll raw metrics up into hourly buckets (cheap idempotent upsert
        // over the last 26h; long-range charts read the rollups).
        if (shouldRunPeriodicTask('metrics_hourly_rollup', 0, 900)) {
            ServerMonitoring::aggregateHourlyMetrics();
        }

        // Clean old metrics
        ServerMonitoring::cleanOldMetrics();

        // Failover pools: if an active member has been failing critical health
        // checks, repoint the domain to a healthy standby (and notify). Uses the
        // health just recorded above; no server-to-server UDP probe.
        if (in_array(strtolower((string) Config::get('AMNEZIA_AUTO_FAILOVER_ENABLED', '1')), ['1', 'true', 'yes', 'on'], true)) {
            try {
                $failThreshold = max(2, (int) Config::get('AMNEZIA_FAILOVER_FAILURE_THRESHOLD', '3'));
                foreach (ServerPool::checkAndFailover($failThreshold) as $fo) {
                    if (($fo['action'] ?? '') === 'failover') {
                        echo "[" . date('Y-m-d H:i:s') . "] POOL FAILOVER: pool {$fo['pool']} #{$fo['from']} -> #{$fo['to']}\n";
                    } elseif (($fo['action'] ?? '') === 'no_candidate') {
                        echo "[" . date('Y-m-d H:i:s') . "] POOL: active #{$fo['from']} down, no healthy standby\n";
                    }
                }
            } catch (Throwable $e) {
                error_log('Pool failover check failed: ' . $e->getMessage());
            }
        }

        // Calculate sleep time
        $executionTime = microtime(true) - $startTime;
        $sleepTime = max(0, $collectionInterval - $executionTime);
        
        echo "[" . date('Y-m-d H:i:s') . "] Collection completed in " . round($executionTime, 2) . "s, sleeping for " . round($sleepTime, 2) . "s\n\n";
        
        if ($sleepTime > 0) {
            sleep((int)$sleepTime);
        }
        
    } catch (Exception $e) {
        echo "[" . date('Y-m-d H:i:s') . "] FATAL ERROR: " . $e->getMessage() . "\n";
        error_log("[FATAL] Metrics collector error: " . $e->getMessage());
        echo "Retrying in 30 seconds...\n\n";
        sleep(30);
    } catch (Error $e) {
        echo "[" . date('Y-m-d H:i:s') . "] CRITICAL ERROR: " . $e->getMessage() . "\n";
        error_log("[CRITICAL] Metrics collector error: " . $e->getMessage());
        echo "Retrying in 30 seconds...\n\n";
        sleep(30);
    }
}
