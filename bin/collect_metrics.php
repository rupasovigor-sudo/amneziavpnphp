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
$awgEnforcementInterval = (int) Config::get('AMNEZIA_AWG_ENFORCEMENT_INTERVAL_SECONDS', '0');
$cpuWarningPercent = configFloat('ALERT_CPU_WARNING_PERCENT', 90.0);
$cpuCriticalPercent = configFloat('ALERT_CPU_CRITICAL_PERCENT', 98.0);
$ramWarningPercent = configFloat('ALERT_RAM_WARNING_PERCENT', 90.0);
$ramCriticalPercent = configFloat('ALERT_RAM_CRITICAL_PERCENT', 97.0);
$diskWarningPercent = configFloat('ALERT_DISK_WARNING_PERCENT', 85.0);
$diskCriticalPercent = configFloat('ALERT_DISK_CRITICAL_PERCENT', 95.0);
$resourceFailureThreshold = max(2, (int) Config::get('ALERT_RESOURCE_FAILURE_THRESHOLD', '5'));
echo "[" . date('Y-m-d H:i:s') . "] Metrics collection interval: {$collectionInterval}s\n";
echo "[" . date('Y-m-d H:i:s') . "] AWG enforcement interval: {$awgEnforcementInterval}s\n";
echo "[" . date('Y-m-d H:i:s') . "] Resource alert failure threshold: {$resourceFailureThreshold}\n";

$alertManager = new AlertManager();

// Main loop
while (true) {
    try {
        $startTime = microtime(true);
        
        // Get all active servers
        $servers = VpnServer::listAll();
        
        foreach ($servers as $server) {
            if ($server['status'] !== 'active') {
                continue;
            }
            
            try {
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
                
                // Enforce single IP per user for Xray servers
                $containerName = $server['container_name'] ?? '';
                if (strpos($containerName, 'xray') !== false) {
                    $monitoring->enforceXraySingleIpPerUser();
                }
                
                // Enforce single IP per peer for AWG servers
                if (strpos($containerName, 'awg') !== false || strpos($containerName, 'wireguard') !== false) {
                    if ($awgEnforcementInterval > 0 && shouldRunPeriodicTask('awg_enforcement', (int) $server['id'], $awgEnforcementInterval)) {
                        $monitoring->enforceAwgSingleIpPerPeer();
                    } elseif ($awgEnforcementInterval <= 0 && shouldRunPeriodicTask('awg_enforcement_cleanup', (int) $server['id'], 300)) {
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

                recordPercentThreshold($alertManager, $server, 'cpu_usage_high', $cpuPercent, $cpuWarningPercent, $cpuCriticalPercent, 'CPU', $resourceFailureThreshold);
                recordPercentThreshold($alertManager, $server, 'ram_usage_high', $ramPercent, $ramWarningPercent, $ramCriticalPercent, 'RAM', $resourceFailureThreshold);
                recordPercentThreshold($alertManager, $server, 'disk_usage_high', $diskPercent, $diskWarningPercent, $diskCriticalPercent, 'Disk', $resourceFailureThreshold);
                
                // Collect client metrics
                $clientMetrics = $monitoring->collectClientMetrics();
                
                if (!empty($clientMetrics)) {
                    foreach ($clientMetrics as $cm) {
                        echo "  Client #{$cm['client_id']} ({$cm['client_name']}): UP={$cm['speed_up_kbps']}Kbps DOWN={$cm['speed_down_kbps']}Kbps\n";
                    }
                } else {
                    echo "  No active clients\n";
                }
                
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
        
        // Clean old metrics
        ServerMonitoring::cleanOldMetrics();
        
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
