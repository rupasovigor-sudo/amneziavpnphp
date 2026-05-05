#!/bin/bash

# Monitor and restart metrics collector if it's not running
# This script checks if collect_metrics.php is running and restarts it if needed
# Uses flock to prevent multiple instances (#42)

SCRIPT_PATH="/var/www/html/bin/collect_metrics.php"
LOG_FILE="/var/log/metrics_monitor.log"
PID_FILE="/var/run/collect_metrics.pid"
LOCK_FILE="/var/run/metrics_monitor.lock"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Use flock to prevent multiple monitor instances
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    log_message "Another monitor instance is running, exiting"
    exit 0
fi

# Check if the process is running
is_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            # Check if it's actually our script
            if ps -p "$PID" -o args= | grep -q "collect_metrics.php"; then
                return 0
            fi
        fi
    fi
    # Also check if any real collect_metrics.php is running (catches orphan processes).
    # Keep the pattern specific so wrapper shell commands do not get mistaken for the collector.
    if pgrep -f "^/usr/local/bin/php ${SCRIPT_PATH}$" > /dev/null 2>&1; then
        # Update PID file with actual PID
        pgrep -f "^/usr/local/bin/php ${SCRIPT_PATH}$" | head -1 > "$PID_FILE"
        return 0
    fi
    return 1
}

# Start the metrics collector
start_collector() {
    log_message "Starting metrics collector..."
    /usr/local/bin/php "$SCRIPT_PATH" >> /var/log/metrics_collector.log 2>&1 &
    echo $! > "$PID_FILE"
    log_message "Metrics collector started with PID: $(cat $PID_FILE)"
    notify_collector_restart "$(cat "$PID_FILE")"
}

notify_collector_restart() {
    local pid="$1"

    COLLECTOR_PID="$pid" /usr/local/bin/php <<'PHP' >/dev/null 2>&1 || true
<?php
require "/var/www/html/vendor/autoload.php";
require "/var/www/html/inc/Config.php";
Config::load("/var/www/html/.env");
require "/var/www/html/inc/DB.php";
require "/var/www/html/inc/AlertManager.php";

$alerts = new AlertManager();
$alerts->recordEvent(
    null,
    'Panel',
    'collector_restarted',
    'Metrics collector was not running and monitor_metrics.sh started it with PID ' . (getenv('COLLECTOR_PID') ?: 'unknown') . '.',
    'warning'
);
PHP
}

# Main logic
if is_running; then
    log_message "Metrics collector is running (PID: $(cat $PID_FILE))"
else
    log_message "Metrics collector is not running - starting it"
    start_collector
fi
