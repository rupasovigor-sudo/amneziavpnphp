<?php

/**
 * ServerMonitoring - Collect and store server metrics
 * 
 * Collects:
 * - CPU usage
 * - RAM usage
 * - Disk usage
 * - Network speed
 * - Client traffic speed
 */
class ServerMonitoring
{
    private VpnServer $server;
    private array $serverData;
    private array $wireguardDumpCache = [];

    public function __construct(int $serverId)
    {
        $this->server = new VpnServer($serverId);
        $this->serverData = $this->server->getData();
    }

    /**
     * Collect all server metrics
     * Uses a single SSH call to minimize connections (#42)
     */
    public function collectMetrics(): array
    {
        // Combine all metric commands into one SSH call
        // Use semicolons instead of && to ensure all commands execute even if one fails
        $cpuCommand = <<<'SH'
tmp="/tmp/amnezia_cpu_stat_$$"
awk 'NR==1 {
  idle=$5+$6
  total=0
  for (i=2; i<=NF; i++) total+=$i
  print idle, total
}' /proc/stat > "$tmp"
sleep 1
awk -v file="$tmp" 'BEGIN {
  getline line < file
  split(line, first, " ")
  idle1=first[1]
  total1=first[2]
}
NR==1 {
  idle2=$5+$6
  total2=0
  for (i=2; i<=NF; i++) total2+=$i
  delta_total=total2-total1
  delta_idle=idle2-idle1
  if (delta_total > 0) {
    printf "%.1f\n", 100 * (delta_total - delta_idle) / delta_total
  } else {
    print "0.0"
  }
}' /proc/stat
rm -f "$tmp"
SH;
        $combinedCmd = implode('; ', [
            "echo CPU_START",
            $cpuCommand,
            "echo RAM_START",
            "free -m | grep Mem | awk '{print \$3, \$2}'",
            "echo DISK_START",
            "df -BM / | tail -1 | awk '{print int(\$3/1024), int(\$2/1024)}'",
            "echo NET_RX_START",
            "cat /sys/class/net/\$(ip route | grep default | awk '{print \$5}' | head -1)/statistics/rx_bytes",
            "echo NET_TX_START",
            "cat /sys/class/net/\$(ip route | grep default | awk '{print \$5}' | head -1)/statistics/tx_bytes",
        ]);

        $result1 = $this->execSSH($combinedCmd);

        // Parse first batch
        $cpu = null;
        $ramUsed = null;
        $ramTotal = null;
        $diskUsed = null;
        $diskTotal = null;
        $rxBytes1 = null;
        $txBytes1 = null;

        if ($result1) {
            $lines = explode("\n", trim($result1));
            $section = '';
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === 'CPU_START') { $section = 'cpu'; continue; }
                if ($line === 'RAM_START') { $section = 'ram'; continue; }
                if ($line === 'DISK_START') { $section = 'disk'; continue; }
                if ($line === 'NET_RX_START') { $section = 'rx'; continue; }
                if ($line === 'NET_TX_START') { $section = 'tx'; continue; }

                switch ($section) {
                    case 'cpu':
                        $cpu = (float) $line;
                        $section = '';
                        break;
                    case 'ram':
                        $parts = preg_split('/\s+/', $line);
                        if (count($parts) >= 2) {
                            $ramUsed = (int) $parts[0];
                            $ramTotal = (int) $parts[1];
                        }
                        $section = '';
                        break;
                    case 'disk':
                        $parts = preg_split('/\s+/', $line);
                        if (count($parts) >= 2) {
                            $diskUsed = (float) $parts[0];
                            $diskTotal = (float) $parts[1];
                        }
                        $section = '';
                        break;
                    case 'rx':
                        $rxBytes1 = (int) $line;
                        $section = '';
                        break;
                    case 'tx':
                        $txBytes1 = (int) $line;
                        $section = '';
                        break;
                }
            }
        }

        // Second SSH call after 1 second for network speed (only if first succeeded)
        $rxMbps = null;
        $txMbps = null;
        if ($rxBytes1 !== null && $txBytes1 !== null) {
            sleep(1);
            $netCmd = implode('; ', [
                "echo RX",
                "cat /sys/class/net/\$(ip route | grep default | awk '{print \$5}' | head -1)/statistics/rx_bytes",
                "echo TX",
                "cat /sys/class/net/\$(ip route | grep default | awk '{print \$5}' | head -1)/statistics/tx_bytes",
            ]);
            $result2 = $this->execSSH($netCmd);
            if ($result2) {
                $lines = explode("\n", trim($result2));
                $section = '';
                $rxBytes2 = null;
                $txBytes2 = null;
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === 'RX') { $section = 'rx'; continue; }
                    if ($line === 'TX') { $section = 'tx'; continue; }
                    if ($section === 'rx') { $rxBytes2 = (int) $line; $section = ''; }
                    if ($section === 'tx') { $txBytes2 = (int) $line; $section = ''; }
                }
                if ($rxBytes2 !== null) {
                    $rxMbps = round((($rxBytes2 - $rxBytes1) * 8) / 1000000, 2);
                }
                if ($txBytes2 !== null) {
                    $txMbps = round((($txBytes2 - $txBytes1) * 8) / 1000000, 2);
                }
            }
        }

        $metrics = [
            'cpu_percent' => $cpu,
            'ram_used_mb' => $ramUsed,
            'ram_total_mb' => $ramTotal,
            'disk_used_gb' => $diskUsed,
            'disk_total_gb' => $diskTotal,
            'network_rx_mbps' => $rxMbps,
            'network_tx_mbps' => $txMbps,
        ];

        $this->saveServerMetrics($metrics);

        return $metrics;
    }

    /**
     * Collect lightweight service health checks for alerting.
     *
     * @return array<string, array{ok: bool, severity: string, message: string}>
     */
    public function collectHealthChecks(): array
    {
        $checks = [];
        $containerName = trim((string) ($this->serverData['container_name'] ?? ''));
        $vpnPort = (int) ($this->serverData['vpn_port'] ?? 0);

        $probe = $this->execSSH('echo __AMNEZIA_SSH_OK__');
        $sshOk = is_string($probe) && str_contains($probe, '__AMNEZIA_SSH_OK__');
        $checks['ssh'] = [
            'ok' => $sshOk,
            'severity' => 'critical',
            'message' => $sshOk ? 'SSH доступен' : 'SSH недоступен или команда не вернула ответ',
        ];

        if (!$sshOk || $containerName === '') {
            return $checks;
        }

        $containerArg = escapeshellarg($containerName);
        $script = <<<'SH'
	CONTAINER="$1"
	VPN_PORT="$2"
	WATCHDOG_LOOKBACK="$3"
	HANDSHAKE_STALE_SECONDS="$4"

running="$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo missing)"
echo "container_running=${running}"

if [ "$running" != "true" ]; then
  exit 0
fi

is_wg=0
case "$CONTAINER" in
  *awg*|*wireguard*) is_wg=1 ;;
esac
echo "is_wireguard=${is_wg}"

if [ "$is_wg" = "1" ]; then
  iface=""
  for candidate in awg0 wg0; do
    if docker exec "$CONTAINER" sh -lc "ip link show '$candidate' >/dev/null 2>&1"; then
      iface="$candidate"
      break
    fi
  done

  echo "wg_iface=${iface}"
	  if [ -n "$iface" ]; then
	    listen_port="$(docker exec "$CONTAINER" sh -lc "awg show '$iface' listen-port 2>/dev/null || wg show '$iface' listen-port 2>/dev/null || true" | head -1)"
	    dump="$(docker exec "$CONTAINER" sh -lc "awg show '$iface' dump 2>/dev/null || wg show '$iface' dump 2>/dev/null || true")"
	    peer_count="$(printf '%s\n' "$dump" | awk 'NR > 1 {count++} END {print count+0}')"
	    recent_peer_count="$(printf '%s\n' "$dump" | awk -v now="$(date +%s)" -v stale="$HANDSHAKE_STALE_SECONDS" 'NR > 1 && $5 ~ /^[0-9]+$/ && $5 > 0 && (now - $5) <= stale {count++} END {print count+0}')"
	    echo "wg_listen_port=${listen_port}"
	    echo "wg_peer_count=${peer_count}"
	    echo "wg_recent_peer_count=${recent_peer_count}"
	  fi

	  if [ -n "$VPN_PORT" ] && [ "$VPN_PORT" != "0" ]; then
	    drops="$(docker exec "$CONTAINER" sh -lc "iptables -L INPUT -n --line-numbers 2>/dev/null | awk -v port='dpt:${VPN_PORT}' '\$2 == \"DROP\" && (\$3 == \"udp\" || \$3 == \"17\") && index(\$0, port) {count++} END {print count+0}'" 2>/dev/null || echo 0)"
	    echo "vpn_port_drop_rules=${drops}"
	  fi

	  if [ -n "$WATCHDOG_LOOKBACK" ] && [ "$WATCHDOG_LOOKBACK" != "0" ] && [ -r /var/log/amnezia-awg2-watchdog.log ]; then
	    latest="$(grep ' RESTART:' /var/log/amnezia-awg2-watchdog.log 2>/dev/null | tail -1 || true)"
	    if [ -n "$latest" ]; then
	      ts="$(printf '%s' "$latest" | cut -c1-19)"
	      epoch="$(date -d "$ts" +%s 2>/dev/null || echo 0)"
	      now="$(date +%s)"
	      if [ "$epoch" -gt 0 ]; then
	        age=$((now - epoch))
	        echo "watchdog_restart_age=${age}"
	        echo "watchdog_restart_line=${latest}"
	      fi
	    fi
	  fi
	fi
SH;

        $watchdogLookbackSeconds = max(0, (int) Config::get('ALERT_WATCHDOG_RESTART_LOOKBACK_SECONDS', '900'));
        $handshakeStaleSeconds = max(60, (int) Config::get('ALERT_HANDSHAKE_STALE_SECONDS', '1800'));
        $cmd = 'bash -s -- ' . $containerArg . ' ' . escapeshellarg((string) $vpnPort) . ' ' . escapeshellarg((string) $watchdogLookbackSeconds) . ' ' . escapeshellarg((string) $handshakeStaleSeconds) . ' <<' . "'AMNEZIA_HEALTH_SH'\n" . $script . "\nAMNEZIA_HEALTH_SH";
        $output = $this->execSSH($cmd);
        $values = $this->parseHealthOutput((string) $output);

        $containerRunning = ($values['container_running'] ?? '') === 'true';
        $checks['container_running'] = [
            'ok' => $containerRunning,
            'severity' => 'critical',
            'message' => $containerRunning
                ? "Контейнер {$containerName} запущен"
                : "Контейнер {$containerName} не запущен или не найден",
        ];

        if (($values['is_wireguard'] ?? '0') === '1') {
            $iface = trim((string) ($values['wg_iface'] ?? ''));
            $checks['wireguard_interface'] = [
                'ok' => $iface !== '',
                'severity' => 'critical',
                'message' => $iface !== '' ? "Интерфейс {$iface} существует" : 'WireGuard/AWG интерфейс awg0/wg0 не найден',
            ];

            if ($iface !== '' && $vpnPort > 0) {
                $listenPort = (int) ($values['wg_listen_port'] ?? 0);
                $checks['wireguard_port'] = [
                    'ok' => $listenPort === $vpnPort,
                    'severity' => 'critical',
                    'message' => $listenPort === $vpnPort
                        ? "WireGuard/AWG слушает порт {$vpnPort}"
                        : "WireGuard/AWG слушает порт {$listenPort}, в панели указан {$vpnPort}",
                ];
            }

            if ($vpnPort > 0) {
                $drops = (int) ($values['vpn_port_drop_rules'] ?? 0);
                $checks['wireguard_input_drops'] = [
                    'ok' => $drops === 0,
                    'severity' => 'critical',
                    'message' => $drops === 0
                        ? "DROP-правил на VPN UDP порт {$vpnPort} нет"
                        : "Найдено DROP-правил на VPN UDP порт {$vpnPort}: {$drops}",
                ];
            }

            $peerCount = (int) ($values['wg_peer_count'] ?? 0);
            $recentPeerCount = (int) ($values['wg_recent_peer_count'] ?? 0);
            $minPeers = max(1, (int) Config::get('ALERT_HANDSHAKE_MIN_PEERS', '3'));
            $stalePercentThreshold = max(1, min(100, (float) Config::get('ALERT_HANDSHAKE_STALE_PERCENT', '70')));
            // Pool-aware: a single member's peer dump is NOT a health signal for a
            // pool. Clients sit on whichever member they last resolved — after a
            // manual switch they linger on the OLD member until they re-resolve the
            // domain, so the active member can legitimately show ~0 fresh peers
            // while every client is happily online elsewhere in the pool. Judge the
            // POOL as a whole (last_handshake is the newest seen across members);
            // only alert when clients are stale on ALL members, which is a real
            // outage rather than a migration in progress.
            $poolId = (int) ($this->serverData['pool_id'] ?? 0);
            if ($poolId > 0) {
                $st = DB::conn()->prepare(
                    "SELECT COUNT(*) AS total,
                            SUM(vc.last_handshake IS NOT NULL
                                AND vc.last_handshake >= DATE_SUB(NOW(), INTERVAL ? SECOND)) AS fresh
                     FROM vpn_clients vc
                     JOIN vpn_servers s ON s.id = vc.server_id
                     WHERE s.pool_id = ? AND vc.status = 'active'"
                );
                $st->execute([$handshakeStaleSeconds, $poolId]);
                $row = $st->fetch(PDO::FETCH_ASSOC) ?: [];
                $poolTotal = (int) ($row['total'] ?? 0);
                $poolFresh = (int) ($row['fresh'] ?? 0);
                if ($poolTotal >= $minPeers) {
                    $poolStalePercent = ($poolTotal - $poolFresh) / $poolTotal * 100;
                    $checks['wireguard_mass_stale_handshake'] = [
                        'ok' => $poolStalePercent < $stalePercentThreshold,
                        'severity' => $poolStalePercent >= 90 ? 'critical' : 'warning',
                        'message' => sprintf(
                            'ПУЛ: свежий handshake за %ds у %d/%d клиентов (по всем членам пула), stale %.1f%% (порог %.1f%%); на этом сервере %d/%d',
                            $handshakeStaleSeconds,
                            $poolFresh,
                            $poolTotal,
                            $poolStalePercent,
                            $stalePercentThreshold,
                            $recentPeerCount,
                            $peerCount
                        ),
                    ];
                }
            } elseif ($peerCount >= $minPeers) {
                $staleCount = max(0, $peerCount - $recentPeerCount);
                $stalePercent = $peerCount > 0 ? ($staleCount / $peerCount * 100) : 0.0;
                $checks['wireguard_mass_stale_handshake'] = [
                    'ok' => $stalePercent < $stalePercentThreshold,
                    'severity' => $stalePercent >= 90 ? 'critical' : 'warning',
                    'message' => sprintf(
                        'Свежий handshake за %ds: %d/%d peers, stale %.1f%% (порог %.1f%%)',
                        $handshakeStaleSeconds,
                        $recentPeerCount,
                        $peerCount,
                        $stalePercent,
                        $stalePercentThreshold
                    ),
                ];
            }

            $restartAge = isset($values['watchdog_restart_age']) ? (int) $values['watchdog_restart_age'] : null;
            if ($restartAge !== null && $watchdogLookbackSeconds > 0) {
                $line = trim((string) ($values['watchdog_restart_line'] ?? ''));
                $checks['watchdog_restart_recent'] = [
                    'ok' => $restartAge > $watchdogLookbackSeconds,
                    'severity' => 'warning',
                    'message' => $restartAge > $watchdogLookbackSeconds
                        ? 'Watchdog restart в недавнем окне не найден'
                        : "Watchdog перезапускал контейнер {$restartAge}s назад" . ($line !== '' ? ": {$line}" : ''),
                ];
            }
        }

        return $checks;
    }

    /**
     * @return array<string, string>
     */
    private function parseHealthOutput(string $output): array
    {
        $values = [];
        foreach (preg_split('/\r?\n/', $output) ?: [] as $line) {
            if (!str_contains($line, '=')) {
                continue;
            }
            [$key, $value] = explode('=', $line, 2);
            $key = trim($key);
            if ($key !== '') {
                $values[$key] = trim($value);
            }
        }

        return $values;
    }

    /**
     * Collect client traffic metrics
     */
    public function collectClientMetrics(): array
    {
        // Refresh last_handshake by public key first: in a failover pool a client
        // is connected to whichever member is active, but its row is bound to the
        // member it was created on — so match peers by pubkey, not server_id.
        $this->refreshHandshakes();

        // Speed/traffic must be read from the awg0 where the client's session
        // actually lives. That is NOT necessarily the active member: after a
        // manual switch clients linger on the old one until they re-resolve the
        // domain. So every member collects the pool-wide list, and
        // getClientStats() refuses to write for clients whose session belongs to
        // another member — otherwise an idle member (peers are synced everywhere,
        // so it sees them with zero counters) would wipe the real figures.
        $serverId = (int) ($this->serverData['id'] ?? 0);
        $poolId = (int) ($this->serverData['pool_id'] ?? 0);
        if ($poolId > 0) {
            $clients = VpnClient::listByPool($poolId);
        } else {
            $clients = VpnClient::listByServer($serverId);
        }
        $results = [];

        foreach ($clients as $client) {
            if ($client['status'] !== 'active')
                continue;

            $stats = $this->getClientStats($client);
            if ($stats) {
                $this->saveClientMetrics($client['id'], $stats);
                $results[] = [
                    'client_id' => $client['id'],
                    'client_name' => $client['name'],
                    'speed_up_kbps' => $stats['speed_up_kbps'],
                    'speed_down_kbps' => $stats['speed_down_kbps'],
                ];
            }
        }

        return $results;
    }

    /**
     * Read this server's awg0 peers and advance last_handshake on any matching
     * client row (by public key), only when the handshake is newer than stored.
     * Pool-aware: a client connected to the active member updates its row even
     * though that row's server_id is a different pool member.
     */
    private function refreshHandshakes(): void
    {
        $container = $this->resolveContainerForProtocol('awg2');
        if ($container === '') {
            $container = trim((string) ($this->serverData['container_name'] ?? 'amnezia-awg2')) ?: 'amnezia-awg2';
        }
        // Reuse the same interface dump getClientStats reads (populate the shared
        // per-container cache once) instead of a second SSH round-trip.
        if (!array_key_exists($container, $this->wireguardDumpCache)) {
            $this->wireguardDumpCache[$container] = $this->fetchWireguardDump($container);
        }
        $peers = $this->wireguardDumpCache[$container];
        if (empty($peers)) {
            return;
        }
        $upd = DB::conn()->prepare(
            "UPDATE vpn_clients SET last_handshake = ?
             WHERE public_key = ? AND (last_handshake IS NULL OR last_handshake < ?)"
        );
        foreach ($peers as $pub => $info) {
            $hs = (int) ($info['handshake_ts'] ?? 0);
            if ((string) $pub !== '' && $hs > 0) {
                $date = date('Y-m-d H:i:s', $hs);
                $upd->execute([$date, (string) $pub, $date]);
            }
        }
    }

    /**
     * Turn this server's raw WireGuard byte counters into monotonic pool-wide
     * totals.
     *
     * The counters are per-server and restart from zero when the container is
     * recreated, and in a failover pool a client's session hops between members
     * — so the raw value is meaningless as a stored total. We remember the last
     * raw value per (client, server) and add only the increment. A raw value
     * BELOW the remembered one means the counter was reset, in which case the
     * whole raw value is the increment.
     *
     * @return array{0:int,1:int} cumulative [sent, received]
     */
    private function accumulateTraffic(int $clientId, int $rawSent, int $rawReceived): array
    {
        $db = DB::conn();
        $serverId = (int) ($this->serverData['id'] ?? 0);

        $st = $db->prepare('SELECT last_sent, last_received FROM client_traffic_counters WHERE client_id = ? AND server_id = ?');
        $st->execute([$clientId, $serverId]);
        $prev = $st->fetch(PDO::FETCH_ASSOC);

        if ($prev) {
            $lastSent = (int) $prev['last_sent'];
            $lastReceived = (int) $prev['last_received'];
            $deltaSent = $rawSent >= $lastSent ? ($rawSent - $lastSent) : $rawSent;
            $deltaReceived = $rawReceived >= $lastReceived ? ($rawReceived - $lastReceived) : $rawReceived;
        } else {
            // First sight of this (client, server): treat the current reading as
            // the baseline rather than booking it all as fresh traffic.
            $deltaSent = 0;
            $deltaReceived = 0;
        }

        // $rawSent is what the server RECEIVED FROM the client. It only moves
        // while the client is actually transmitting (keepalive counts), so the
        // moment it last moved is the truthful "still connected" timestamp —
        // unlike a handshake, which merely ages after a disconnect.
        $rxMoved = !$prev || $rawSent !== (int) $prev['last_sent'];
        $db->prepare(
            'INSERT INTO client_traffic_counters (client_id, server_id, last_sent, last_received, last_rx_at)
             VALUES (?, ?, ?, ?, ' . ($rxMoved ? 'NOW()' : 'NULL') . ')
             ON DUPLICATE KEY UPDATE last_sent = VALUES(last_sent), last_received = VALUES(last_received)'
            . ($rxMoved ? ', last_rx_at = NOW()' : '')
        )->execute([$clientId, $serverId, $rawSent, $rawReceived]);

        $cur = $db->prepare('SELECT bytes_sent, bytes_received FROM vpn_clients WHERE id = ?');
        $cur->execute([$clientId]);
        $row = $cur->fetch(PDO::FETCH_ASSOC) ?: [];

        return [
            (int) ($row['bytes_sent'] ?? 0) + $deltaSent,
            (int) ($row['bytes_received'] ?? 0) + $deltaReceived,
        ];
    }

    /**
     * Get client current stats and calculate speed
     */
    private function getClientStats(array $client): ?array
    {
        $db = DB::conn();

        $containerName = (string) ($this->serverData['container_name'] ?? '');
        $bytesSent = 0;
        $bytesReceived = 0;

        $protocolSlug = '';
        if (!empty($client['protocol_id'])) {
            $stmtProto = $db->prepare('SELECT slug FROM protocols WHERE id = ?');
            $stmtProto->execute([$client['protocol_id']]);
            $protoData = $stmtProto->fetch();
            if ($protoData) {
                $protocolSlug = (string) ($protoData['slug'] ?? '');
            }
        }

        $publicKey = $client['public_key'];
        $isWireguardClient = (
            stripos($protocolSlug, 'awg') !== false ||
            stripos($protocolSlug, 'wireguard') !== false
        );

        if ($isWireguardClient) {
            $containerName = $this->resolveContainerForProtocol($protocolSlug);
        }

        if (empty($publicKey) || !$isWireguardClient) {
            // Protocols without a dedicated collector keep their stored DB values.
            $stmt = $db->prepare("SELECT bytes_sent, bytes_received FROM vpn_clients WHERE id = ?");
            $stmt->execute([$client['id']]);
            $currentDbStats = $stmt->fetch(PDO::FETCH_ASSOC);
            $bytesSent = (int) ($currentDbStats['bytes_sent'] ?? 0);
            $bytesReceived = (int) ($currentDbStats['bytes_received'] ?? 0);
        } else {
            $peerStats = $this->getWireguardPeerStats($containerName, $publicKey);
            $inPool = (int) ($this->serverData['pool_id'] ?? 0) > 0;
            if (!$peerStats) {
                if ($inPool) {
                    // Peer absent here — leave the owning member's figures alone.
                    return null;
                }
            } else {
                $handshakeTs = (int) $peerStats['handshake_ts'];
                if ($inPool) {
                    // Byte counters are per-server, but peers are synced to EVERY
                    // pool member, so an idle member sees the peer with zero /
                    // stale counters. Writing those would wipe the real traffic
                    // recorded where the client is actually connected. Only the
                    // member holding the freshest handshake owns the stats
                    // (refreshHandshakes() has already stored that maximum).
                    if ($handshakeTs <= 0) {
                        return null; // never connected here
                    }
                    $stmtOwn = $db->prepare('SELECT last_handshake FROM vpn_clients WHERE id = ?');
                    $stmtOwn->execute([$client['id']]);
                    $dbHs = $stmtOwn->fetchColumn();
                    if (!empty($dbHs) && strtotime((string) $dbHs) > $handshakeTs) {
                        return null; // another member has a fresher session
                    }
                }
                // Raw WireGuard counters are per-server and reset when the
                // container is recreated; in a pool the session also moves
                // between members. Accumulate DELTAS into a monotonic total so
                // the stored figure survives both (traffic limits read it).
                [$bytesSent, $bytesReceived] = $this->accumulateTraffic(
                    (int) $client['id'],
                    (int) $peerStats['bytes_sent'],
                    (int) $peerStats['bytes_received']
                );
                if ($handshakeTs > 0) {
                    $handshakeDate = date('Y-m-d H:i:s', $handshakeTs);
                    // Only advance last_handshake, never overwrite a fresher value
                    // reported by another pool member.
                    $stmtHs = $db->prepare("UPDATE vpn_clients SET last_handshake = ? WHERE id = ? AND (last_handshake IS NULL OR last_handshake < ?)");
                    $stmtHs->execute([$handshakeDate, $client['id'], $handshakeDate]);
                }
            }
        }

        // Calculate speed (Kbps) from the previous metrics sample.
        $stmt = $db->prepare("
            SELECT bytes_sent, bytes_received, collected_at
            FROM client_metrics
            WHERE client_id = ?
            ORDER BY collected_at DESC
            LIMIT 1
        ");
        $stmt->execute([$client['id']]);
        $previous = $stmt->fetch(PDO::FETCH_ASSOC);

        $speedUp = 0;
        $speedDown = 0;

        if ($previous) {
            $timeDiff = time() - strtotime($previous['collected_at']);
            if ($timeDiff > 0 && $timeDiff < 300) {
                $bytesDiffSent = (int) $bytesSent - (int) $previous['bytes_sent'];
                $bytesDiffReceived = (int) $bytesReceived - (int) $previous['bytes_received'];
                if ($bytesDiffSent >= 0) {
                    $speedUp = round(($bytesDiffSent * 8) / $timeDiff / 1000, 2);
                }
                if ($bytesDiffReceived >= 0) {
                    $speedDown = round(($bytesDiffReceived * 8) / $timeDiff / 1000, 2);
                }
            }
        }

        return [
            'bytes_sent' => (int) $bytesSent,
            'bytes_received' => (int) $bytesReceived,
            'speed_up_kbps' => $speedUp,
            'speed_down_kbps' => $speedDown,
        ];
    }

    /**
     * Save server metrics to database
     */
    private function saveServerMetrics(array $metrics): void
    {
        $db = DB::conn();

        $stmt = $db->prepare("
            INSERT INTO server_metrics 
            (server_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, network_rx_mbps, network_tx_mbps)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");

        $stmt->execute([
            $this->serverData['id'],
            $metrics['cpu_percent'],
            $metrics['ram_used_mb'],
            $metrics['ram_total_mb'],
            $metrics['disk_used_gb'],
            $metrics['disk_total_gb'],
            $metrics['network_rx_mbps'],
            $metrics['network_tx_mbps'],
        ]);
    }

    /**
     * Save client metrics to database
     */
    private function saveClientMetrics(int $clientId, array $stats): void
    {
        $db = DB::conn();

        $stmtExists = $db->prepare('SELECT id FROM vpn_clients WHERE id = ? LIMIT 1');
        $stmtExists->execute([$clientId]);
        if (!$stmtExists->fetchColumn()) {
            return;
        }

        $stmt = $db->prepare("
            INSERT INTO client_metrics 
            (client_id, bytes_sent, bytes_received, speed_up_kbps, speed_down_kbps)
            VALUES (?, ?, ?, ?, ?)
        ");

        try {
            $stmt->execute([
                $clientId,
                $stats['bytes_sent'],
                $stats['bytes_received'],
                $stats['speed_up_kbps'],
                $stats['speed_down_kbps'],
            ]);
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') {
                return;
            }
            throw $e;
        }

        // Update vpn_clients table with latest stats (don't touch last_handshake - it's set separately for WG/AWG)
        $stmt = $db->prepare("
            UPDATE vpn_clients 
            SET bytes_sent = ?, bytes_received = ?, speed_up = ?, speed_down = ?, current_speed = ?, last_sync_at = NOW()
            WHERE id = ?
        ");

        $currentSpeed = $stats['speed_up_kbps'] + $stats['speed_down_kbps']; // Total speed in Kbps? Or bytes/s?
        // Note: speed_up_kbps is in Kbps (kilobits?). 
        // VpnClient stores speed in Bytes/s (based on my previous edit: bytesDiff/timeDiff).
        // ServerMonitoring calculates: round(($bytesDiffSent * 8) / $timeDiff / 1000, 2) -> Kbps

        // Wait! VpnClient implementation I did:
        // $speedUp = (int) ($sentDiff / $timeDiff); // Bytes per second

        // ServerMonitoring implementation:
        // $speedUp = round(($bytesDiffSent * 8) / $timeDiff / 1000, 2); // Kilobits per second

        // I need to be consistent. 
        // Frontend expects KB/s (KiloBYTES). 
        // VpnClient stores BYTES per second. Twig does `speed / 1024` -> KB/s.

        // So I should convert ServerMonitoring stats to Bytes/s before saving to vpn_clients.
        // ServerMonitoring $stats['speed_up_kbps'] is Kbps.
        // Bytes/s = Kbps * 1000 / 8.

        $speedUpBytes = (int) ($stats['speed_up_kbps'] * 1000 / 8);
        $speedDownBytes = (int) ($stats['speed_down_kbps'] * 1000 / 8);
        $totalSpeedBytes = $speedUpBytes + $speedDownBytes;

        $stmt->execute([
            $stats['bytes_sent'],
            $stats['bytes_received'],
            $speedUpBytes,
            $speedDownBytes,
            $totalSpeedBytes,
            $clientId
        ]);
    }

    /**
     * Get server metrics for last 24 hours
     */
    /** Ranges longer than this are served from hourly rollups, not raw rows. */
    private const ROLLUP_THRESHOLD_HOURS = 48;

    public static function getServerMetrics(int $serverId, int $hours = 24): array
    {
        $db = DB::conn();

        if ($hours > self::ROLLUP_THRESHOLD_HOURS) {
            $stmt = $db->prepare("
                SELECT server_id, bucket_start AS collected_at, samples,
                       cpu_percent, cpu_percent_max, ram_used_mb, ram_total_mb,
                       disk_used_gb, disk_total_gb,
                       network_rx_mbps, network_tx_mbps,
                       network_rx_mbps_max, network_tx_mbps_max
                FROM server_metrics_hourly
                WHERE server_id = ?
                AND bucket_start >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                ORDER BY bucket_start ASC
            ");
            $stmt->execute([$serverId, $hours]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        }

        $stmt = $db->prepare("
            SELECT *
            FROM server_metrics
            WHERE server_id = ?
            AND collected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
            ORDER BY collected_at ASC
        ");

        $stmt->execute([$serverId, $hours]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Get client metrics for last 24 hours
     */
    public static function getClientMetrics(int $clientId, int $hours = 24, int $maxPoints = 720): array
    {
        $db = DB::conn();
        $maxPoints = max(1, min(5000, $maxPoints));

        if ($hours > self::ROLLUP_THRESHOLD_HOURS) {
            $stmt = $db->prepare("
                SELECT *
                FROM (
                    SELECT client_id, bucket_start AS collected_at, samples,
                           bytes_sent, bytes_received,
                           speed_up_kbps, speed_down_kbps,
                           speed_up_kbps_max, speed_down_kbps_max
                    FROM client_metrics_hourly
                    WHERE client_id = ?
                    AND bucket_start >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                    ORDER BY bucket_start DESC
                    LIMIT {$maxPoints}
                ) recent
                ORDER BY collected_at ASC
            ");
            $stmt->execute([$clientId, $hours]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        }

        $stmt = $db->prepare("
            SELECT *
            FROM (
                SELECT *
                FROM client_metrics
                WHERE client_id = ?
                AND collected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                ORDER BY collected_at DESC
                LIMIT {$maxPoints}
            ) recent
            ORDER BY collected_at ASC
        ");

        $stmt->execute([$clientId, $hours]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Get metrics for all clients on a server in one query.
     */
    public static function getClientMetricsForServer(int $serverId, int $hours = 24, int $maxPointsPerClient = 120): array
    {
        $db = DB::conn();
        $maxPointsPerClient = max(1, min(2000, $maxPointsPerClient));

        $clientStmt = $db->prepare('SELECT id FROM vpn_clients WHERE server_id = ? ORDER BY id');
        $clientStmt->execute([$serverId]);
        $clientIds = array_map('intval', $clientStmt->fetchAll(PDO::FETCH_COLUMN));
        if (empty($clientIds)) {
            return [];
        }

        if ($hours > self::ROLLUP_THRESHOLD_HOURS) {
            $stmt = $db->prepare("
                SELECT *
                FROM (
                    SELECT
                        NULL AS id,
                        client_id,
                        bytes_sent,
                        bytes_received,
                        speed_up_kbps,
                        speed_down_kbps,
                        bucket_start AS collected_at
                    FROM client_metrics_hourly
                    WHERE client_id = ?
                      AND bucket_start >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                    ORDER BY bucket_start DESC
                    LIMIT {$maxPointsPerClient}
                ) recent
                ORDER BY collected_at ASC
            ");
        } else {
            $stmt = $db->prepare("
                SELECT *
                FROM (
                    SELECT
                        id,
                        client_id,
                        bytes_sent,
                        bytes_received,
                        speed_up_kbps,
                        speed_down_kbps,
                        collected_at
                    FROM client_metrics
                    WHERE client_id = ?
                      AND collected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                    ORDER BY collected_at DESC
                    LIMIT {$maxPointsPerClient}
                ) recent
                ORDER BY collected_at ASC
            ");
        }

        $metrics = [];
        foreach ($clientIds as $clientId) {
            $stmt->execute([$clientId, $hours]);
            $metrics = array_merge($metrics, $stmt->fetchAll(PDO::FETCH_ASSOC));
        }

        usort($metrics, static function (array $left, array $right): int {
            $clientCompare = ((int) $left['client_id']) <=> ((int) $right['client_id']);
            if ($clientCompare !== 0) {
                return $clientCompare;
            }
            return strcmp((string) $left['collected_at'], (string) $right['collected_at']);
        });

        return $metrics;
    }

    /**
     * Upsert hourly rollups from raw metrics. Covers the last 26 hours each
     * run, so late samples and collector downtime are re-absorbed; the upsert
     * is idempotent. Called periodically by the metrics collector.
     */
    public static function aggregateHourlyMetrics(): void
    {
        $db = DB::conn();

        $db->exec("
            INSERT INTO server_metrics_hourly
                (server_id, bucket_start, samples,
                 cpu_percent, cpu_percent_max, ram_used_mb, ram_total_mb,
                 disk_used_gb, disk_total_gb,
                 network_rx_mbps, network_tx_mbps, network_rx_mbps_max, network_tx_mbps_max)
            SELECT
                server_id,
                DATE_FORMAT(collected_at, '%Y-%m-%d %H:00:00'),
                COUNT(*),
                AVG(cpu_percent), MAX(cpu_percent),
                AVG(ram_used_mb), MAX(ram_total_mb),
                AVG(disk_used_gb), MAX(disk_total_gb),
                AVG(network_rx_mbps), AVG(network_tx_mbps),
                MAX(network_rx_mbps), MAX(network_tx_mbps)
            FROM server_metrics
            WHERE collected_at >= DATE_SUB(NOW(), INTERVAL 26 HOUR)
            GROUP BY server_id, DATE_FORMAT(collected_at, '%Y-%m-%d %H:00:00')
            ON DUPLICATE KEY UPDATE
                samples = VALUES(samples),
                cpu_percent = VALUES(cpu_percent),
                cpu_percent_max = VALUES(cpu_percent_max),
                ram_used_mb = VALUES(ram_used_mb),
                ram_total_mb = VALUES(ram_total_mb),
                disk_used_gb = VALUES(disk_used_gb),
                disk_total_gb = VALUES(disk_total_gb),
                network_rx_mbps = VALUES(network_rx_mbps),
                network_tx_mbps = VALUES(network_tx_mbps),
                network_rx_mbps_max = VALUES(network_rx_mbps_max),
                network_tx_mbps_max = VALUES(network_tx_mbps_max)
        ");

        // bytes_* are cumulative counters, so a bucket keeps their MAX.
        $db->exec("
            INSERT INTO client_metrics_hourly
                (client_id, bucket_start, samples,
                 bytes_sent, bytes_received,
                 speed_up_kbps, speed_down_kbps, speed_up_kbps_max, speed_down_kbps_max)
            SELECT
                client_id,
                DATE_FORMAT(collected_at, '%Y-%m-%d %H:00:00'),
                COUNT(*),
                MAX(bytes_sent), MAX(bytes_received),
                AVG(speed_up_kbps), AVG(speed_down_kbps),
                MAX(speed_up_kbps), MAX(speed_down_kbps)
            FROM client_metrics
            WHERE collected_at >= DATE_SUB(NOW(), INTERVAL 26 HOUR)
            GROUP BY client_id, DATE_FORMAT(collected_at, '%Y-%m-%d %H:00:00')
            ON DUPLICATE KEY UPDATE
                samples = VALUES(samples),
                bytes_sent = VALUES(bytes_sent),
                bytes_received = VALUES(bytes_received),
                speed_up_kbps = VALUES(speed_up_kbps),
                speed_down_kbps = VALUES(speed_down_kbps),
                speed_up_kbps_max = VALUES(speed_up_kbps_max),
                speed_down_kbps_max = VALUES(speed_down_kbps_max)
        ");
    }

    /**
     * Clean old metrics (raw rows and hourly rollups, separate retentions).
     */
    public static function cleanOldMetrics(): void
    {
        $db = DB::conn();
        $retentionDays = max(1, min(365, (int) Config::get('AMNEZIA_METRICS_RETENTION_DAYS', '30')));
        $hourlyRetentionDays = max($retentionDays, min(3650, (int) Config::get('AMNEZIA_METRICS_HOURLY_RETENTION_DAYS', '180')));

        do {
            $deleted = $db->exec("DELETE FROM server_metrics WHERE collected_at < DATE_SUB(NOW(), INTERVAL {$retentionDays} DAY) LIMIT 5000");
        } while ($deleted === 5000);

        do {
            $deleted = $db->exec("DELETE FROM client_metrics WHERE collected_at < DATE_SUB(NOW(), INTERVAL {$retentionDays} DAY) LIMIT 5000");
        } while ($deleted === 5000);

        $db->exec("DELETE FROM server_metrics_hourly WHERE bucket_start < DATE_SUB(NOW(), INTERVAL {$hourlyRetentionDays} DAY)");
        $db->exec("DELETE FROM client_metrics_hourly WHERE bucket_start < DATE_SUB(NOW(), INTERVAL {$hourlyRetentionDays} DAY)");
    }

    /**
     * Execute SSH command on server
     * Supports both password and SSH key authentication
     */
    private function execSSH(string $cmd): ?string
    {
        $timeoutSeconds = max(5, (int) Config::get('AMNEZIA_SSH_COMMAND_TIMEOUT_SECONDS', '20'));
        $output = Ssh::exec($this->serverData, $cmd, ['timeout' => $timeoutSeconds, 'stderr' => 'discard'])->output;
        return $output !== '' ? $output : null;
    }
    private function resolveContainerForProtocol(string $protocolSlug): string
    {
        $default = trim((string) ($this->serverData['container_name'] ?? ''));
        if ($protocolSlug === '') {
            return $default;
        }

        try {
            $db = DB::conn();
            $stmt = $db->prepare('SELECT definition FROM protocols WHERE slug = ? LIMIT 1');
            $stmt->execute([$protocolSlug]);
            $definitionJson = $stmt->fetchColumn();
            if (is_string($definitionJson) && $definitionJson !== '') {
                $definition = json_decode($definitionJson, true);
                if (is_array($definition)) {
                    $candidate = trim((string) ($definition['metadata']['container_name'] ?? ''));
                    if ($candidate !== '') {
                        return $candidate;
                    }
                }
            }
        } catch (Throwable $e) {
            // Fallback to default container.
        }

        if ($protocolSlug === 'awg2') {
            return 'amnezia-awg2';
        }

        return $default;
    }

    private function getWireguardPeerStats(string $containerName, string $publicKey): ?array
    {
        $containerName = trim($containerName);
        $publicKey = trim($publicKey);

        if ($containerName === '' || $publicKey === '') {
            return null;
        }

        if (!array_key_exists($containerName, $this->wireguardDumpCache)) {
            $this->wireguardDumpCache[$containerName] = $this->fetchWireguardDump($containerName);
        }

        return $this->wireguardDumpCache[$containerName][$publicKey] ?? null;
    }

    private function fetchWireguardDump(string $containerName): array
    {
        $containerArg = escapeshellarg($containerName);
        $cmd = "docker exec {$containerArg} wg show all dump 2>/dev/null || docker exec {$containerArg} awg show all dump 2>/dev/null";
        $result = $this->execSSH($cmd);

        if (!$result || trim($result) === '') {
            return [];
        }

        $peers = [];
        foreach (explode("\n", trim($result)) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if (!$parts || count($parts) < 8) {
                continue;
            }

            // wg show all dump:
            // interface pubkey psk endpoint allowed-ips latest-handshake rx-bytes tx-bytes keepalive
            $peerKey = (string) $parts[1];
            if ($peerKey === '' || $peerKey === '(none)') {
                continue;
            }

            $peers[$peerKey] = [
                'handshake_ts' => (int) $parts[5],
                'bytes_sent' => (int) $parts[6],
                'bytes_received' => (int) $parts[7],
            ];
        }

        return $peers;
    }

    /**
     * Enforce single IP per peer for AWG/WireGuard connections.
     * If a peer's endpoint changes while session is active, block the new IP.
     */
    public function enforceAwgSingleIpPerPeer(): void
    {
        $containerName = $this->serverData['container_name'] ?? '';
        if (strpos($containerName, 'awg') === false && strpos($containerName, 'wireguard') === false) {
            return; // Not an AWG server
        }

        // Get current peer states
        $protocolSlug = (string) ($this->serverData['install_protocol'] ?? '');
        $isAwg2 = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2');
        $cmd = $isAwg2
            ? "docker exec $containerName awg show awg0 dump"
            : "docker exec $containerName wg show wg0 dump";
        $result = $this->execSSH($cmd);
        if (!$result && $isAwg2) {
            $result = $this->execSSH("docker exec $containerName wg show wg0 dump");
        }
        if (!$result) {
            return;
        }

        $lines = explode("\n", trim($result));
        if (count($lines) < 2) {
            return; // No peers
        }

        // Load locked endpoints from file
        $lockFile = '/tmp/awg_locked_endpoints_' . $this->serverData['id'] . '.json';
        $lockedEndpoints = [];
        $lockFileCmd = "cat $lockFile 2>/dev/null || echo '{}'";
        $lockData = $this->execSSH($lockFileCmd);
        if ($lockData) {
            $lockedEndpoints = json_decode($lockData, true) ?: [];
        }

        $currentPeers = [];
        $ipsToBlock = [];
        $now = time();

        // Skip first line (interface info)
        for ($i = 1; $i < count($lines); $i++) {
            $parts = preg_split('/\s+/', trim($lines[$i]));
            if (count($parts) < 8) {
                continue;
            }

            // Format: interface pubkey psk endpoint allowed-ips latest-handshake rx tx keepalive
            $pubkey = $parts[0];
            $endpoint = $parts[2]; // IP:Port or (none)
            $latestHandshake = (int)$parts[4];

            if ($endpoint === '(none)' || $latestHandshake === 0) {
                // Peer not connected - clear lock
                unset($lockedEndpoints[$pubkey]);
                continue;
            }

            // Extract just IP from endpoint (IP:Port)
            $endpointIp = explode(':', $endpoint)[0];
            $isActive = ($now - $latestHandshake) < 180; // Active if handshake within 3 minutes

            $currentPeers[$pubkey] = $endpointIp;

            if ($isActive) {
                if (!isset($lockedEndpoints[$pubkey])) {
                    // First connection - lock this IP
                    $lockedEndpoints[$pubkey] = $endpointIp;
                } elseif ($lockedEndpoints[$pubkey] !== $endpointIp) {
                    // Endpoint changed during active session - block new IP
                    $ipsToBlock[] = $endpointIp;
                    error_log("[AWG Enforcement] Peer $pubkey changed endpoint from {$lockedEndpoints[$pubkey]} to $endpointIp - blocking");
                }
            } else {
                // Session expired - update locked endpoint for next connection
                $lockedEndpoints[$pubkey] = $endpointIp;
            }
        }

        // Clean up locks for peers that no longer exist
        foreach ($lockedEndpoints as $pubkey => $ip) {
            if (!isset($currentPeers[$pubkey])) {
                unset($lockedEndpoints[$pubkey]);
            }
        }

        // Save locked endpoints
        $lockJson = json_encode($lockedEndpoints);
        $saveLockCmd = "echo " . escapeshellarg($lockJson) . " > $lockFile";
        $this->execSSH($saveLockCmd);

        // Apply iptables rules for blocked IPs
        if (!empty($ipsToBlock)) {
            foreach ($ipsToBlock as $ip) {
                // Block UDP traffic from this IP to WireGuard port
                $wgPort = $this->serverData['vpn_port'] ?? 51820;
                $blockCmd = "docker exec $containerName iptables -C INPUT -s $ip -p udp --dport $wgPort -j DROP 2>/dev/null || docker exec $containerName iptables -I INPUT -s $ip -p udp --dport $wgPort -j DROP";
                $this->execSSH($blockCmd);
            }
        }

        // Remove blocks for IPs that are now the locked endpoint (old device disconnected)
        $wgPort = $this->serverData['vpn_port'] ?? 51820;
        $listRulesCmd = "docker exec $containerName iptables -L INPUT -n --line-numbers | grep 'DROP.*udp dpt:$wgPort' | awk '{print \$1, \$4}'";
        $rulesResult = $this->execSSH($listRulesCmd);
        if ($rulesResult) {
            $rulesToRemove = [];
            foreach (explode("\n", trim($rulesResult)) as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 2) {
                    $ruleNum = $parts[0];
                    $blockedIp = $parts[1];
                    // If this IP is now the locked endpoint for any peer, remove the block
                    if (in_array($blockedIp, $lockedEndpoints)) {
                        $rulesToRemove[] = $ruleNum;
                    }
                }
            }
            // Remove rules in reverse order (highest number first)
            rsort($rulesToRemove);
            foreach ($rulesToRemove as $ruleNum) {
                $rmCmd = "docker exec $containerName iptables -D INPUT $ruleNum 2>/dev/null || true";
                $this->execSSH($rmCmd);
            }
        }
    }

    /**
     * Remove DROP rules that were created by the legacy AWG single-endpoint enforcement.
     */
    public function clearAwgSingleIpBlocks(): void
    {
        $containerName = trim((string) ($this->serverData['container_name'] ?? ''));
        if ($containerName === '' || (strpos($containerName, 'awg') === false && strpos($containerName, 'wireguard') === false)) {
            return;
        }

        $wgPort = (int) ($this->serverData['vpn_port'] ?? 51820);
        if ($wgPort <= 0) {
            $wgPort = 51820;
        }

        $containerArg = escapeshellarg($containerName);
        $cmd = "docker exec -e WG_PORT={$wgPort} {$containerArg} sh -lc " . escapeshellarg(<<<'SH'
set -e
removed=0
while :; do
  rule="$(iptables -L INPUT -n --line-numbers 2>/dev/null | awk -v port="dpt:${WG_PORT}" '$2 == "DROP" && ($3 == "udp" || $3 == "17") && index($0, port) {print $1; exit}')"
  [ -n "$rule" ] || break
  iptables -D INPUT "$rule" 2>/dev/null || break
  removed=$((removed + 1))
done
echo "$removed"
SH);

        $result = trim((string) $this->execSSH($cmd));
        if ($result !== '' && $result !== '0') {
            error_log("[AWG Enforcement] Removed {$result} legacy endpoint block rule(s) on {$containerName}:{$wgPort}");
        }
    }

    /**
     * Get online clients for a specific server
     * Returns array of online client logins/emails
     */
    /**
     * Seconds since the last handshake within which a client still counts as
     * online. Tunable via CLIENT_ONLINE_WINDOW_SECONDS; the default is generous
     * because an idle WireGuard tunnel refreshes its handshake only on rekey.
     */
    public static function onlineWindow(): int
    {
        // Judged against the last traffic RECEIVED FROM the client, not the last
        // handshake. A handshake only ages, so a client that switched its VPN
        // off still read as online for the whole window; with keepalive the
        // from-client counter moves every ~25s and stops the instant it leaves.
        // The floor is well above the 60s collector cycle so a client is not
        // flagged offline merely because the sample is between passes.
        return max(120, (int) Config::get('CLIENT_ONLINE_WINDOW_SECONDS', '180'));
    }

    /**
     * Names of clients that actually sent traffic recently. Pool-wide: the
     * session may live on any member.
     *
     * @return string[]
     */
    public static function clientsWithRecentTraffic(int $poolId = 0, int $serverId = 0): array
    {
        $window = self::onlineWindow();
        $db = DB::conn();
        if ($poolId > 0) {
            $stmt = $db->prepare(
                "SELECT DISTINCT vc.name
                 FROM vpn_clients vc
                 JOIN client_traffic_counters t ON t.client_id = vc.id
                 JOIN vpn_servers s ON s.id = t.server_id
                 WHERE s.pool_id = ? AND vc.status = 'active'
                   AND t.last_rx_at IS NOT NULL
                   AND t.last_rx_at >= DATE_SUB(NOW(), INTERVAL ? SECOND)"
            );
            $stmt->execute([$poolId, $window]);
        } else {
            $stmt = $db->prepare(
                "SELECT DISTINCT vc.name
                 FROM vpn_clients vc
                 JOIN client_traffic_counters t ON t.client_id = vc.id
                 WHERE t.server_id = ? AND vc.status = 'active'
                   AND t.last_rx_at IS NOT NULL
                   AND t.last_rx_at >= DATE_SUB(NOW(), INTERVAL ? SECOND)"
            );
            $stmt->execute([$serverId, $window]);
        }
        return array_values(array_unique($stmt->fetchAll(PDO::FETCH_COLUMN) ?: []));
    }

    public static function getOnlineClientsForServer(array $serverData): array
    {
        // Prefer the traffic-based signal; fall back to the handshake window only
        // while last_rx_at has not been populated yet (fresh install, first
        // collector pass), otherwise a disconnected client reads online until
        // its handshake ages out.
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        $byTraffic = self::clientsWithRecentTraffic($poolId, (int) ($serverData['id'] ?? 0));
        $haveTrafficData = (int) DB::conn()->query(
            'SELECT COUNT(*) FROM client_traffic_counters WHERE last_rx_at IS NOT NULL'
        )->fetchColumn() > 0;
        if ($haveTrafficData) {
            return $byTraffic;
        }

        $result = [];
        $db = DB::conn();

        // WireGuard/AWG clients with a recent handshake (< 5 minutes) are online.
        // Pool-aware: in a failover pool a client is homed on one member but
        // connects to the ACTIVE member (via the shared domain), and its handshake
        // is collected there. So on the active member count online across the WHOLE
        // pool (by pool_id), not just clients whose server_id equals this server —
        // otherwise pool clients homed on a standby flicker to "Active".
        $poolId = (int) ($serverData['pool_id'] ?? 0);
        $activeId = 0;
        if ($poolId > 0) {
            $st = $db->prepare('SELECT active_server_id FROM server_pools WHERE id = ?');
            $st->execute([$poolId]);
            $activeId = (int) $st->fetchColumn();
        }
        // Any pool member (active or standby) reports pool-wide online state: the
        // client list on a member's page is pool-wide too, and after a manual
        // switch clients linger on the old member until they re-resolve the
        // domain — so "online" means "connected to SOME member of the pool".
        // refreshHandshakes() already keeps last_handshake as the newest value
        // seen across all members, so this reflects reality on either page.
        // A quiet-but-connected tunnel only refreshes its handshake on rekey, so a
        // 300s window makes idle clients flap between "online" and "active".
        // One tunable source of truth, shared with the UI (see onlineWindow()).
        $window = self::onlineWindow();
        if ($poolId > 0) {
            $stmt = $db->prepare("
                SELECT vc.name FROM vpn_clients vc
                JOIN vpn_servers s ON s.id = vc.server_id
                WHERE s.pool_id = ?
                  AND vc.status = 'active'
                  AND vc.last_handshake IS NOT NULL
                  AND vc.last_handshake >= DATE_SUB(NOW(), INTERVAL ? SECOND)
            ");
            $stmt->execute([$poolId, $window]);
        } else {
            $stmt = $db->prepare("
                SELECT vc.name FROM vpn_clients vc
                WHERE vc.server_id = ?
                  AND vc.status = 'active'
                  AND vc.last_handshake IS NOT NULL
                  AND vc.last_handshake >= DATE_SUB(NOW(), INTERVAL ? SECOND)
            ");
            $stmt->execute([$serverData['id'], $window]);
        }
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if (!in_array($row['name'], $result)) {
                $result[] = $row['name'];
            }
        }
        
        return $result;
    }
}
