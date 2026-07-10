<?php

/**
 * ServerNetCheck — verify that a server actually receives unsolicited inbound
 * UDP on the VPN port. Some providers silently drop inbound UDP (stateful
 * firewall / anti-amplification), which makes the host useless as an AmneziaWG
 * endpoint even though the container is up and SSH/TCP work.
 *
 * The check is active: a *prober* server (any other active server, whose
 * outbound UDP is known to work) sends probe datagrams to the target's public
 * IP:port while the target runs tcpdump on its internet interface. If the
 * packets show up in the capture, inbound UDP is open.
 */
class ServerNetCheck
{
    /**
     * @return array{success:bool, checked:bool, reachable?:bool, sent?:int,
     *               received?:int, prober?:string, target_ip?:string,
     *               port?:int, message:string}
     */
    public static function udpReachable(int $targetId, int $port = 443, ?int $proberId = null): array
    {
        $target = new VpnServer($targetId);
        $t = $target->getData();
        if (!$t) {
            return ['success' => false, 'checked' => false, 'message' => "Server {$targetId} not found"];
        }
        $targetIp = trim((string) ($t['host'] ?? ''));
        if ($targetIp === '') {
            return ['success' => false, 'checked' => false, 'message' => 'Server has no host IP'];
        }

        if ($proberId === null) {
            $proberId = self::pickProber($targetId);
        }
        if ($proberId === null) {
            return [
                'success' => true,
                'checked' => false,
                'message' => 'Нужен второй активный сервер как пробер — с него шлётся UDP-проба. Добавьте ещё один рабочий сервер, чтобы проверять новые.',
            ];
        }
        $prober = new VpnServer($proberId);
        $p = $prober->getData();
        $proberName = (string) ($p['name'] ?? ('#' . $proberId));

        // Target's internet interface (net0/eth0/…).
        $iface = trim($target->executeCommand(
            "ip route get 8.8.8.8 2>/dev/null | grep -oE 'dev [a-z0-9]+' | awk '{print \$2}' | head -1",
            true
        ));
        if ($iface === '') {
            $iface = 'eth0';
        }

        // 1. Arm tcpdump on the target for inbound UDP to its IP:port.
        $cap = '/tmp/udpcheck_' . $targetId . '.txt';
        $target->executeCommand(sprintf(
            "rm -f %s; timeout 8 tcpdump -ni %s 'udp and dst host %s and port %d' -c 40 > %s 2>&1 & echo armed",
            escapeshellarg($cap),
            escapeshellarg($iface),
            escapeshellarg($targetIp),
            $port,
            escapeshellarg($cap)
        ), true);
        sleep(1);

        // 2. Send probes from the prober (bash /dev/udp — reliable, no python).
        $sent = 12;
        $prober->executeCommand(sprintf(
            "bash -c 'for i in \$(seq 1 %d); do echo -n UDPCHECK > /dev/udp/%s/%d 2>/dev/null; sleep 0.25; done'; echo sent",
            $sent,
            $targetIp,
            $port
        ), true);

        // 3. Wait for the capture window to close, then count arrivals.
        sleep(6);
        $countRaw = trim($target->executeCommand(sprintf(
            "grep -c ' UDP,' %s 2>/dev/null || echo 0; rm -f %s",
            escapeshellarg($cap),
            escapeshellarg($cap)
        ), true));
        $received = (int) preg_replace('/\D.*$/s', '', $countRaw);

        $reachable = $received > 0;
        return [
            'success' => true,
            'checked' => true,
            'reachable' => $reachable,
            'sent' => $sent,
            'received' => $received,
            'prober' => $proberName,
            'target_ip' => $targetIp,
            'port' => $port,
            'message' => $reachable
                ? "Входящий UDP/{$port} работает — {$received} из {$sent} проб дошло (с «{$proberName}»). Сервер годится как VPN-узел."
                : "Входящий UDP/{$port} НЕ проходит — 0 из {$sent} проб дошло (с «{$proberName}»). Провайдер режет входящий UDP; сервер не подойдёт как VPN-узел.",
        ];
    }

    /** Pick an active server other than the target; prefer a pool member. */
    private static function pickProber(int $excludeId): ?int
    {
        $servers = VpnServer::listAll();
        $candidates = array_values(array_filter($servers, static function ($s) use ($excludeId) {
            return (int) $s['id'] !== $excludeId && ($s['status'] ?? '') === 'active';
        }));
        if (empty($candidates)) {
            return null;
        }
        usort($candidates, static function ($a, $b) {
            return (!empty($b['pool_id']) ? 1 : 0) <=> (!empty($a['pool_id']) ? 1 : 0);
        });
        return (int) $candidates[0]['id'];
    }
}
