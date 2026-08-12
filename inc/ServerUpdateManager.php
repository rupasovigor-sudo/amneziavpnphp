<?php

/**
 * Package updates for managed VPN servers (OS packages, Docker, awg2, WARP).
 *
 * Design notes — this runs against LIVE VPN hosts, so it is deliberately
 * conservative:
 *
 *  - audit() is strictly READ-ONLY. It never runs `apt-get update` (that takes
 *    the apt lock and can collide with unattended-upgrades); it reads the cached
 *    package lists and reports how stale they are instead.
 *  - updateOs() refuses to touch the ACTIVE pool member unless explicitly
 *    forced: clients are connected there and an apt run can restart services.
 *  - updateOs() HOLDS the docker/containerd packages for the duration of the
 *    upgrade. Upgrading dockerd restarts the daemon, which kills the awg2
 *    container and drops every tunnel — that must be a separate, deliberate
 *    action, not a side effect of routine patching.
 *  - It waits for the dpkg lock rather than failing, because fresh servers run
 *    unattended-upgrades on first boot (we hit exactly this during deploys).
 *  - After the upgrade it re-verifies the server and, if the VPN did not come
 *    back cleanly, clears validated_clean so auto-failover will not route
 *    clients onto a broken member.
 */
class ServerUpdateManager
{
    /** Seconds to wait for a busy dpkg/apt lock before giving up. */
    private const LOCK_WAIT_SECONDS = 600;

    /**
     * Read-only inventory of what is out of date on a server.
     *
     * @return array{ok:bool,error?:string,...}
     */
    public static function audit(int $serverId): array
    {
        try {
            $server = new VpnServer($serverId);
        } catch (Exception $e) {
            return ['ok' => false, 'error' => 'Сервер не найден: ' . $e->getMessage()];
        }

        // Strictly read-only: cached apt lists only, no `apt-get update`.
        $script = <<<'SH'
set -u
echo "kernel=$(uname -r)"
if [ -r /var/run/reboot-required ] || [ -r /run/reboot-required ]; then
  echo "reboot_required=1"
else
  echo "reboot_required=0"
fi
if command -v apt-get >/dev/null 2>&1; then
  echo "pkg_mgr=apt"
  up="$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -v '^Listing' | grep -c '/' || true)"
  echo "upgradable=${up:-0}"
  sec="$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -ci 'security' || true)"
  echo "security=${sec:-0}"
  # How stale the cached package lists are (audit never refreshes them itself).
  if [ -d /var/lib/apt/lists ]; then
    now="$(date +%s)"
    mt="$(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo "$now")"
    echo "lists_age_h=$(( (now - mt) / 3600 ))"
  fi
  # Is a docker package among the pending upgrades? (handled separately)
  dk="$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -Ec '^(docker|containerd)' || true)"
  echo "docker_upgradable=${dk:-0}"
  # Ubuntu deliberately withholds non-security updates from a share of machines
  # (phased rollout). Those are not actionable — counting them as "pending"
  # leaves a server looking stale for weeks with nothing to do about it.
  ph="$(LC_ALL=C apt-get -s upgrade 2>/dev/null | sed -n '/deferred due to phasing/{n;p;}' | wc -w || true)"
  echo "phased=${ph:-0}"
  # Kernel meta-packages need full-upgrade, not plain upgrade.
  kr="$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -Ec '^linux-' || true)"
  echo "kernel_upgradable=${kr:-0}"
else
  echo "pkg_mgr=unknown"
fi
if command -v docker >/dev/null 2>&1; then
  echo "docker_version=$(docker --version 2>/dev/null | sed 's/,.*//' | awk '{print $3}')"
  echo "awg2_running=$(docker ps --filter name=amnezia-awg2 --format '{{.Names}}' 2>/dev/null | grep -c amnezia-awg2 || true)"
  echo "awg2_image_created=$(docker inspect -f '{{.Created}}' "$(docker inspect -f '{{.Image}}' amnezia-awg2 2>/dev/null)" 2>/dev/null | cut -c1-19)"
fi
if command -v systemctl >/dev/null 2>&1; then
  echo "warp_active=$(systemctl is-active awg2-warp-egress.service 2>/dev/null || echo inactive)"
fi
# awg2 is built from a --depth=1 clone of upstream master with no version pin,
# so "is there an update" means "has upstream moved since this was cloned".
if [ -d /opt/amnezia/awg2/src/.git ]; then
  echo "awg2_local_head=$(git -C /opt/amnezia/awg2/src rev-parse HEAD 2>/dev/null)"
  echo "awg2_src_date=$(git -C /opt/amnezia/awg2/src log -1 --format=%cs 2>/dev/null)"
fi
# cf-warp v3 uses native registration (no wgcf binary), so the only thing that
# can go stale is our own runtime script — compare it byte-for-byte with the repo.
if [ -f /usr/local/sbin/awg2-warp-egress ]; then
  echo "warp_script_sha=$(sha256sum /usr/local/sbin/awg2-warp-egress 2>/dev/null | awk '{print $1}')"
fi
if command -v unattended-upgrade >/dev/null 2>&1 || [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
  echo "unattended=1"
else
  echo "unattended=0"
fi
SH;

        try {
            $out = $server->executeCommand($script);
        } catch (Exception $e) {
            return ['ok' => false, 'error' => 'SSH: ' . $e->getMessage()];
        }

        $values = [];
        foreach (preg_split('/\r?\n/', (string) $out) ?: [] as $line) {
            if (strpos($line, '=') === false) {
                continue;
            }
            [$k, $v] = explode('=', $line, 2);
            $k = trim($k);
            if ($k !== '') {
                $values[$k] = trim($v);
            }
        }

        $audit = [
            'ok'                => true,
            'upgradable'        => (int) ($values['upgradable'] ?? 0),
            'security'          => (int) ($values['security'] ?? 0),
            'docker_upgradable' => (int) ($values['docker_upgradable'] ?? 0),
            'kernel_upgradable' => (int) ($values['kernel_upgradable'] ?? 0),
            'phased'            => (int) ($values['phased'] ?? 0),
            // What the operator can actually act on right now.
            'actionable'        => max(0, (int) ($values['upgradable'] ?? 0) - (int) ($values['phased'] ?? 0)),
            'reboot_required'   => ($values['reboot_required'] ?? '0') === '1',
            'lists_age_h'       => isset($values['lists_age_h']) ? (int) $values['lists_age_h'] : null,
            'kernel'            => $values['kernel'] ?? '',
            'docker_version'    => $values['docker_version'] ?? '',
            'awg2_running'      => (int) ($values['awg2_running'] ?? 0) > 0,
            'awg2_image_created' => $values['awg2_image_created'] ?? '',
            'warp_active'       => ($values['warp_active'] ?? '') === 'active',
            'unattended'        => ($values['unattended'] ?? '0') === '1',
            'audited_at'        => date('Y-m-d H:i:s'),
        ];

        // awg2: compare the built source against upstream master.
        $localHead = $values['awg2_local_head'] ?? '';
        $upstreamHead = self::awg2UpstreamHead();
        $audit['awg2_local_head'] = $localHead ? substr($localHead, 0, 12) : '';
        $audit['awg2_src_date'] = $values['awg2_src_date'] ?? '';
        $audit['awg2_upstream_head'] = $upstreamHead ? substr($upstreamHead, 0, 12) : '';
        $audit['awg2_update_available'] = ($localHead !== '' && $upstreamHead !== null)
            ? ($localHead !== $upstreamHead)
            : null; // null = не смогли определить

        // cf-warp: our own runtime script is the only thing that can go stale.
        $installedSha = $values['warp_script_sha'] ?? '';
        $repoSha = self::warpRepoScriptSha();
        $audit['warp_update_available'] = ($installedSha !== '' && $repoSha !== null)
            ? ($installedSha !== $repoSha)
            : null;

        DB::conn()->prepare('UPDATE vpn_servers SET server_update_audit = ?, server_update_audited_at = NOW() WHERE id = ?')
            ->execute([json_encode($audit, JSON_UNESCAPED_UNICODE), $serverId]);

        return $audit;
    }

    /**
     * Current upstream HEAD of amneziawg-go, cached briefly so clicking
     * "проверить" on several servers does not hammer GitHub. Resolved from the
     * PANEL (one lookup for the whole fleet) rather than from each server, which
     * also works when a server has no outbound GitHub access.
     */
    /** The amneziawg-go ref servers are built from (AWG2_PIN_REF, default master). */
    public static function awg2PinnedRef(): string
    {
        return trim((string) Config::get('AWG2_PIN_REF', 'master')) ?: 'master';
    }

    public static function awg2UpstreamHead(): ?string
    {
        $ref = self::awg2PinnedRef();
        $cacheFile = sys_get_temp_dir() . '/awg2_upstream_head_' . md5($ref) . '.json';
        $ttl = max(300, (int) Config::get('AWG2_UPSTREAM_CACHE_SECONDS', '3600'));
        if (is_readable($cacheFile)) {
            $cached = json_decode((string) @file_get_contents($cacheFile), true);
            if (is_array($cached) && (time() - (int) ($cached['at'] ?? 0)) < $ttl && !empty($cached['head'])) {
                return (string) $cached['head'];
            }
        }

        $repo = escapeshellarg('https://github.com/amnezia-vpn/amneziawg-go.git');
        // A pinned ref may be a branch, a tag or a plain commit SHA.
        if (preg_match('/^[0-9a-f]{40}$/i', $ref)) {
            @file_put_contents($cacheFile, json_encode(['head' => strtolower($ref), 'at' => time()]));
            return strtolower($ref);
        }
        $refArg = $ref === 'master' ? 'HEAD' : escapeshellarg($ref);
        $out = @shell_exec("git ls-remote {$repo} {$refArg} 2>/dev/null");
        if (!$out || !preg_match('/^([0-9a-f]{40})\s/m', (string) $out, $m)) {
            return null;
        }
        @file_put_contents($cacheFile, json_encode(['head' => $m[1], 'at' => time()]));
        return $m[1];
    }

    /** sha256 of the WARP runtime script shipped in this repo. */
    public static function warpRepoScriptSha(): ?string
    {
        $path = dirname(__DIR__) . '/scripts/awg2_warp_egress_runtime_v3.sh';
        return is_readable($path) ? hash_file('sha256', $path) : null;
    }

    /** Last stored audit for a server, or null if it was never audited. */
    public static function lastAudit(int $serverId): ?array
    {
        $st = DB::conn()->prepare('SELECT server_update_audit FROM vpn_servers WHERE id = ?');
        $st->execute([$serverId]);
        $raw = $st->fetchColumn();
        if (!$raw) {
            return null;
        }
        $data = json_decode((string) $raw, true);
        return is_array($data) ? $data : null;
    }

    /**
     * Is this server the ACTIVE member of a failover pool? Updating it would
     * disturb the clients currently terminating there.
     */
    public static function isActivePoolMember(int $serverId): bool
    {
        $st = DB::conn()->prepare(
            'SELECT COUNT(*) FROM vpn_servers s
             JOIN server_pools p ON p.id = s.pool_id
             WHERE s.id = ? AND p.active_server_id = s.id'
        );
        $st->execute([$serverId]);
        return (int) $st->fetchColumn() > 0;
    }

    /**
     * Publish an intermediate progress line for a running job. The UI polls the
     * state every few seconds, so without this a multi-minute apt run looks
     * indistinguishable from a hung one.
     */
    public static function progress(int $serverId, string $message): void
    {
        DB::conn()->prepare('UPDATE vpn_servers SET server_update_message = ? WHERE id = ? AND server_update_state = ?')
            ->execute([mb_substr($message, 0, 1000), $serverId, 'running']);
    }

    public static function setState(int $serverId, ?string $state, string $message = ''): void
    {
        DB::conn()->prepare(
            'UPDATE vpn_servers
             SET server_update_state = ?, server_update_message = ?,
                 server_update_started_at = CASE WHEN ? = \'running\' THEN NOW() ELSE server_update_started_at END
             WHERE id = ?'
        )->execute([$state, mb_substr($message, 0, 1000), (string) $state, $serverId]);
    }

    /** @return array{state:?string,message:?string,started_at:?string} */
    public static function getState(int $serverId): array
    {
        $st = DB::conn()->prepare(
            'SELECT server_update_state, server_update_message, server_update_started_at
             FROM vpn_servers WHERE id = ?'
        );
        $st->execute([$serverId]);
        $row = $st->fetch(PDO::FETCH_ASSOC) ?: [];
        return [
            'state'      => $row['server_update_state'] ?? null,
            'message'    => $row['server_update_message'] ?? null,
            'started_at' => $row['server_update_started_at'] ?? null,
        ];
    }

    /**
     * Apply pending OS package updates. Docker/containerd are held for the
     * duration so routine patching can never restart the daemon underneath the
     * running VPN container. Blocking and multi-minute — run it from the worker.
     *
     * @return array{success:bool,message:string,audit?:array}
     */
    public static function updateOs(int $serverId, bool $force = false): array
    {
        if (!$force && self::isActivePoolMember($serverId)) {
            return [
                'success' => false,
                'message' => 'Это активный член пула — на нём висят клиенты. Сначала переключите пул на другой сервер.',
            ];
        }

        try {
            $server = new VpnServer($serverId);
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Сервер не найден: ' . $e->getMessage()];
        }

        $lockWait = self::LOCK_WAIT_SECONDS;

        // Split into phases with a status update between each, so the UI shows
        // real progress instead of a spinner that sits still for minutes.
        self::progress($serverId, 'Ожидание блокировки apt и обновление списка пакетов…');
        $prepare = <<<SH
set -u
export DEBIAN_FRONTEND=noninteractive
# Fresh servers run unattended-upgrades on first boot; wait it out instead of
# failing the whole update on a transient lock.
waited=0
while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
  if [ "\$waited" -ge {$lockWait} ]; then echo "RESULT=lock_timeout"; exit 1; fi
  sleep 5
  waited=\$(( waited + 5 ))
done
echo "lock_waited=\$waited"
apt-get update -qq || { echo "RESULT=update_failed"; exit 1; }
before="\$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -v '^Listing' | grep -c '/' || true)"
echo "before=\${before:-0}"
echo "RESULT=ok"
SH;

        try {
            $out = (string) $server->executeCommand($prepare);
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'SSH/apt: ' . $e->getMessage()];
        }
        if (strpos($out, 'RESULT=ok') === false) {
            return [
                'success' => false,
                'message' => strpos($out, 'RESULT=lock_timeout') !== false
                    ? 'не дождались dpkg-lock (' . self::LOCK_WAIT_SECONDS . 's) — идёт другое обновление'
                    : 'apt-get update не отработал (репозитории недоступны?)',
            ];
        }

        $before = preg_match('/^before=(\d+)/m', $out, $m) ? (int) $m[1] : 0;
        if ($before === 0) {
            self::progress($serverId, 'Обновлять нечего, проверяю сервер…');
        } else {
            self::progress($serverId, "Устанавливаю обновления: {$before} пакет(ов). Это может занять несколько минут…");
        }

        $upgrade = <<<'SH'
set -u
export DEBIAN_FRONTEND=noninteractive
# Hold docker/containerd: upgrading dockerd restarts it and kills the awg2
# container. That is a separate, deliberate operation.
HELD=""
for p in docker.io docker-ce docker-ce-cli containerd containerd.io; do
  if dpkg -l "$p" >/dev/null 2>&1; then
    apt-mark hold "$p" >/dev/null 2>&1 && HELD="$HELD $p"
  fi
done
echo "held=$HELD"
apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
rc=$?
# Always restore the previous hold state, even if the upgrade failed.
for p in $HELD; do apt-mark unhold "$p" >/dev/null 2>&1; done
if [ "$rc" -ne 0 ]; then echo "RESULT=upgrade_failed"; exit 1; fi
apt-get -y autoremove --purge >/dev/null 2>&1 || true
after="$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -v '^Listing' | grep -c '/' || true)"
echo "after=${after:-0}"
# Classify what is left, otherwise "0 installed, 7 remaining" reads as a
# failure when it is in fact the expected outcome of `apt-get upgrade`.
echo "left_docker=$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -Ec '^(docker|containerd)' || true)"
echo "left_kernel=$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -Ec '^linux-' || true)"
echo "left_phased=$(LC_ALL=C apt-get -s upgrade 2>/dev/null | sed -n '/deferred due to phasing/,/^[A-Z]/p' | grep -c '^ ' || true)"
# "kept back" splits two ways, needing DIFFERENT actions:
#  - on apt-mark hold (often the cloud image pins qemu-guest-agent): neither
#    upgrade nor full-upgrade will touch it; only `apt-mark unhold` will.
#  - kept back but NOT held: the upgrade needs new deps -> full-upgrade.
# Reporting them together (or as "needs full-upgrade") is misleading, so split.
echo "left_heldback=$(LC_ALL=C apt-get -s upgrade 2>/dev/null | awk '/have been kept back/{f=1;next} /^[0-9]+ upgraded/{f=0} f' | wc -w || true)"
echo "left_onhold=$(comm -12 <(apt-mark showhold 2>/dev/null | sort -u) <(LC_ALL=C apt list --upgradable 2>/dev/null | grep -v '^Listing' | cut -d/ -f1 | sort -u) | grep -c . || true)"
if [ -r /var/run/reboot-required ] || [ -r /run/reboot-required ]; then
  echo "reboot_required=1"
else
  echo "reboot_required=0"
fi
echo "RESULT=ok"
SH;

        try {
            $out = (string) $server->executeCommand($upgrade);
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'SSH/apt: ' . $e->getMessage()];
        }
        if (strpos($out, 'RESULT=ok') === false) {
            return ['success' => false, 'message' => 'apt завершился с ошибкой при установке обновлений'];
        }

        $after = preg_match('/^after=(\d+)/m', $out, $m2) ? (int) $m2[1] : 0;
        $reboot = (bool) preg_match('/^reboot_required=1/m', $out);
        self::progress($serverId, 'Пакеты установлены, проверяю сервер…');

        $installed = max(0, $before - $after);
        $msg = "Обновлено пакетов: {$installed}";

        if ($after > 0) {
            // Explain the leftovers: all three causes are expected, not errors.
            $leftDocker = preg_match('/^left_docker=(\d+)/m', $out, $d) ? (int) $d[1] : 0;
            $leftKernel = preg_match('/^left_kernel=(\d+)/m', $out, $k) ? (int) $k[1] : 0;
            $leftPhased = preg_match('/^left_phased=(\d+)/m', $out, $p) ? (int) $p[1] : 0;
            $leftHeld = preg_match('/^left_heldback=(\d+)/m', $out, $h) ? (int) $h[1] : 0;
            $leftOnHold = preg_match('/^left_onhold=(\d+)/m', $out, $oh) ? (int) $oh[1] : 0;
            // Kernel packages are also "kept back"; and on-hold packages show up
            // as kept back too. Don't double-count: full-upgrade candidates are
            // the kept-back ones that are neither kernel nor pinned by a hold.
            $leftHeldOther = max(0, $leftHeld - $leftKernel - $leftOnHold);
            $why = [];
            if ($leftDocker) {
                $why[] = "{$leftDocker} Docker (удерживаются намеренно — обновляйте кнопкой «Docker»)";
            }
            if ($leftKernel) {
                $why[] = "{$leftKernel} ядро (нужен full-upgrade — кнопка «Ядро»)";
            }
            if ($leftHeldOther) {
                $why[] = "{$leftHeldOther} придержаны — нужны новые зависимости (full-upgrade, кнопка «Ядро»)";
            }
            if ($leftOnHold) {
                $why[] = "{$leftOnHold} на hold (закреплены — обычно провайдером; ни upgrade, ни full-upgrade не тронет, снять: apt-mark unhold)";
            }
            if ($leftPhased) {
                $why[] = "{$leftPhased} отложены Ubuntu (phased updates — станут доступны позже сами)";
            }
            $other = max(0, $after - $leftDocker - $leftKernel - $leftHeldOther - $leftOnHold - $leftPhased);
            if ($other > 0) {
                $why[] = "{$other} прочие";
            }
            $msg .= ". Осталось {$after}" . ($why ? ': ' . implode(', ', $why) : '');
        }

        if ($reboot) {
            $msg .= '. ⚠ Требуется перезагрузка (ядро/библиотеки)';
        }

        // Verify the VPN survived; if not, take the member out of failover.
        $verify = self::verifyAfterUpdate($serverId);
        $msg .= '. ' . $verify['message'];

        $audit = self::audit($serverId);

        return [
            'success' => $verify['ok'],
            'message' => $msg,
            'audit'   => $audit['ok'] ? $audit : null,
        ];
    }

    /**
     * Run a full-upgrade so packages that need NEW dependencies can install —
     * in practice the kernel meta-packages, which plain `apt-get upgrade`
     * always keeps back. Separate from updateOs() because full-upgrade may pull
     * in and remove packages, and a new kernel only takes effect after a reboot.
     * Docker stays held here too.
     */
    public static function updateKernel(int $serverId, bool $force = false): array
    {
        if (!$force && self::isActivePoolMember($serverId)) {
            return ['success' => false, 'message' => 'Это активный член пула — сначала переключите пул на другой сервер.'];
        }
        try {
            $server = new VpnServer($serverId);
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Сервер не найден: ' . $e->getMessage()];
        }

        self::progress($serverId, 'full-upgrade: ставлю пакеты, требующие новых зависимостей (ядро)…');
        $lockWait = self::LOCK_WAIT_SECONDS;
        $script = <<<SH
set -u
export DEBIAN_FRONTEND=noninteractive
waited=0
while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
  if [ "\$waited" -ge {$lockWait} ]; then echo "RESULT=lock_timeout"; exit 1; fi
  sleep 5; waited=\$(( waited + 5 ))
done
HELD=""
for p in docker.io docker-ce docker-ce-cli containerd containerd.io; do
  dpkg -l "\$p" >/dev/null 2>&1 && apt-mark hold "\$p" >/dev/null 2>&1 && HELD="\$HELD \$p"
done
apt-get update -qq || { for p in \$HELD; do apt-mark unhold "\$p" >/dev/null 2>&1; done; echo "RESULT=update_failed"; exit 1; }
before="\$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -v '^Listing' | grep -c '/' || true)"
echo "before=\${before:-0}"
apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade
rc=\$?
for p in \$HELD; do apt-mark unhold "\$p" >/dev/null 2>&1; done
if [ "\$rc" -ne 0 ]; then echo "RESULT=upgrade_failed"; exit 1; fi
apt-get -y autoremove --purge >/dev/null 2>&1 || true
after="\$(LC_ALL=C apt list --upgradable 2>/dev/null | grep -v '^Listing' | grep -c '/' || true)"
echo "after=\${after:-0}"
if [ -r /var/run/reboot-required ] || [ -r /run/reboot-required ]; then echo "reboot_required=1"; else echo "reboot_required=0"; fi
echo "RESULT=ok"
SH;

        try {
            $out = (string) $server->executeCommand($script);
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'SSH/apt: ' . $e->getMessage()];
        }
        if (strpos($out, 'RESULT=ok') === false) {
            return [
                'success' => false,
                'message' => strpos($out, 'RESULT=lock_timeout') !== false
                    ? 'не дождались dpkg-lock' : 'full-upgrade завершился с ошибкой',
            ];
        }

        $before = preg_match('/^before=(\d+)/m', $out, $m) ? (int) $m[1] : 0;
        $after = preg_match('/^after=(\d+)/m', $out, $m2) ? (int) $m2[1] : 0;
        $reboot = (bool) preg_match('/^reboot_required=1/m', $out);

        self::progress($serverId, 'Проверяю сервер после full-upgrade…');
        $verify = self::verifyAfterUpdate($serverId);

        $msg = 'full-upgrade: обновлено ' . max(0, $before - $after) . ", осталось {$after}";
        if ($reboot) {
            $msg .= '. ⚠ Новое ядро активируется только после перезагрузки';
        }

        return [
            'success' => $verify['ok'],
            'message' => $msg . '. ' . $verify['message'],
            'audit'   => self::audit($serverId) ?: null,
        ];
    }

    /**
     * Upgrade Docker/containerd. Deliberately separate from updateOs(): this
     * restarts the daemon, which bounces the awg2 container and drops every
     * tunnel on this host for a few seconds.
     *
     * @return array{success:bool,message:string,audit?:?array}
     */
    public static function updateDocker(int $serverId, bool $force = false): array
    {
        if (!$force && self::isActivePoolMember($serverId)) {
            return ['success' => false, 'message' => 'Это активный член пула — обновление Docker разорвёт соединения клиентов. Сначала переключите пул.'];
        }
        try {
            $server = new VpnServer($serverId);
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Сервер не найден: ' . $e->getMessage()];
        }

        self::progress($serverId, 'Обновляю Docker: ожидание apt, затем перезапуск демона…');
        $lockWait = self::LOCK_WAIT_SECONDS;
        $script = <<<SH
set -u
export DEBIAN_FRONTEND=noninteractive
waited=0
while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
  if [ "\$waited" -ge {$lockWait} ]; then echo "RESULT=lock_timeout"; exit 1; fi
  sleep 5; waited=\$(( waited + 5 ))
done
echo "before=\$(docker --version 2>/dev/null | sed 's/,.*//' | awk '{print \$3}')"
for p in docker.io docker-ce docker-ce-cli containerd containerd.io; do
  dpkg -l "\$p" >/dev/null 2>&1 && apt-mark unhold "\$p" >/dev/null 2>&1
done
apt-get update -qq || { echo "RESULT=update_failed"; exit 1; }
PKGS=""
for p in docker.io docker-ce docker-ce-cli containerd containerd.io; do
  dpkg -l "\$p" >/dev/null 2>&1 && PKGS="\$PKGS \$p"
done
[ -z "\$PKGS" ] && { echo "RESULT=nothing"; exit 0; }
apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install --only-upgrade \$PKGS || { echo "RESULT=upgrade_failed"; exit 1; }
echo "after=\$(docker --version 2>/dev/null | sed 's/,.*//' | awk '{print \$3}')"
# restart_policy=always brings awg2 back, but give it a moment and nudge it.
sleep 8
docker start amnezia-awg2 >/dev/null 2>&1 || true
systemctl restart awg2-warp-egress.service >/dev/null 2>&1 || true
echo "RESULT=ok"
SH;

        try {
            $out = (string) $server->executeCommand($script);
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'SSH/apt: ' . $e->getMessage()];
        }

        if (strpos($out, 'RESULT=nothing') !== false) {
            return ['success' => true, 'message' => 'Пакеты Docker не установлены через apt — обновлять нечего'];
        }
        if (strpos($out, 'RESULT=ok') === false) {
            $reason = strpos($out, 'RESULT=lock_timeout') !== false ? 'не дождались dpkg-lock' : 'apt не смог обновить Docker';
            return ['success' => false, 'message' => $reason];
        }

        $before = preg_match('/^before=(.*)$/m', $out, $m) ? trim($m[1]) : '?';
        $after = preg_match('/^after=(.*)$/m', $out, $m2) ? trim($m2[1]) : '?';
        $verify = self::verifyAfterUpdate($serverId);

        return [
            'success' => $verify['ok'],
            'message' => "Docker: {$before} → {$after}. " . $verify['message'],
            'audit'   => self::audit($serverId) ?: null,
        ];
    }

    /**
     * Rebuild awg2 from current upstream, keeping the pool identity.
     * Pool members only — see ServerPool::redeployMember().
     */
    public static function rebuildAwg2(int $serverId, bool $force = false): array
    {
        if (!$force && self::isActivePoolMember($serverId)) {
            return ['success' => false, 'message' => 'Это активный член пула — пересборка awg2 разорвёт соединения. Сначала переключите пул.'];
        }
        self::progress($serverId, 'Пересобираю awg2 из upstream (сборка Go занимает несколько минут)…');
        $res = ServerPool::redeployMember($serverId);
        if (empty($res['success'])) {
            return ['success' => false, 'message' => (string) $res['message']];
        }
        $verify = self::verifyAfterUpdate($serverId);
        return [
            'success' => $verify['ok'],
            'message' => $res['message'] . '. ' . $verify['message'],
            'audit'   => self::audit($serverId) ?: null,
        ];
    }

    /** Reinstall the cf-warp egress (picks up newer runtime scripts). */
    public static function reinstallWarp(int $serverId, bool $force = false): array
    {
        if (!$force && self::isActivePoolMember($serverId)) {
            return ['success' => false, 'message' => 'Это активный член пула — переустановка WARP прервёт egress. Сначала переключите пул.'];
        }
        try {
            self::progress($serverId, 'Переустанавливаю WARP egress…');
            $proto = InstallProtocolManager::getBySlug('cf-warp');
            if (!$proto) {
                return ['success' => false, 'message' => 'Протокол cf-warp не найден'];
            }
            $res = InstallProtocolManager::activate(new VpnServer($serverId), $proto, []);
            if (empty($res['success'])) {
                return ['success' => false, 'message' => 'Переустановка WARP не удалась'];
            }
        } catch (Throwable $e) {
            return ['success' => false, 'message' => 'WARP: ' . $e->getMessage()];
        }

        $audit = self::audit($serverId);
        $ok = !empty($audit['warp_active']);
        return [
            'success' => $ok,
            'message' => $ok ? 'WARP egress переустановлен и активен' : 'WARP переустановлен, но сервис не активен — проверьте вручную',
            'audit'   => $audit ?: null,
        ];
    }

    /**
     * Reboot the server and wait for it to come back. The awg2 container has
     * restart_policy=always and the WARP unit is enabled, so both return on
     * boot; we still re-verify and nudge WARP, whose policy routing rule is
     * known to occasionally not survive a restart.
     */
    public static function reboot(int $serverId, bool $force = false): array
    {
        if (!$force && self::isActivePoolMember($serverId)) {
            return ['success' => false, 'message' => 'Это активный член пула — перезагрузка отключит клиентов. Сначала переключите пул.'];
        }
        try {
            $server = new VpnServer($serverId);
            // Detach so the SSH channel closing does not abort the reboot.
            $server->executeCommand('(sleep 2; systemctl reboot) >/dev/null 2>&1 & echo reboot-scheduled', true);
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Не удалось отправить команду перезагрузки: ' . $e->getMessage()];
        }

        // Give it time to actually go down before probing, otherwise the first
        // probe succeeds against the still-running system.
        self::progress($serverId, 'Команда перезагрузки отправлена, жду ухода сервера…');
        sleep(20);

        $started = time();
        $deadline = $started + 300;
        $back = false;
        while (time() < $deadline) {
            sleep(10);
            self::progress($serverId, 'Жду возврата сервера… ' . (time() - $started) . 'с из 300');
            try {
                $probe = (new VpnServer($serverId))->executeCommand('echo up');
                if (strpos((string) $probe, 'up') !== false) {
                    $back = true;
                    break;
                }
            } catch (Throwable $e) {
                // still down — keep waiting
            }
        }

        if (!$back) {
            DB::conn()->prepare(
                'UPDATE vpn_servers SET validated_clean = NULL, validated_at = NOW(), validation_note = ?
                 WHERE id = ? AND pool_id IS NOT NULL'
            )->execute(['снят с failover: сервер не вернулся после перезагрузки', $serverId]);
            return ['success' => false, 'message' => 'Сервер не вернулся в течение 5 минут — проверьте через панель провайдера. Снят с авто-failover.'];
        }

        // The WARP fwmark rule sometimes does not survive a restart.
        try {
            (new VpnServer($serverId))->executeCommand('systemctl restart awg2-warp-egress.service >/dev/null 2>&1 || true; echo done', true);
        } catch (Throwable $e) {
            // non-fatal
        }

        $verify = self::verifyAfterUpdate($serverId);
        return [
            'success' => $verify['ok'],
            'message' => 'Сервер перезагрузился и доступен. ' . $verify['message'],
            'audit'   => self::audit($serverId) ?: null,
        ];
    }

    /**
     * Rolling update of a whole failover pool, one member at a time.
     *
     * Order matters: standby members are patched first and verified; only once a
     * healthy updated standby exists is the pool switched onto it, and only then
     * is the former active patched. That keeps a serving member available at
     * every step. The active is never touched while it is still active.
     *
     * Note the honest limitation: clients linger on the member they last
     * resolved, so patching the FORMER active still bumps whoever stayed on it.
     * Nothing can avoid that short of waiting for clients to drift over.
     *
     * @param string[] $actions subset of os|docker|awg2|warp|reboot, in order
     * @return array{success:bool,message:string,steps:array<int,array<string,mixed>>}
     */
    public static function rollingPoolUpdate(int $poolId, array $actions = ['os']): array
    {
        $actions = array_values(array_intersect($actions, ['os', 'docker', 'awg2', 'warp', 'reboot']));
        if (!$actions) {
            return ['success' => false, 'message' => 'Не выбрано ни одного действия', 'steps' => []];
        }

        $pool = ServerPool::get($poolId);
        if (!$pool) {
            return ['success' => false, 'message' => 'Пул не найден', 'steps' => []];
        }
        $members = ServerPool::members($poolId);
        if (count($members) < 2) {
            return [
                'success' => false,
                'message' => 'В пуле меньше двух серверов — обновлять без простоя нечем. Обновляйте сервер вручную.',
                'steps' => [],
            ];
        }

        $activeId = (int) ($pool['active_server_id'] ?? 0);
        $steps = [];
        $failed = false;

        $run = function (int $serverId, string $label) use ($actions, &$steps): bool {
            foreach ($actions as $action) {
                $res = self::runAction($serverId, $action, false);
                $steps[] = [
                    'server' => $serverId,
                    'label'  => $label,
                    'action' => $action,
                    'ok'     => !empty($res['success']),
                    'message' => (string) ($res['message'] ?? ''),
                ];
                self::recordHistory($serverId, $action, !empty($res['success']) ? 'done' : 'failed', (string) ($res['message'] ?? ''), false);
                if (empty($res['success'])) {
                    return false;
                }
            }
            return true;
        };

        // 1. Every standby, one at a time.
        $updatedStandby = 0;
        foreach ($members as $m) {
            $id = (int) $m['id'];
            if ($id === $activeId) {
                continue;
            }
            if ($run($id, 'standby')) {
                $updatedStandby++;
            } else {
                $failed = true;
                break;
            }
        }

        if ($failed || $updatedStandby === 0) {
            return [
                'success' => false,
                'message' => 'Обновление резервных серверов не завершилось — активный сервер не трогали. Разберитесь и повторите.',
                'steps' => $steps,
            ];
        }

        // 2. Promote a healthy, updated standby before touching the active one.
        $target = null;
        foreach ($members as $m) {
            $id = (int) $m['id'];
            if ($id !== $activeId && (int) ($m['validated_clean'] ?? 0) === 1) {
                $target = $id;
                break;
            }
        }
        if ($target === null) {
            return [
                'success' => false,
                'message' => 'Резервные обновлены, но ни один не помечен годным (validated_clean=1) — переключать пул на непроверенный сервер небезопасно. Активный не обновлён.',
                'steps' => $steps,
            ];
        }

        $switch = ServerPool::setActive($poolId, $target, 'rolling_update');
        $steps[] = [
            'server' => $target, 'label' => 'switch', 'action' => 'activate',
            'ok' => !empty($switch['success']), 'message' => (string) ($switch['message'] ?? ''),
        ];
        if (empty($switch['success'])) {
            return ['success' => false, 'message' => 'Не удалось переключить пул — бывший активный не обновлён.', 'steps' => $steps];
        }

        // 3. The former active is now a standby: patch it too.
        if ($activeId > 0 && !$run($activeId, 'ex-active')) {
            return [
                'success' => false,
                'message' => 'Пул переключён на обновлённый сервер, но обновление бывшего активного не завершилось.',
                'steps' => $steps,
            ];
        }

        return [
            'success' => true,
            'message' => "Пул обновлён: резервных {$updatedStandby}, переключение на #{$target}, бывший активный обновлён.",
            'steps' => $steps,
        ];
    }

    /** Dispatch a single maintenance action by name. */
    public static function runAction(int $serverId, string $action, bool $force = false): array
    {
        switch ($action) {
            case 'kernel': return self::updateKernel($serverId, $force);
            case 'docker': return self::updateDocker($serverId, $force);
            case 'awg2':   return self::rebuildAwg2($serverId, $force);
            case 'warp':   return self::reinstallWarp($serverId, $force);
            case 'reboot': return self::reboot($serverId, $force);
            default:       return self::updateOs($serverId, $force);
        }
    }

    /** Record a finished maintenance action so the UI can show what was done. */
    public static function recordHistory(int $serverId, string $action, string $state, string $message, bool $forced = false): void
    {
        try {
            $st = DB::conn()->prepare('SELECT server_update_started_at FROM vpn_servers WHERE id = ?');
            $st->execute([$serverId]);
            $startedAt = $st->fetchColumn() ?: null;

            DB::conn()->prepare(
                'INSERT INTO server_update_history (server_id, action, state, message, forced, started_at)
                 VALUES (?, ?, ?, ?, ?, ?)'
            )->execute([$serverId, $action, $state, mb_substr($message, 0, 1000), $forced ? 1 : 0, $startedAt]);
        } catch (Throwable $e) {
            error_log('ServerUpdateManager::recordHistory: ' . $e->getMessage());
        }
    }

    /** @return array<int,array<string,mixed>> most recent actions first */
    public static function history(int $serverId, int $limit = 10): array
    {
        try {
            $st = DB::conn()->prepare(
                'SELECT action, state, message, forced, started_at, finished_at
                 FROM server_update_history WHERE server_id = ?
                 ORDER BY finished_at DESC LIMIT ' . max(1, min(50, $limit))
            );
            $st->execute([$serverId]);
            return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
        } catch (Throwable $e) {
            return [];
        }
    }

    /**
     * Guarantee the worker log is writable by the current (www-data) user
     * BEFORE spawning. The worker is launched as `nohup php ... >> LOG &`, and
     * the shell opens that redirect BEFORE exec'ing the worker — so if LOG is
     * owned by root (e.g. left behind by a manual `docker exec` run), the
     * redirect fails and the worker NEVER RUNS. The job then stays 'running'
     * with no log line until the reaper marks it failed. This is the same
     * failure mode that silently killed every #18 update. The logs dir is
     * www-data-owned, so a stale root-owned file inside it can be replaced.
     */
    public static function ensureWritableLog(string $path): void
    {
        if (is_file($path) && !is_writable($path)) {
            @unlink($path);
        }
        if (!is_file($path)) {
            @touch($path);
        }
        @chmod($path, 0664);
    }

    /**
     * Clear jobs left in 'running' by a worker that died (container restart,
     * OOM). Without this the UI would poll a job that will never finish.
     */
    public static function reapStuck(int $olderThanSeconds = 3600): int
    {
        $st = DB::conn()->prepare(
            "UPDATE vpn_servers
             SET server_update_state = 'failed',
                 server_update_message = 'Задача прервана: воркер не завершился (сброшено автоматически)'
             WHERE server_update_state = 'running'
               AND server_update_started_at IS NOT NULL
               AND server_update_started_at < DATE_SUB(NOW(), INTERVAL ? SECOND)"
        );
        $st->execute([max(600, $olderThanSeconds)]);
        return $st->rowCount();
    }

    /**
     * Post-update gate: re-run the health checks. If the VPN did not come back,
     * drop validated_clean so auto-failover will not send clients here.
     *
     * @return array{ok:bool,message:string}
     */
    public static function verifyAfterUpdate(int $serverId): array
    {
        try {
            $monitoring = new ServerMonitoring($serverId);
            $checks = $monitoring->collectHealthChecks();
        } catch (Exception $e) {
            return ['ok' => false, 'message' => 'Проверка после обновления не отработала: ' . $e->getMessage()];
        }

        $critical = [];
        foreach (['container_running', 'wireguard_interface', 'wireguard_port', 'wireguard_input_drops'] as $name) {
            if (isset($checks[$name]) && empty($checks[$name]['ok'])) {
                $critical[] = $checks[$name]['message'];
            }
        }

        if ($critical) {
            DB::conn()->prepare(
                'UPDATE vpn_servers SET validated_clean = NULL, validated_at = NOW(), validation_note = ?
                 WHERE id = ? AND pool_id IS NOT NULL'
            )->execute(['снят с failover: проблемы после обновления пакетов', $serverId]);

            return [
                'ok' => false,
                'message' => 'ПРОВЕРКА НЕ ПРОЙДЕНА: ' . implode('; ', $critical) . '. Сервер снят с авто-failover',
            ];
        }

        return ['ok' => true, 'message' => 'Проверка пройдена: контейнер, awg0 и порт в норме'];
    }
}
