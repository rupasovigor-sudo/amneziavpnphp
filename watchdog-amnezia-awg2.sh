#!/usr/bin/env bash
set -u
set -o pipefail

# === CONFIG ===
# Standalone script for the remote Amnezia server. It does not read panel .env.
CONTAINER="${CONTAINER:-amnezia-awg2}"
WG_IFACE="${WG_IFACE:-awg0}"

# Реальный UDP-порт Amnezia на хосте. По умолчанию определяем из `docker port`.
# Можно жестко задать здесь, если нужно: UDP_PORT="30184"
UDP_PORT="${UDP_PORT:-auto}"

# Handshake НЕ является причиной рестарта.
# Это только диагностическое окно: считаем, сколько peers были активны недавно.
ACTIVE_HANDSHAKE_WINDOW="${ACTIVE_HANDSHAKE_WINDOW:-1800}"

# Рестартовать только при критических ошибках.
MAX_FAILS_BEFORE_RESTART="${MAX_FAILS_BEFORE_RESTART:-2}"

LOG_FILE="${LOG_FILE:-/var/log/amnezia-awg2-watchdog.log}"
STATE_DIR="${STATE_DIR:-/var/run/amnezia-watchdog}"
FAIL_FILE="${STATE_DIR}/${CONTAINER}.fails"
LAST_RESTART_FILE="${STATE_DIR}/${CONTAINER}.last_restart"
LOCK_FILE="${STATE_DIR}/${CONTAINER}.lock"

# Не рестартовать чаще, чем раз в 3 минуты
RESTART_COOLDOWN="${RESTART_COOLDOWN:-180}"

# Не позволяем отдельным docker/awg/iptables проверкам зависать.
CHECK_TIMEOUT="${CHECK_TIMEOUT:-12}"
RESTART_TIMEOUT="${RESTART_TIMEOUT:-60}"

mkdir -p "$STATE_DIR"
touch "$LOG_FILE" 2>/dev/null || true

exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  echo "$(date '+%F %T') [$CONTAINER] SKIP: another watchdog instance is running" >> "$LOG_FILE"
  exit 0
fi

log() {
  echo "$(date '+%F %T') [$CONTAINER] $*" >> "$LOG_FILE"
}

fail_count_get() {
  cat "$FAIL_FILE" 2>/dev/null || echo 0
}

fail_count_set() {
  echo "$1" > "$FAIL_FILE"
}

reset_fail_count() {
  fail_count_set 0
}

inc_fail_count() {
  local current
  current="$(fail_count_get)"
  current=$((current + 1))
  fail_count_set "$current"
  echo "$current"
}

can_restart_now() {
  local now last delta
  now="$(date +%s)"
  last="$(cat "$LAST_RESTART_FILE" 2>/dev/null || echo 0)"
  delta=$((now - last))

  [ "$delta" -ge "$RESTART_COOLDOWN" ]
}

restart_container() {
  local reason="$1"

  if ! can_restart_now; then
    log "RESTART SKIPPED: cooldown active. reason=${reason}"
    return 1
  fi

  log "RESTART: ${reason}"
  if timeout --kill-after=10s "${RESTART_TIMEOUT}s" docker restart "$CONTAINER" >>"$LOG_FILE" 2>&1; then
    echo "$(date +%s)" > "$LAST_RESTART_FILE"
    reset_fail_count
    sleep 5
    if docker_running; then
      log "RESTART OK: container is running after restart"
    else
      log "RESTART WARN: docker restart returned success but container is not running"
    fi
  else
    log "RESTART FAILED: docker restart command failed or timed out. reason=${reason}"
    return 1
  fi
}

critical_fail() {
  local reason="$1"
  local fails

  fails="$(inc_fail_count)"
  log "CRITICAL FAIL ${fails}/${MAX_FAILS_BEFORE_RESTART}: ${reason}"

  if [ "$fails" -ge "$MAX_FAILS_BEFORE_RESTART" ]; then
    restart_container "$reason"
  fi
}

warn() {
  log "WARN: $*"
}

docker_running() {
  timeout --kill-after=3s "${CHECK_TIMEOUT}s" docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true
}

docker_exec() {
  timeout --kill-after=3s "${CHECK_TIMEOUT}s" docker exec "$CONTAINER" sh -c "$1"
}

docker_cmd() {
  timeout --kill-after=3s "${CHECK_TIMEOUT}s" docker "$@"
}

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

detect_udp_port() {
  local port

  port="$(
    docker_cmd port "$CONTAINER" 2>/dev/null \
      | awk '
      /\/udp/ {
        target = $NF
        sub(/.*:/, "", target)
        if (target ~ /^[0-9]+$/) {
          print target
          exit
        }
      }
    '
  )"

  if is_uint "$port"; then
    echo "$port"
    return 0
  fi

  docker_cmd inspect -f '{{range $private, $bindings := .NetworkSettings.Ports}}{{if $bindings}}{{range $bindings}}{{println $private " " .HostPort}}{{end}}{{end}}{{end}}' "$CONTAINER" 2>/dev/null \
    | awk '
      $1 ~ /\/udp$/ && $2 ~ /^[0-9]+$/ {
        print $2
        exit
      }
    '
}

# === 1. Container exists/running ===
if ! docker_cmd inspect "$CONTAINER" >/dev/null 2>&1; then
  log "CRITICAL: container not found: ${CONTAINER}"
  exit 2
fi

if ! docker_running; then
  critical_fail "container is not running"
  exit 0
fi

# === 2. Process exists ===
if ! docker_exec 'pgrep -x amneziawg-go >/dev/null || pgrep -x awg >/dev/null || pgrep -f "awg-quick|wg-quick|sleep infinity" >/dev/null' >/dev/null 2>&1; then
  critical_fail "amneziawg-go/awg process not found"
  exit 0
fi

# === 3. Interface exists ===
if ! docker_exec "ip link show ${WG_IFACE} >/dev/null 2>&1"; then
  critical_fail "interface ${WG_IFACE} not found"
  exit 0
fi

# === 4. awg/wg show works ===
if ! docker_exec "awg show ${WG_IFACE} >/dev/null 2>&1 || wg show ${WG_IFACE} >/dev/null 2>&1"; then
  critical_fail "awg/wg show ${WG_IFACE} failed"
  exit 0
fi

# === 5. UDP port visible ===
UDP_VISIBLE="0"

if [ "$UDP_PORT" = "auto" ] || ! is_uint "$UDP_PORT"; then
  DETECTED_UDP_PORT="$(detect_udp_port || true)"
  if is_uint "$DETECTED_UDP_PORT"; then
    UDP_PORT="$DETECTED_UDP_PORT"
  else
    warn "failed to auto-detect UDP port from docker port output"
  fi
fi

if is_uint "$UDP_PORT"; then
  if ss -H -lunp 2>/dev/null | awk -v port=":${UDP_PORT}" '$0 ~ port {found=1} END {exit found ? 0 : 1}'; then
    UDP_VISIBLE="1"
  fi

  if [ "$UDP_VISIBLE" != "1" ]; then
    if docker_cmd port "$CONTAINER" 2>/dev/null | grep -qE "0\.0\.0\.0:${UDP_PORT}|:::${UDP_PORT}|:${UDP_PORT}$"; then
      UDP_VISIBLE="1"
    fi
  fi
else
  critical_fail "UDP_PORT is not numeric and auto-detection failed: ${UDP_PORT}"
  exit 0
fi

if [ "$UDP_VISIBLE" != "1" ]; then
  critical_fail "UDP port ${UDP_PORT} is not visible in ss/docker port"
  exit 0
fi

# === 6. NAT exists ===
NAT_OK="0"

if docker_exec "iptables -t nat -S 2>/dev/null | grep -qE 'MASQUERADE|SNAT'"; then
  NAT_OK="1"
fi

if [ "$NAT_OK" != "1" ]; then
  if docker_exec "command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -qE 'masquerade|snat'"; then
    NAT_OK="1"
  fi
fi

if [ "$NAT_OK" != "1" ]; then
  critical_fail "NAT/MASQUERADE/SNAT rule not found inside container"
  exit 0
fi

# === 7. Basic route exists inside container ===
ROUTE_CHECK="$(docker_exec "ip route get 1.1.1.1 2>/dev/null" || true)"

if ! echo "$ROUTE_CHECK" | grep -q "dev "; then
  critical_fail "no route to internet inside container. route_get='${ROUTE_CHECK}'"
  exit 0
fi

# === 8. Handshake diagnostics only, no restart ===
NOW="$(date +%s)"

DUMP="$(
  docker_exec "awg show ${WG_IFACE} dump 2>/dev/null || wg show ${WG_IFACE} dump 2>/dev/null" 2>/dev/null || true
)"

PEERS_TOTAL="$(
  echo "$DUMP" | awk 'NR > 1 {count++} END {print count+0}'
)"

ACTIVE_PEERS="$(
  echo "$DUMP" | awk -v now="$NOW" -v win="$ACTIVE_HANDSHAKE_WINDOW" '
    NR > 1 && $5 ~ /^[0-9]+$/ && $5 > 0 && (now - $5) <= win {count++}
    END {print count+0}
  '
)"

NEWEST_HANDSHAKE_AGE="$(
  echo "$DUMP" | awk -v now="$NOW" '
    NR > 1 && $5 ~ /^[0-9]+$/ && $5 > 0 {
      age = now - $5
      if (min == "" || age < min) min = age
    }
    END {
      if (min == "") print "none"; else print min
    }
  '
)"

# Если много клиентов, отсутствие свежего handshake не критично.
# Это только warning.
if [ "$PEERS_TOTAL" -gt 0 ] && [ "$ACTIVE_PEERS" -eq 0 ]; then
  warn "no peers with handshake in last ${ACTIVE_HANDSHAKE_WINDOW}s. peers_total=${PEERS_TOTAL}, newest_handshake_age=${NEWEST_HANDSHAKE_AGE}"
fi

# === 9. UDP conntrack diagnostics only ===
CONNTRACK_COUNT="unknown"

if command -v conntrack >/dev/null 2>&1; then
  CONNTRACK_COUNT="$(timeout --kill-after=3s "${CHECK_TIMEOUT}s" conntrack -L -p udp 2>/dev/null | grep -c ":${UDP_PORT}" || true)"
fi

# === OK ===
log "OK: process=alive iface=${WG_IFACE} udp_port=${UDP_PORT} nat=ok route=ok peers_total=${PEERS_TOTAL} active_peers_${ACTIVE_HANDSHAKE_WINDOW}s=${ACTIVE_PEERS} newest_handshake_age=${NEWEST_HANDSHAKE_AGE}s conntrack_udp_records=${CONNTRACK_COUNT}"

reset_fail_count
exit 0
