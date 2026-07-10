#!/bin/bash
set -euo pipefail

# AWG2 Cloudflare WARP egress runtime v3.
#
# Difference from v2: instead of a single wgcf-generated profile, this manages a
# POOL of WARP profiles registered directly against the official WARP API (no
# wgcf binary), and ROTATES the active profile on health failure / HTTP 429 /
# a traffic threshold — to dodge per-device rate limits and blocks.
#
# The netns + veth + policy-routing plumbing (namespace awg2warp, table 51888,
# mark 0x2cf2, MTU 1280, per-netns resolv.conf) is preserved from v2: it is the
# validated path that actually carries WARP traffic.

CONTAINER_NAME="${SERVER_CONTAINER:-amnezia-awg2}"
HOST_CONFIG_DIR="${AWG2_HOST_CONFIG_DIR:-/opt/amnezia/awg2}"
CONFIG_FILE="${AWG2_CONFIG_FILE:-awg0.conf}"
STATE_DIR="/var/lib/cloudflare-warp/awg2-egress"
PROFILE_DIR="$STATE_DIR/profiles"
# wg setconf/syncconf reads are confined by AppArmor to /etc/wireguard, so the
# live setconf for the active profile must live there (not under STATE_DIR).
SETCONF_FILE="/etc/wireguard/awg2-warp-egress.setconf"
NS="${WARP_NS:-awg2warp}"
VETH_HOST="${WARP_VETH_HOST:-awg2warp0}"
VETH_NS="${WARP_VETH_NS:-awg2warp1}"
HOST_VETH_IP="${WARP_HOST_VETH_IP:-10.255.0.1}"
NS_VETH_IP="${WARP_NS_VETH_IP:-10.255.0.2}"
VETH_CIDR="${WARP_VETH_CIDR:-10.255.0.0/30}"
TABLE="${WARP_ROUTE_TABLE:-51888}"
MARK="${WARP_MARK:-0x2cf2}"
CHAIN="AWG2_WARP_EGRESS"
WG_IF="${WARP_WG_IF:-wgcf}"

POOL_SIZE="${WARP_POOL_SIZE:-5}"
# Rotate the active profile once this many bytes have egressed through it
# (default 5 GiB); 0 disables traffic-based rotation.
ROTATE_TRAFFIC_BYTES="${WARP_ROTATE_TRAFFIC_BYTES:-5368709120}"
WARP_API="https://api.cloudflareclient.com/v0a2158/reg"

# Cloudflare WARP endpoints to spread rotations across (host:port). WARP accepts
# the same anycast entry on several ports (2408/500/4500/1701); varying the port
# changes the flow 5-tuple. Keep only endpoints verified to complete a handshake
# from a typical server — 162.159.193.x / 188.114.x did not respond in testing.
WARP_ENDPOINTS=(
  "engage.cloudflareclient.com:2408"
  "162.159.192.1:2408"
  "162.159.192.1:500"
  "162.159.192.1:4500"
  "162.159.192.1:1701"
)

export DEBIAN_FRONTEND=noninteractive

log() { echo "[$(date -Is)] $*"; }

# Count registered profiles without tripping set -e on an unmatched glob.
count_profiles() {
  find "$PROFILE_DIR" -mindepth 2 -maxdepth 2 -name profile.setconf 2>/dev/null | wc -l | tr -d ' '
}

# List profile slot names (e.g. 01 02 ...), sorted, safe under set -e.
list_slots() {
  find "$PROFILE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null -printf '%f\n' | sort
}

need_awg2_container() {
  if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    log "ERROR: AWG2 container not found: $CONTAINER_NAME"
    exit 1
  fi
}

install_packages() {
  command -v wg >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 && return 0
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates iproute2 iptables wireguard-tools python3 >/dev/null 2>&1
}

container_ips() {
  docker exec "$CONTAINER_NAME" hostname -i 2>/dev/null \
    | tr ' ' '\n' \
    | grep -E '^[0-9]+(\.[0-9]+){3}$' \
    | sort -u || true
}

# ---------------------------------------------------------------------------
# WARP profile pool — native registration (no wgcf)
# ---------------------------------------------------------------------------

# Ensure the pool has POOL_SIZE profiles; register the missing ones with backoff.
register_pool() {
  mkdir -p "$PROFILE_DIR"
  local have i out priv rest peer endpoint v4 cid slot backoff
  have="$(count_profiles)"
  log "WARP pool: have $have / $POOL_SIZE profiles"
  backoff=2
  for i in $(seq 1 "$POOL_SIZE"); do
    slot="$(printf '%02d' "$i")"
    [ -s "$PROFILE_DIR/$slot/profile.setconf" ] && continue
    local attempt ok=0
    for attempt in 1 2 3; do
      priv="$(wg genkey)"
      out="$(register_slot "$priv" 2>/dev/null || true)"
      if [ -n "$out" ]; then
        read -r peer endpoint v4 cid <<<"$out"
        if [ -n "$peer" ] && [ -n "$endpoint" ] && [ -n "$v4" ]; then
          mkdir -p "$PROFILE_DIR/$slot"
          # setconf-ready (no Address/DNS/MTU — those go on the interface)
          {
            echo "[Interface]"
            echo "PrivateKey = $priv"
            echo "[Peer]"
            echo "PublicKey = $peer"
            echo "AllowedIPs = 0.0.0.0/0, ::/0"
            echo "Endpoint = ${endpoint}"
          } > "$PROFILE_DIR/$slot/profile.setconf"
          {
            echo "client_v4=$v4"
            echo "client_id=$cid"
            echo "endpoint_host=$endpoint"
            echo "registered_at=$(date -Is)"
          } > "$PROFILE_DIR/$slot/meta"
          log "WARP pool: registered slot $slot (v4=$v4, endpoint=$endpoint)"
          ok=1
          break
        fi
      fi
      log "WARP pool: slot $slot attempt $attempt failed, backoff ${backoff}s"
      sleep "$backoff"
      backoff=$((backoff * 2))
    done
    [ "$ok" = "1" ] || log "WARP pool: slot $slot could not be registered (will retry next run)"
  done
  # Establish an active profile if none set.
  if [ ! -s "$STATE_DIR/active" ]; then
    local first
    first="$(list_slots | head -1)"
    [ -n "$first" ] && echo "$first" > "$STATE_DIR/active"
  fi
}

# Register one device using an externally-supplied private key; print
# "<peer> <endpoint_host> <v4> <client_id>".
register_slot() {
  local priv="$1" pub
  pub="$(printf '%s' "$priv" | wg pubkey)"
  WARP_PUB="$pub" python3 - "$WARP_API" <<'PY'
import json, os, sys, urllib.request, base64, secrets, datetime
api = sys.argv[1]; pub = os.environ["WARP_PUB"]
install_id = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")[:22]
body = {"key": pub, "install_id": install_id,
        "fcm_token": install_id + ":APA91b" + secrets.token_hex(67)[:134],
        "tos": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "model": "PC", "type": "Android", "locale": "en_US"}
req = urllib.request.Request(api, data=json.dumps(body).encode(), headers={
    "Content-Type": "application/json; charset=UTF-8",
    "User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.30-2158"}, method="POST")
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.load(r)
except Exception as e:
    sys.stderr.write("register failed: %s\n" % e); sys.exit(3)
c = data["config"]
print("%s %s %s %s" % (c["peers"][0]["public_key"], c["peers"][0]["endpoint"]["host"],
                       c["interface"]["addresses"]["v4"], c.get("client_id", "")))
PY
}

active_slot() {
  cat "$STATE_DIR/active" 2>/dev/null | tr -d '[:space:]'
}

active_profile_setconf() {
  local slot; slot="$(active_slot)"
  echo "$PROFILE_DIR/$slot/profile.setconf"
}

# Endpoint (ip:port) for the active profile, pinning the hostname to an IP and
# optionally overriding the endpoint host from the rotation endpoint list.
resolve_active_endpoint() {
  local slot endpoint host port ip idx
  slot="$(active_slot)"
  # Choose an endpoint from the rotation list, keyed by slot number, so
  # different profiles prefer different anycast entry IPs.
  idx=$(( (10#${slot:-1} - 1) % ${#WARP_ENDPOINTS[@]} ))
  endpoint="${WARP_ENDPOINTS[$idx]}"
  host="${endpoint%:*}"; port="${endpoint##*:}"
  ip="$host"
  if ! echo "$host" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
    ip="$(getent ahostsv4 "$host" | awk '{print $1; exit}')"
  fi
  [ -n "$ip" ] || { log "ERROR: cannot resolve endpoint $endpoint"; return 1; }
  echo "$ip:$port"
}

# ---------------------------------------------------------------------------
# netns + routing plumbing (preserved from v2)
# ---------------------------------------------------------------------------

cleanup_runtime() {
  set +e
  local ips ip
  ips="$(cat "$STATE_DIR/container_ips" 2>/dev/null || container_ips)"
  for ip in $ips; do
    while iptables -t mangle -D PREROUTING -s "$ip/32" -j "$CHAIN" 2>/dev/null; do :; done
  done
  while iptables -D FORWARD -i "$VETH_HOST" -o eth0 -j ACCEPT 2>/dev/null; do :; done
  while iptables -D FORWARD -i eth0 -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
  while iptables -t nat -D POSTROUTING -s "$VETH_CIDR" -o eth0 -j MASQUERADE 2>/dev/null; do :; done
  iptables -t mangle -F "$CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$CHAIN" 2>/dev/null || true
  while ip rule del fwmark "$MARK" table "$TABLE" 2>/dev/null; do :; done
  ip route flush table "$TABLE" 2>/dev/null || true
  ip link del "$VETH_HOST" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  set -e
}

detect_vpn_port() {
  local port
  port="$(grep -E '^[[:space:]]*ListenPort[[:space:]]*=' "$HOST_CONFIG_DIR/$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]' || true)"
  if [ -z "$port" ]; then
    port="$(docker exec "$CONTAINER_NAME" sh -c "grep -E '^[[:space:]]*ListenPort[[:space:]]*=' /opt/amnezia/awg/$CONFIG_FILE 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]'" || true)"
  fi
  if [ -z "$port" ]; then
    port="$(docker port "$CONTAINER_NAME" 2>/dev/null | awk '/\/udp/ { sub(/.*:/,"",$NF); print $NF; exit }')"
  fi
  echo "${port:-0}"
}

# Read a field (PrivateKey / PublicKey) from the active profile.
profile_field() {
  grep -E "^$1[[:space:]]*=" "$(active_profile_setconf)" 2>/dev/null | head -1 | sed -E 's/^[^=]*=[[:space:]]*//'
}

# Bring the active profile up as a WireGuard interface and move it into the
# namespace. The interface is created (and its UDP socket bound) in the ROOT
# netns, so the outer WARP packets egress via the host's normal default route —
# validated as the path that actually carries traffic. Configured inline with
# `wg set` (not `wg setconf`) to avoid the AppArmor confinement on config files
# and to keep the private key off disk.
wg_bring_up_active() {
  local endpoint priv peer
  endpoint="$(resolve_active_endpoint)" || return 1
  priv="$(profile_field PrivateKey)"
  peer="$(profile_field PublicKey)"
  [ -n "$priv" ] && [ -n "$peer" ] || { log "ERROR: active profile missing keys"; return 1; }
  ip -n "$NS" link del "$WG_IF" 2>/dev/null || true
  ip link del "$WG_IF" 2>/dev/null || true
  ip link add "$WG_IF" type wireguard
  wg set "$WG_IF" private-key <(printf '%s' "$priv") peer "$peer" \
    endpoint "$endpoint" allowed-ips 0.0.0.0/0,::/0 persistent-keepalive 25
  ip link set "$WG_IF" netns "$NS"
  ip netns exec "$NS" ip addr add 172.16.0.2/32 dev "$WG_IF" 2>/dev/null || true
  ip netns exec "$NS" ip link set mtu 1280 dev "$WG_IF"
  ip netns exec "$NS" ip link set "$WG_IF" up
  ip netns exec "$NS" ip route replace default dev "$WG_IF"
  echo "$endpoint" > "$STATE_DIR/endpoint"
}

setup_warp_namespace() {
  ip netns add "$NS"
  mkdir -p "/etc/netns/$NS"
  { echo "nameserver 1.1.1.1"; echo "nameserver 1.0.0.1"; } > "/etc/netns/$NS/resolv.conf"

  ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
  ip addr add "$HOST_VETH_IP/30" dev "$VETH_HOST"
  ip link set "$VETH_HOST" up
  ip link set "$VETH_NS" netns "$NS"
  ip netns exec "$NS" ip addr add "$NS_VETH_IP/30" dev "$VETH_NS"
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip link set "$VETH_NS" up

  wg_bring_up_active || return 1

  ip netns exec "$NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec "$NS" iptables -t nat -F POSTROUTING
  ip netns exec "$NS" iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE

  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w "net.ipv4.conf.$VETH_HOST.rp_filter=0" >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
  iptables -C FORWARD -i "$VETH_HOST" -o eth0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$VETH_HOST" -o eth0 -j ACCEPT
  iptables -C FORWARD -i eth0 -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i eth0 -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -t nat -C POSTROUTING -s "$VETH_CIDR" -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$VETH_CIDR" -o eth0 -j MASQUERADE
}

warp_trace() {
  ip netns exec "$NS" curl -4 -s --max-time 8 \
    --resolve cloudflare.com:443:104.16.132.229 \
    https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true
}

wait_for_warp() {
  local trace i
  : > "$STATE_DIR/last_trace"
  for i in $(seq 1 8); do
    trace="$(warp_trace)"
    printf '%s\n' "$trace" > "$STATE_DIR/last_trace"
    echo "$trace" | grep -q '^warp=on$' && return 0
    sleep 3
  done
  return 1
}

install_client_routing() {
  local ips="$1" vpn_port="$2" ip net
  iptables -t mangle -N "$CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$CHAIN"
  for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t mangle -A "$CHAIN" -d "$net" -j RETURN
  done
  [ "$vpn_port" != "0" ] && iptables -t mangle -A "$CHAIN" -p udp --sport "$vpn_port" -j RETURN
  iptables -t mangle -A "$CHAIN" -j MARK --set-mark "$MARK"
  for ip in $ips; do
    iptables -t mangle -C PREROUTING -s "$ip/32" -j "$CHAIN" 2>/dev/null || \
      iptables -t mangle -A PREROUTING -s "$ip/32" -j "$CHAIN"
  done
  ip rule show | grep -q "fwmark ${MARK}.*lookup ${TABLE}" || \
    ip rule add fwmark "$MARK" table "$TABLE" priority 11888
  ip route replace default via "$NS_VETH_IP" dev "$VETH_HOST" table "$TABLE"
  printf '%s\n' $ips > "$STATE_DIR/container_ips"
  echo "$vpn_port" > "$STATE_DIR/vpn_port"
}

# Current cumulative tx bytes on the active WARP interface.
warp_tx_bytes() {
  ip netns exec "$NS" cat "/sys/class/net/$WG_IF/statistics/tx_bytes" 2>/dev/null || echo 0
}

print_variables() {
  local ips="$1" vpn_port="$2" trace warp_ip warp_on slot rotations
  trace="$(cat "$STATE_DIR/last_trace" 2>/dev/null || true)"
  warp_ip="$(echo "$trace" | awk -F= '$1=="ip"{print $2; exit}')"
  warp_on="$(echo "$trace" | awk -F= '$1=="warp"{print $2; exit}')"
  slot="$(active_slot)"
  rotations="$(cat "$STATE_DIR/rotation_count" 2>/dev/null || echo 0)"
  echo "Variable: warp_mode=wireguard_netns_pool_rotating"
  echo "Variable: routing_scope=awg2_client_egress_tcp_udp"
  echo "Variable: awg2_container=$CONTAINER_NAME"
  echo "Variable: awg2_container_ips=$(echo "$ips" | tr '\n' ' ')"
  echo "Variable: awg2_vpn_port=$vpn_port"
  echo "Variable: warp_namespace=$NS"
  echo "Variable: warp_pool_size=$(count_profiles)"
  echo "Variable: warp_active_profile=$slot"
  echo "Variable: warp_rotations=$rotations"
  echo "Variable: warp_ip=${warp_ip:-unknown}"
  echo "Variable: warp_status=${warp_on:-unknown}"
}

# ---------------------------------------------------------------------------
# Bring the active profile up inside the (already-created) namespace.
# ---------------------------------------------------------------------------
bring_up_active() {
  setup_warp_namespace
}

start_egress() {
  local ips vpn_port
  need_awg2_container
  mkdir -p "$STATE_DIR" "$PROFILE_DIR"
  cleanup_runtime
  install_packages
  register_pool

  [ -s "$(active_profile_setconf)" ] || { log "ERROR: no active WARP profile after registration"; exit 21; }

  ips="$(container_ips)"
  [ -z "$ips" ] && { log "ERROR: no Docker IP for $CONTAINER_NAME"; exit 1; }
  vpn_port="$(detect_vpn_port)"

  bring_up_active || { log "ERROR: failed to bring up active WARP profile"; cleanup_runtime; exit 22; }

  if ! wait_for_warp; then
    log "WARP unhealthy on active profile $(active_slot); trying rotation"
    if ! rotate_profile "startup_unhealthy" || ! wait_for_warp; then
      log "ERROR: WARP did not become healthy after rotation; egress not routed"
      cleanup_runtime
      exit 20
    fi
  fi

  install_client_routing "$ips" "$vpn_port"
  echo "$(warp_tx_bytes)" > "$STATE_DIR/traffic_baseline"
  print_variables "$ips" "$vpn_port"
}

# ---------------------------------------------------------------------------
# Rotation: switch the live WARP interface to the next profile without tearing
# down the namespace, veth or client routing. Cheap and non-disruptive.
# ---------------------------------------------------------------------------
next_slot() {
  local cur slots n idx
  cur="$(active_slot)"
  mapfile -t slots < <(list_slots)
  n="${#slots[@]}"
  [ "$n" -eq 0 ] && { echo ""; return; }
  idx=0
  for i in "${!slots[@]}"; do [ "${slots[$i]}" = "$cur" ] && idx="$i"; done
  echo "${slots[$(( (idx + 1) % n ))]}"
}

rotate_profile() {
  local reason="${1:-manual}" nxt endpoint
  nxt="$(next_slot)"
  [ -z "$nxt" ] && { log "rotate: no profiles to rotate to"; return 1; }
  echo "$nxt" > "$STATE_DIR/active"

  # Re-create the WARP interface with the next profile. The namespace, veth and
  # client policy-routing stay in place, so only the tunnel identity changes.
  if ip netns list 2>/dev/null | grep -qw "$NS"; then
    wg_bring_up_active || return 1
  else
    bring_up_active || return 1
  fi
  endpoint="$(cat "$STATE_DIR/endpoint" 2>/dev/null || true)"

  echo "$(warp_tx_bytes)" > "$STATE_DIR/traffic_baseline"
  local cnt; cnt="$(cat "$STATE_DIR/rotation_count" 2>/dev/null || echo 0)"; echo "$((cnt + 1))" > "$STATE_DIR/rotation_count"
  echo "[$(date -Is)] rotate -> $nxt endpoint=$endpoint reason=$reason" >> "$STATE_DIR/rotations.log"
  log "rotated to profile $nxt (endpoint=$endpoint, reason=$reason)"
}

# Health probe used by the systemd timer: rotate on WARP-down / 429 / traffic cap.
health_check() {
  [ -d "/var/run/netns" ] && ip netns list 2>/dev/null | grep -qw "$NS" || { log "health: namespace missing, starting"; start_egress; return; }
  local trace warp_on http429 baseline now used
  trace="$(warp_trace)"
  printf '%s\n' "$trace" > "$STATE_DIR/last_trace"
  warp_on="$(echo "$trace" | awk -F= '$1=="warp"{print $2; exit}')"

  # HTTP 429 probe (rate-limited exit) — a real request through the tunnel.
  http429="$(ip netns exec "$NS" curl -4 -s -o /dev/null -w '%{http_code}' --max-time 8 https://www.gstatic.com/generate_204 2>/dev/null || echo 000)"

  if [ "$warp_on" != "on" ] || [ "$http429" = "429" ]; then
    log "health: unhealthy (warp=$warp_on http=$http429) -> rotate"
    rotate_profile "health_warp=${warp_on}_http=${http429}"
    wait_for_warp || log "health: still unhealthy after rotation"
    return
  fi

  # Traffic-threshold rotation.
  if [ "$ROTATE_TRAFFIC_BYTES" != "0" ]; then
    baseline="$(cat "$STATE_DIR/traffic_baseline" 2>/dev/null || echo 0)"
    now="$(warp_tx_bytes)"
    used=$(( now - baseline ))
    [ "$used" -lt 0 ] && used="$now"
    if [ "$used" -ge "$ROTATE_TRAFFIC_BYTES" ]; then
      log "health: traffic cap reached (${used} bytes) -> rotate"
      rotate_profile "traffic_${used}_bytes"
      wait_for_warp || log "health: unhealthy after traffic rotation"
    fi
  fi
}

status_egress() {
  systemctl is-active awg2-warp-egress.service 2>/dev/null || true
  systemctl is-enabled awg2-warp-egress.service 2>/dev/null || true
  ip netns exec "$NS" wg show "$WG_IF" 2>/dev/null || true
  cat "$STATE_DIR/last_trace" 2>/dev/null || true
  echo "active=$(active_slot) pool=$(count_profiles) rotations=$(cat "$STATE_DIR/rotation_count" 2>/dev/null || echo 0)"
  iptables -t mangle -S "$CHAIN" 2>/dev/null || true
  ip rule show | grep "$TABLE" || true
}

case "${1:-start}" in
  start)    start_egress ;;
  stop)     cleanup_runtime ;;
  rotate)   rotate_profile "${2:-manual}" ;;
  health)   health_check ;;
  register) mkdir -p "$STATE_DIR" "$PROFILE_DIR"; install_packages; register_pool ;;
  status)   status_egress ;;
  cleanup)  cleanup_runtime ;;
  *) echo "Usage: $0 {start|stop|rotate [reason]|health|register|status|cleanup}"; exit 2 ;;
esac
