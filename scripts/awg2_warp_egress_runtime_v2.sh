#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${SERVER_CONTAINER:-amnezia-awg2}"
HOST_CONFIG_DIR="${AWG2_HOST_CONFIG_DIR:-/opt/amnezia/awg2}"
CONFIG_FILE="${AWG2_CONFIG_FILE:-awg0.conf}"
STATE_DIR="/var/lib/cloudflare-warp/awg2-egress"
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
WGCF_BIN="/usr/local/bin/wgcf"

export DEBIAN_FRONTEND=noninteractive

log() {
  echo "[$(date -Is)] $*"
}

need_awg2_container() {
  if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    log "ERROR: AWG2 container not found: $CONTAINER_NAME"
    exit 1
  fi
}

install_packages() {
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates iproute2 iptables wireguard-tools resolvconf >/dev/null 2>&1 || \
    apt-get install -y -qq curl ca-certificates iproute2 iptables wireguard-tools >/dev/null 2>&1
}

install_wgcf() {
  if command -v wgcf >/dev/null 2>&1; then
    return 0
  fi

  local arch url api_json
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) log "ERROR: unsupported architecture for wgcf: $arch"; exit 1 ;;
  esac

  api_json="$(mktemp)"
  curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest -o "$api_json"
  url="$(awk -F'"' -v suffix="_linux_$arch" '$2 == "browser_download_url" && $4 ~ suffix "$" { print $4; exit }' "$api_json")"
  rm -f "$api_json"
  if [ -z "$url" ]; then
    log "ERROR: failed to find wgcf linux_$arch release"
    exit 1
  fi

  curl -fsSL "$url" -o "$WGCF_BIN"
  chmod +x "$WGCF_BIN"
}

container_ips() {
  docker exec "$CONTAINER_NAME" hostname -i 2>/dev/null \
    | tr ' ' '\n' \
    | grep -E '^[0-9]+(\.[0-9]+){3}$' \
    | sort -u || true
}

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

prepare_warp_profile() {
  install_wgcf
  mkdir -p "$STATE_DIR" /etc/wireguard
  cd "$STATE_DIR"

  if [ ! -s wgcf-account.toml ] || [ ! -s wgcf-profile.conf ]; then
    rm -f wgcf-account.toml wgcf-profile.conf
    "$WGCF_BIN" register --accept-tos
    "$WGCF_BIN" generate
  fi

  cp -f "$STATE_DIR/wgcf-profile.conf" /etc/wireguard/awg2-warp-egress.conf
}

resolve_endpoint_ip() {
  local endpoint host port ip
  endpoint="$(awk -F= '/^[[:space:]]*Endpoint[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/wireguard/awg2-warp-egress.conf)"
  host="${endpoint%:*}"
  port="${endpoint##*:}"
  ip="$host"
  if ! echo "$host" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
    ip="$(getent ahostsv4 "$host" | awk '{print $1; exit}')"
  fi
  if [ -z "$ip" ]; then
    log "ERROR: failed to resolve WARP endpoint: $endpoint"
    exit 1
  fi
  echo "$ip:$port" > "$STATE_DIR/endpoint"
  echo "$ip"
}

write_wg_setconf() {
  local endpoint
  endpoint="$(cat "$STATE_DIR/endpoint")"
  awk -v endpoint="$endpoint" '
    /^[[:space:]]*(Address|DNS|MTU)[[:space:]]*=/ { next }
    /^[[:space:]]*Endpoint[[:space:]]*=/ { print "Endpoint = " endpoint; next }
    { print }
  ' /etc/wireguard/awg2-warp-egress.conf > "$STATE_DIR/wgcf.setconf"
}

setup_warp_namespace() {
  local endpoint_ip="$1"

  ip netns add "$NS"
  mkdir -p "/etc/netns/$NS"
  {
    echo "nameserver 1.1.1.1"
    echo "nameserver 1.0.0.1"
  } > "/etc/netns/$NS/resolv.conf"

  ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
  ip addr add "$HOST_VETH_IP/30" dev "$VETH_HOST"
  ip link set "$VETH_HOST" up
  ip link set "$VETH_NS" netns "$NS"
  ip netns exec "$NS" ip addr add "$NS_VETH_IP/30" dev "$VETH_NS"
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip link set "$VETH_NS" up

  ip netns exec "$NS" ip link add "$WG_IF" type wireguard
  ip netns exec "$NS" wg setconf "$WG_IF" "$STATE_DIR/wgcf.setconf"
  ip netns exec "$NS" ip addr add 172.16.0.2/32 dev "$WG_IF" 2>/dev/null || true
  ip netns exec "$NS" ip link set mtu 1280 dev "$WG_IF"
  ip netns exec "$NS" ip link set "$WG_IF" up
  ip netns exec "$NS" ip route add "$endpoint_ip/32" via "$HOST_VETH_IP" dev "$VETH_NS"
  ip netns exec "$NS" ip route add 172.17.0.0/16 via "$HOST_VETH_IP" dev "$VETH_NS" 2>/dev/null || true
  ip netns exec "$NS" ip route add default dev "$WG_IF"
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
    if echo "$trace" | grep -q '^warp=on$'; then
      return 0
    fi
    sleep 3
  done
  return 1
}

install_client_routing() {
  local ips="$1"
  local vpn_port="$2"
  local ip net

  iptables -t mangle -N "$CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$CHAIN"
  for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t mangle -A "$CHAIN" -d "$net" -j RETURN
  done
  if [ "$vpn_port" != "0" ]; then
    iptables -t mangle -A "$CHAIN" -p udp --sport "$vpn_port" -j RETURN
  fi
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
  echo "$TABLE" > "$STATE_DIR/table"
  echo "$MARK" > "$STATE_DIR/mark"
}

print_variables() {
  local ips="$1"
  local vpn_port="$2"
  local trace warp_ip warp_on
  trace="$(cat "$STATE_DIR/last_trace" 2>/dev/null || true)"
  warp_ip="$(echo "$trace" | awk -F= '$1=="ip"{print $2; exit}')"
  warp_on="$(echo "$trace" | awk -F= '$1=="warp"{print $2; exit}')"

  echo "Variable: warp_mode=wireguard_netns_health_gated"
  echo "Variable: routing_scope=awg2_client_egress_tcp_udp"
  echo "Variable: awg2_container=$CONTAINER_NAME"
  echo "Variable: awg2_container_ips=$(echo "$ips" | tr '\n' ' ')"
  echo "Variable: awg2_vpn_port=$vpn_port"
  echo "Variable: warp_namespace=$NS"
  echo "Variable: warp_veth=$VETH_HOST/$VETH_NS"
  echo "Variable: warp_ip=${warp_ip:-unknown}"
  echo "Variable: warp_status=${warp_on:-unknown}"
  echo "Variable: routed_subnets=awg2-container-egress-except-vpn-handshake"
}

start_egress() {
  local ips vpn_port endpoint_ip

  need_awg2_container
  mkdir -p "$STATE_DIR" /etc/wireguard
  cleanup_runtime
  install_packages
  prepare_warp_profile

  ips="$(container_ips)"
  if [ -z "$ips" ]; then
    log "ERROR: no Docker IP found for $CONTAINER_NAME"
    exit 1
  fi

  vpn_port="$(detect_vpn_port)"
  endpoint_ip="$(resolve_endpoint_ip)"
  write_wg_setconf
  setup_warp_namespace "$endpoint_ip"

  if ! wait_for_warp; then
    log "ERROR: WARP did not become healthy; client egress was not routed"
    ip netns exec "$NS" wg show "$WG_IF" 2>/dev/null || true
    cleanup_runtime
    exit 20
  fi

  install_client_routing "$ips" "$vpn_port"
  print_variables "$ips" "$vpn_port"
}

status_egress() {
  systemctl is-active awg2-warp-egress.service 2>/dev/null || true
  systemctl is-enabled awg2-warp-egress.service 2>/dev/null || true
  ip netns exec "$NS" wg show "$WG_IF" 2>/dev/null || true
  cat "$STATE_DIR/last_trace" 2>/dev/null || true
  iptables -t mangle -S "$CHAIN" 2>/dev/null || true
  ip rule show | grep "$TABLE" || true
}

case "${1:-start}" in
  start)
    start_egress
    ;;
  stop)
    cleanup_runtime
    ;;
  status)
    status_egress
    ;;
  cleanup)
    cleanup_runtime
    ;;
  *)
    echo "Usage: $0 {start|stop|status|cleanup}"
    exit 2
    ;;
esac
