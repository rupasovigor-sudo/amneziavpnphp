#!/bin/bash
set -euo pipefail

STATE_DIR="/var/lib/cloudflare-warp/awg2-egress"
NS="${WARP_NS:-awg2warp}"
VETH_HOST="${WARP_VETH_HOST:-awg2warp0}"
VETH_CIDR="${WARP_VETH_CIDR:-10.255.0.0/30}"
TABLE="${WARP_ROUTE_TABLE:-51888}"
MARK="${WARP_MARK:-0x2cf2}"
CHAIN="AWG2_WARP_EGRESS"
OLD_TCP_CHAIN="AWG2_WARP_TCP"

echo "=== Removing Cloudflare WARP AWG2 client egress ==="

systemctl stop awg2-warp-egress-retry.timer 2>/dev/null || true
systemctl disable awg2-warp-egress-retry.timer 2>/dev/null || true
systemctl stop awg2-warp-egress.service 2>/dev/null || true
systemctl disable awg2-warp-egress.service 2>/dev/null || true

IPS="$(cat "$STATE_DIR/container_ips" 2>/dev/null || docker exec amnezia-awg2 hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' || true)"
for ip in $IPS; do
  while iptables -t mangle -D PREROUTING -s "$ip/32" -j "$CHAIN" 2>/dev/null; do :; done
  while iptables -t nat -D PREROUTING -s "$ip/32" -p tcp -j "$OLD_TCP_CHAIN" 2>/dev/null; do :; done
done

iptables -t mangle -F "$CHAIN" 2>/dev/null || true
iptables -t mangle -X "$CHAIN" 2>/dev/null || true
iptables -t nat -F "$OLD_TCP_CHAIN" 2>/dev/null || true
iptables -t nat -X "$OLD_TCP_CHAIN" 2>/dev/null || true

while iptables -D FORWARD -i "$VETH_HOST" -o eth0 -j ACCEPT 2>/dev/null; do :; done
while iptables -D FORWARD -i eth0 -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s "$VETH_CIDR" -o eth0 -j MASQUERADE 2>/dev/null; do :; done
while ip rule del fwmark "$MARK" table "$TABLE" 2>/dev/null; do :; done
ip route flush table "$TABLE" 2>/dev/null || true
ip link del "$VETH_HOST" 2>/dev/null || true
ip netns del "$NS" 2>/dev/null || true

systemctl stop redsocks-warp 2>/dev/null || true
systemctl disable redsocks-warp 2>/dev/null || true
systemctl stop redsocks 2>/dev/null || true
systemctl disable redsocks 2>/dev/null || true
killall redsocks 2>/dev/null || true
rm -f /etc/systemd/system/redsocks-warp.service
rm -rf /etc/redsocks

rm -f /etc/systemd/system/awg2-warp-egress.service
rm -f /etc/systemd/system/awg2-warp-egress-retry.timer
rm -f /usr/local/sbin/awg2-warp-egress
rm -rf "$STATE_DIR"
rm -rf "/etc/netns/$NS"
rm -f /etc/wireguard/awg2-warp-egress.conf
systemctl daemon-reload 2>/dev/null || true

echo '{"success":true,"message":"Cloudflare WARP AWG2 client egress removed"}'
