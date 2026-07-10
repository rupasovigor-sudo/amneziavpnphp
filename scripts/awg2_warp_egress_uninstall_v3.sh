#!/bin/bash
set +e

# AWG2 Cloudflare WARP egress uninstaller v3 (stored in protocols.uninstall_script).
# Tears down the systemd units, the netns/routing runtime, and local state.

BIN=/usr/local/sbin/awg2-warp-egress
STATE_DIR=/var/lib/cloudflare-warp/awg2-egress

systemctl stop awg2-warp-egress-health.timer 2>/dev/null
systemctl disable awg2-warp-egress-health.timer 2>/dev/null
systemctl stop awg2-warp-egress.service 2>/dev/null
systemctl disable awg2-warp-egress.service 2>/dev/null
systemctl reset-failed awg2-warp-egress.service 2>/dev/null

# Runtime teardown (netns, veth, mangle chain, policy routing).
if [ -x "$BIN" ]; then
  "$BIN" cleanup 2>/dev/null
fi

# Belt-and-suspenders removal in case the engine binary is already gone.
NS=awg2warp; VETH=awg2warp0; TABLE=51888; MARK=0x2cf2; CHAIN=AWG2_WARP_EGRESS
for ip in $(cat "$STATE_DIR/container_ips" 2>/dev/null); do
  while iptables -t mangle -D PREROUTING -s "$ip/32" -j "$CHAIN" 2>/dev/null; do :; done
done
while iptables -D FORWARD -i "$VETH" -o eth0 -j ACCEPT 2>/dev/null; do :; done
while iptables -D FORWARD -i eth0 -o "$VETH" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s 10.255.0.0/30 -o eth0 -j MASQUERADE 2>/dev/null; do :; done
iptables -t mangle -F "$CHAIN" 2>/dev/null
iptables -t mangle -X "$CHAIN" 2>/dev/null
while ip rule del fwmark "$MARK" table "$TABLE" 2>/dev/null; do :; done
ip route flush table "$TABLE" 2>/dev/null
ip link del "$VETH" 2>/dev/null
ip netns del "$NS" 2>/dev/null

rm -f /etc/systemd/system/awg2-warp-egress.service \
      /etc/systemd/system/awg2-warp-egress-health.service \
      /etc/systemd/system/awg2-warp-egress-health.timer
systemctl daemon-reload 2>/dev/null

rm -f "$BIN" /etc/wireguard/awg2-warp-egress.setconf
rm -rf "/etc/netns/$NS" "$STATE_DIR"

echo "WARP_UNINSTALL_DONE"
