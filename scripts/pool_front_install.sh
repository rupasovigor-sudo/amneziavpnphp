#!/bin/bash
# =====================================================================
# Pool front (entry relay) installer — idempotent.
# =====================================================================
# Turns a plain Ubuntu host into a transparent UDP relay for a failover pool:
# clients connect here, nftables DNATs their UDP to the pool members (which
# share one awg2 identity) and masquerades the return path. No tunnel is
# terminated here, so no keys live on this host.
#
# The backend list itself is NOT written by this script — the panel pushes
# /etc/amnezia/relay.nft (PoolFront::push) whenever pool health changes. This
# only prepares the host: forwarding, conntrack tool (to drop flows pinned to a
# removed backend), nftables, and a unit that restores the last ruleset on boot.
# =====================================================================
set -u

log() { echo "front: $*"; }

# 1. Forwarding (persisted). Load conntrack first so its sysctl key exists.
modprobe nf_conntrack 2>/dev/null || true
cat > /etc/sysctl.d/99-amnezia-relay.conf <<'SYSEOF'
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_udp_timeout_stream = 180
SYSEOF
sysctl -p /etc/sysctl.d/99-amnezia-relay.conf >/dev/null 2>&1 || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
log "ip_forward=$(sysctl -n net.ipv4.ip_forward)"

# 2. Packages: nftables (usually present) + conntrack. apt waits for the dpkg
#    lock itself (unattended-upgrades right after boot) instead of failing.
need=""
command -v nft >/dev/null 2>&1 || need="$need nftables"
command -v conntrack >/dev/null 2>&1 || need="$need conntrack"
if [ -n "$need" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=180 update -qq >/dev/null 2>&1 || true
    apt-get -o DPkg::Lock::Timeout=180 install -y -qq $need >/dev/null 2>&1 || log "package install failed:$need (continuing)"
fi
log "nft=$(command -v nft >/dev/null 2>&1 && echo yes || echo no) conntrack=$(command -v conntrack >/dev/null 2>&1 && echo yes || echo no)"

# 3. Placeholder ruleset only if none exists yet (keep a previously pushed one).
mkdir -p /etc/amnezia
if [ ! -s /etc/amnezia/relay.nft ]; then
    cat > /etc/amnezia/relay.nft <<'NFTEOF'
add table ip amnezia_relay
delete table ip amnezia_relay
table ip amnezia_relay {
}
NFTEOF
fi

# 4. Restore the last pushed ruleset on boot.
cat > /etc/systemd/system/amnezia-relay.service <<'UNITEOF'
[Unit]
Description=Amnezia pool relay (UDP -> pool members)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/amnezia/relay.nft
ExecStop=/usr/sbin/nft delete table ip amnezia_relay
[Install]
WantedBy=multi-user.target
UNITEOF
systemctl daemon-reload
systemctl enable amnezia-relay.service >/dev/null 2>&1
# Load through the unit so it also reports "active"; the ruleset file begins
# with add+delete table, so reloading is idempotent.
if ! systemctl restart amnezia-relay.service; then
    nft -c -f /etc/amnezia/relay.nft 2>&1 | head -5
    echo "FRONT_FAIL: relay ruleset did not load"
    exit 1
fi

# A FORWARD DROP policy (ufw, docker) silently eats relayed packets.
if command -v iptables >/dev/null 2>&1 && iptables -S FORWARD 2>/dev/null | grep -q '^-P FORWARD DROP'; then
    echo "FRONT_FAIL: iptables FORWARD policy is DROP (ufw/docker?) - relay would forward nothing"
    exit 1
fi

if [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ] && nft list table ip amnezia_relay >/dev/null 2>&1; then
    echo "FRONT_OK"
else
    echo "FRONT_FAIL: ip_forward off or relay table missing"
    exit 1
fi
