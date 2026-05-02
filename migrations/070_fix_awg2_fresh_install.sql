-- =====================================================================
-- Migration 070: Fix AmneziaWG 2.0 fresh install and non-empty I1-I5
-- =====================================================================

UPDATE protocols
SET
  install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${SERVER_CONTAINER:-amnezia-awg2}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
VPN_PORT="${SERVER_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}"
MTU=${MTU:-1280}
HOST_CONFIG_DIR="/opt/amnezia/awg2"
CONTAINER_CONFIG_DIR="/opt/amnezia/awg"
CONFIG_FILE="awg0.conf"

rand_between() {
  local min="$1"
  local max="$2"
  echo $((min + RANDOM % (max - min + 1)))
}

rand_u31() {
  echo $((((RANDOM << 16) | RANDOM) & 2147483647))
}

rand_h_range() {
  local start
  local finish
  start=$(rand_u31)
  if [ "$start" -lt 100000000 ]; then
    start=$((start + 100000000))
  fi
  if [ "$start" -gt 2146000000 ]; then
    start=$((start - 100000000))
  fi
  finish=$((start + $(rand_between 10000 900000)))
  if [ "$finish" -gt 2147483647 ]; then
    finish=2147483647
  fi
  echo "${start}-${finish}"
}

JC=${JC:-$(rand_between 4 12)}
JMIN=${JMIN:-$(rand_between 8 64)}
JMAX=${JMAX:-$(rand_between 80 512)}
if [ "$JMAX" -le "$JMIN" ]; then
  JMAX=$((JMIN + 32))
fi
S1_VAL=${S1_VAL:-$(rand_between 15 150)}
S2_VAL=${S2_VAL:-$(rand_between 15 150)}
if [ "$((S1_VAL + 56))" -eq "$S2_VAL" ]; then
  S2_VAL=$((S2_VAL + 1))
fi
S3_VAL=${S3_VAL:-$(rand_between 8 64)}
S4_VAL=${S4_VAL:-$(rand_between 8 64)}
H1_VAL=${H1_VAL:-$(rand_h_range)}
H2_VAL=${H2_VAL:-$(rand_h_range)}
H3_VAL=${H3_VAL:-$(rand_h_range)}
H4_VAL=${H4_VAL:-$(rand_h_range)}
while [ "$H2_VAL" = "$H1_VAL" ]; do H2_VAL=$(rand_h_range); done
while [ "$H3_VAL" = "$H1_VAL" ] || [ "$H3_VAL" = "$H2_VAL" ]; do H3_VAL=$(rand_h_range); done
while [ "$H4_VAL" = "$H1_VAL" ] || [ "$H4_VAL" = "$H2_VAL" ] || [ "$H4_VAL" = "$H3_VAL" ]; do H4_VAL=$(rand_h_range); done
I1_VAL=${I1_VAL:-"<r $(rand_between 2 6)><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"}
I2_VAL=${I2_VAL:-"<r $(rand_between 3 8)><b 0x16030100><r $(rand_between 48 96)>"}
I3_VAL=${I3_VAL:-"<r $(rand_between 6 12)><b 0x17030300><r $(rand_between 32 80)>"}
I4_VAL=${I4_VAL:-"<r $(rand_between 4 10)><b 0x00000001><r $(rand_between 24 64)>"}
I5_VAL=${I5_VAL:-"<r $(rand_between 8 14)><b 0x08000000><r $(rand_between 24 72)>"}

if ! command -v git >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq git curl ca-certificates >/dev/null 2>&1
fi

mkdir -p "$HOST_CONFIG_DIR"

if [ ! -d "$HOST_CONFIG_DIR/src/.git" ]; then
  rm -rf "$HOST_CONFIG_DIR/src"
  git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git "$HOST_CONFIG_DIR/src"
fi

docker build --no-cache -t amnezia-awg2 "$HOST_CONFIG_DIR/src"

EXISTING=$(docker ps -aq -f "name=^/${CONTAINER_NAME}$" 2>/dev/null | head -1 || true)

if [ -z "$EXISTING" ]; then
  docker run -d --name "$CONTAINER_NAME" --restart always --cap-add=NET_ADMIN --device /dev/net/tun -p "${VPN_PORT}:${VPN_PORT}/udp" -v "${HOST_CONFIG_DIR}:${CONTAINER_CONFIG_DIR}" amnezia-awg2 sh -c "while [ ! -f ${CONTAINER_CONFIG_DIR}/${CONFIG_FILE} ]; do sleep 1; done; WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up ${CONTAINER_CONFIG_DIR}/${CONFIG_FILE} && sleep infinity"
  sleep 2
else
  STATUS=$(docker inspect --format="{{.State.Status}}" "$CONTAINER_NAME" 2>/dev/null || echo "")
  if [ "$STATUS" != "running" ]; then
    docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
fi

if [ -f "${HOST_CONFIG_DIR}/${CONFIG_FILE}" ]; then
  PORT=$(grep -E "^ListenPort" "${HOST_CONFIG_DIR}/${CONFIG_FILE}" | cut -d= -f2 | tr -d "[:space:]" || true)
  PSK=$(cat "${HOST_CONFIG_DIR}/wireguard_psk.key" 2>/dev/null || true)
  PUBKEY=$(cat "${HOST_CONFIG_DIR}/wireguard_server_public_key.key" 2>/dev/null || true)

  if [ -z "${PUBKEY:-}" ]; then
    PRIVKEY=$(cat "${HOST_CONFIG_DIR}/wireguard_server_private_key.key" 2>/dev/null || true)
    if [ -n "$PRIVKEY" ]; then
      PUBKEY=$(echo "$PRIVKEY" | docker exec -i "$CONTAINER_NAME" awg pubkey)
      echo "$PUBKEY" > "${HOST_CONFIG_DIR}/wireguard_server_public_key.key"
    fi
  fi

  EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

  echo "Using existing AmneziaWG 2.0 configuration"
  echo "Port: ${PORT:-$VPN_PORT}"
  [ -n "${PUBKEY:-}" ] && echo "Server Public Key: $PUBKEY"
  [ -n "${PSK:-}" ] && echo "PresharedKey = $PSK"
  echo "Server Host: $EXTERNAL_IP"
  echo "Container Name: $CONTAINER_NAME"

  for P in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5; do
    VAL=$(grep -E "^$P[[:space:]]*=" "${HOST_CONFIG_DIR}/${CONFIG_FILE}" | cut -d= -f2- | sed "s/^[[:space:]]*//;s/[[:space:]]*$//" || true)
    if [ -n "$VAL" ]; then
      echo "Variable: $P=$VAL"
    fi
  done

  echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"
  exit 0
fi

PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" awg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" awg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" awg genpsk)

cat > "${HOST_CONFIG_DIR}/${CONFIG_FILE}" << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.1.1/24
ListenPort = $VPN_PORT
MTU = $MTU
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1_VAL
S2 = $S2_VAL
S3 = $S3_VAL
S4 = $S4_VAL
H1 = $H1_VAL
H2 = $H2_VAL
H3 = $H3_VAL
H4 = $H4_VAL
I1 = $I1_VAL
I2 = $I2_VAL
I3 = $I3_VAL
I4 = $I4_VAL
I5 = $I5_VAL
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

chmod 600 "${HOST_CONFIG_DIR}/${CONFIG_FILE}"
echo "$PRIVATE_KEY" > "${HOST_CONFIG_DIR}/wireguard_server_private_key.key"
echo "$PUBLIC_KEY" > "${HOST_CONFIG_DIR}/wireguard_server_public_key.key"
echo "$PRESHARED_KEY" > "${HOST_CONFIG_DIR}/wireguard_psk.key"
echo "[]" > "${HOST_CONFIG_DIR}/clientsTable"

docker restart "$CONTAINER_NAME" >/dev/null 2>&1 || true
sleep 2

EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

echo "AmneziaWG 2.0 installed successfully"
echo "Port: $VPN_PORT"
echo "Server Public Key: $PUBLIC_KEY"
echo "PresharedKey = $PRESHARED_KEY"
echo "Server Host: $EXTERNAL_IP"
echo "Container Name: $CONTAINER_NAME"
echo "Variable: Jc=$JC"
echo "Variable: Jmin=$JMIN"
echo "Variable: Jmax=$JMAX"
echo "Variable: S1=$S1_VAL"
echo "Variable: S2=$S2_VAL"
echo "Variable: S3=$S3_VAL"
echo "Variable: S4=$S4_VAL"
echo "Variable: H1=$H1_VAL"
echo "Variable: H2=$H2_VAL"
echo "Variable: H3=$H3_VAL"
echo "Variable: H4=$H4_VAL"
echo "Variable: I1=$I1_VAL"
echo "Variable: I2=$I2_VAL"
echo "Variable: I3=$I3_VAL"
echo "Variable: I4=$I4_VAL"
echo "Variable: I5=$I5_VAL"
echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"',
  output_template = '[Interface]
PrivateKey = {{private_key}}
Address = {{client_ip}}/32
DNS = {{dns_servers}}
MTU = 1280
Jc = {{Jc}}
Jmin = {{Jmin}}
Jmax = {{Jmax}}
S1 = {{S1}}
S2 = {{S2}}
S3 = {{S3}}
S4 = {{S4}}
H1 = {{H1}}
H2 = {{H2}}
H3 = {{H3}}
H4 = {{H4}}
I1 = {{I1}}
I2 = {{I2}}
I3 = {{I3}}
I4 = {{I4}}
I5 = {{I5}}

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{server_host}}:{{server_port}}
PersistentKeepalive = 25',
  definition = JSON_OBJECT(
    'engine', 'shell',
    'metadata', JSON_OBJECT(
      'container_name', 'amnezia-awg2',
      'vpn_subnet', '10.8.1.0/24',
      'port_range', JSON_ARRAY(30000, 65000),
      'config_dir', '/opt/amnezia/awg2',
      'config_file', 'awg0.conf',
      'interface', 'awg0'
    )
  ),
  updated_at = NOW()
WHERE slug = 'awg2';

UPDATE protocol_variables pv
JOIN protocols p ON p.id = pv.protocol_id
SET pv.default_value = CASE pv.variable_name
  WHEN 'Jc' THEN '5'
  WHEN 'Jmin' THEN '10'
  WHEN 'Jmax' THEN '50'
  WHEN 'S1' THEN '51'
  WHEN 'S2' THEN '125'
  WHEN 'S3' THEN '13'
  WHEN 'S4' THEN '9'
  WHEN 'H1' THEN '1443912531-1981073285'
  WHEN 'H2' THEN '1984025557-2135018048'
  WHEN 'H3' THEN '2145217268-2146643749'
  WHEN 'H4' THEN '2146790761-2146860793'
  WHEN 'I1' THEN '<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>'
  WHEN 'I2' THEN '<r 4><b 0x16030100><r 64>'
  WHEN 'I3' THEN '<r 8><b 0x17030300><r 48>'
  WHEN 'I4' THEN '<r 6><b 0x00000001><r 32>'
  WHEN 'I5' THEN '<r 10><b 0x08000000><r 40>'
  ELSE pv.default_value
END
WHERE p.slug = 'awg2'
  AND pv.variable_name IN ('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','I1','I2','I3','I4','I5');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I1', 'text', '<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>', 'AWG2 I1 CPS packet signature', 0
FROM protocols p
WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables pv WHERE pv.protocol_id = p.id AND pv.variable_name = 'I1');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I2', 'text', '<r 4><b 0x16030100><r 64>', 'AWG2 I2 CPS packet signature', 0
FROM protocols p
WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables pv WHERE pv.protocol_id = p.id AND pv.variable_name = 'I2');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I3', 'text', '<r 8><b 0x17030300><r 48>', 'AWG2 I3 CPS packet signature', 0
FROM protocols p
WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables pv WHERE pv.protocol_id = p.id AND pv.variable_name = 'I3');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I4', 'text', '<r 6><b 0x00000001><r 32>', 'AWG2 I4 CPS packet signature', 0
FROM protocols p
WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables pv WHERE pv.protocol_id = p.id AND pv.variable_name = 'I4');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I5', 'text', '<r 10><b 0x08000000><r 40>', 'AWG2 I5 CPS packet signature', 0
FROM protocols p
WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables pv WHERE pv.protocol_id = p.id AND pv.variable_name = 'I5');
