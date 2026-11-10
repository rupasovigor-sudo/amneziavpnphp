#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${AWG31_CONTAINER_NAME:-amnezia-awg31}"
HOST_CONFIG_DIR="${AWG31_HOST_CONFIG_DIR:-/opt/amnezia/awg31}"
CONTAINER_CONFIG_DIR=/opt/amnezia/awg
CONFIG_FILE=awg31.conf
PORT="${AWG31_PORT:-444}"

if [ -n "${AWG31_CONFIG_FILE:-}" ] && [ -s "$AWG31_CONFIG_FILE" ]; then
  CONFIG_SOURCE="$AWG31_CONFIG_FILE"
elif [ -n "${AWG31_CONFIG_B64:-}" ]; then
  CONFIG_SOURCE=''
else
  echo "AWG31_CONFIG_FILE or AWG31_CONFIG_B64 is required" >&2
  exit 2
fi
docker image inspect amnezia-awg2 >/dev/null 2>&1 || { echo "amnezia-awg2 image is missing" >&2; exit 3; }

mkdir -p "$HOST_CONFIG_DIR"
umask 077
NEW_FILE="$HOST_CONFIG_DIR/$CONFIG_FILE.new"
if [ -n "$CONFIG_SOURCE" ]; then
  cp "$CONFIG_SOURCE" "$NEW_FILE"
else
  printf '%s' "$AWG31_CONFIG_B64" | base64 -d > "$NEW_FILE"
fi
grep -q '^\[Interface\]' "$NEW_FILE"
grep -q '^HeaderProtectionKey[[:space:]]*=' "$NEW_FILE"

# Keep already issued 3.1 peers when the image/profile is redeployed.
if [ -s "$HOST_CONFIG_DIR/$CONFIG_FILE" ]; then
  awk 'BEGIN { peer=0 } /^\[Peer\][[:space:]]*$/ { peer=1 } peer { print }' \
    "$HOST_CONFIG_DIR/$CONFIG_FILE" >> "$NEW_FILE"
fi
mv -f "$NEW_FILE" "$HOST_CONFIG_DIR/$CONFIG_FILE"
[ -s "$HOST_CONFIG_DIR/clientsTable" ] || printf '[]\n' > "$HOST_CONFIG_DIR/clientsTable"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart always \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  -p "${PORT}:${PORT}/udp" \
  -v "${HOST_CONFIG_DIR}:${CONTAINER_CONFIG_DIR}" \
  amnezia-awg2 \
  sh -c "WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up ${CONTAINER_CONFIG_DIR}/${CONFIG_FILE} && sleep infinity" \
  >/dev/null

for _ in $(seq 1 20); do
  if docker exec "$CONTAINER_NAME" awg show awg31 >/dev/null 2>&1; then
    echo "AWG31_SIDECAR_OK"
    exit 0
  fi
  sleep 1
done

docker logs --tail 30 "$CONTAINER_NAME" >&2 || true
echo "AWG31 sidecar did not start" >&2
exit 4
