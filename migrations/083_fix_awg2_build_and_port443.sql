-- =====================================================================
-- Migration 083: Fix awg2 install script — Go toolchain + default port 443
-- =====================================================================
-- 1. Upstream amneziawg-go pins an older golang image in its Dockerfile
--    (golang:1.24.4) than its own go.mod requires (go >= 1.25), so
--    `docker build` fails with "go.mod requires go >= 1.25.0". Patch the
--    cloned Dockerfile to use the golang tag matching go.mod before building.
-- 2. The script's fallback VPN port was a random 30000-65000 value; the
--    approved design is UDP/443 (clients connect to domain:443). The panel
--    now always passes SERVER_PORT, but align the script fallback too.
-- Idempotent: the REPLACEs no-op once applied (guarded by NOT LIKE).
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
    install_script,
    'VPN_PORT="${SERVER_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}"',
    'VPN_PORT="${SERVER_PORT:-443}"'
)
WHERE slug = 'awg2';

UPDATE protocols
SET install_script = REPLACE(
    install_script,
    'docker build --no-cache -t amnezia-awg2 "$HOST_CONFIG_DIR/src"',
    '# Align the builder image with the Go version go.mod requires: upstream
# pins an older golang tag in its Dockerfile and the build fails otherwise.
GOVER=$(awk ''/^go /{print $2}'' "$HOST_CONFIG_DIR/src/go.mod" | cut -d. -f1,2)
if [ -n "$GOVER" ] && [ -f "$HOST_CONFIG_DIR/src/Dockerfile" ]; then
  sed -i -E "s|^(FROM[[:space:]]+golang:)[0-9.]+|\\1${GOVER}|" "$HOST_CONFIG_DIR/src/Dockerfile"
fi
docker build --no-cache -t amnezia-awg2 "$HOST_CONFIG_DIR/src"'
)
WHERE slug = 'awg2'
  AND install_script NOT LIKE '%GOVER=%';
