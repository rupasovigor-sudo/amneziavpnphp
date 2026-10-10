-- =====================================================================
-- Migration 116: build the awg2 image in the host network namespace
-- =====================================================================
-- A rebuild removes the old awg2 container first, so the build container
-- can inherit its docker0 address (172.17.0.2). WARP egress marks traffic
-- from that address into the tunnel, and the host's upstream resolvers
-- (e.g. Timeweb 92.53.116.x) refuse queries arriving via WARP — so `apk add`
-- found no packages (exit 3) on every retry and the rebuild failed.
-- `--network host` takes build traffic out of docker0 entirely: no WARP
-- marking, and DNS uses the host's resolver. Idempotent.
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        'docker build -t amnezia-awg2 "$HOST_CONFIG_DIR/src"',
        'docker build --network host -t amnezia-awg2 "$HOST_CONFIG_DIR/src"'
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%docker build -t amnezia-awg2 %'
  AND install_script NOT LIKE '%docker build --network host -t amnezia-awg2%';
