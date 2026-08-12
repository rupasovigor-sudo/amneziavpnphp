-- =====================================================================
-- Migration 105: make the awg2 image build reliable (layer cache + retry)
-- =====================================================================
-- The awg2 image was rebuilt with `docker build --no-cache`, which re-ran
-- `apk add iproute2 iptables bash` and re-downloaded amneziawg-tools from
-- GitHub on EVERY rebuild. The Alpine v3.19 mirror intermittently answers
-- "temporary error (try again later)", failing the build with exit 3 — which
-- under set -e aborted the whole install (the observed "rebuild never
-- completes"). A plain `docker run alpine apk update` on the same host works
-- moments later, so it is transient mirror flakiness, not a real outage.
--
-- Two changes make the rebuild depend on that mirror as little as possible:
--   1. Drop --no-cache. The apk/tools layer keys only on the Dockerfile, so it
--      is cached across rebuilds — verified to make ZERO Alpine CDN requests on
--      a rebuild — while the Go stage still rebuilds when the pinned source
--      commit changes. So a version bump is still picked up.
--   2. Retry the build a few times with backoff, for the cold-cache case (a
--      fresh server's first build still has to hit the mirror once).
--
-- The atomic snapshot/rollback in ServerPool::redeployMember keeps a member
-- safe even if all retries fail. Idempotent: guarded against double-wrapping.
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        'docker build --no-cache -t amnezia-awg2 "$HOST_CONFIG_DIR/src"',
        '_awg2_build_ok=0; for _a in 1 2 3 4; do if docker build -t amnezia-awg2 "$HOST_CONFIG_DIR/src"; then _awg2_build_ok=1; break; fi; echo "awg2 image build attempt $_a failed (likely transient apk/CDN); retrying in 12s..."; sleep 12; done; [ "$_awg2_build_ok" = "1" ] || { echo "awg2 image build failed after retries"; exit 1; }'
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%docker build --no-cache -t amnezia-awg2 "$HOST_CONFIG_DIR/src"%'
  AND install_script NOT LIKE '%_awg2_build_ok%';
