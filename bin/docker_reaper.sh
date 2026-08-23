#!/bin/bash
# =====================================================================
# Weekly docker disk hygiene for the PANEL host.
# =====================================================================
# MUST run on the HOST, not inside the panel container: the container's
# docker CLI points at the dind sidecar (DOCKER_HOST=tcp://dind:2375),
# which is empty. `docker compose build web` accumulates BuildKit cache on
# the HOST daemon on every panel rebuild — 5+ GB of stale layers were
# observed at 74% disk use. Install it via the host's cron.d.
#
# This is SAFE to prune here: the awg2 image is built on the REMOTE pool
# members over SSH, never on the panel host, so migration 105's layer-cache
# reuse (which depends on NOT pruning the members' cache) is unaffected.
# Losing the panel's own build cache only makes the next manual
# `docker compose build web` slower.
#
# Conservative filters:
#   * builder prune keeps cache used within the last 7 days (168h), so an
#     in-progress panel rebuild is not sabotaged.
#   * image prune (no -a) removes only DANGLING images, never tagged ones
#     that a running container references.
# =====================================================================
set -u

ts() { date -u +%FT%TZ; }

if ! command -v docker >/dev/null 2>&1; then
    echo "[docker-reaper $(ts)] docker CLI not available; skipping"
    exit 0
fi

echo "[docker-reaper $(ts)] before:"
docker system df 2>&1 | sed 's/^/  /'

echo "[docker-reaper $(ts)] pruning build cache older than 168h..."
docker builder prune -f --filter until=168h 2>&1 | tail -1

echo "[docker-reaper $(ts)] pruning dangling images..."
docker image prune -f 2>&1 | tail -1

echo "[docker-reaper $(ts)] after:"
docker system df 2>&1 | sed 's/^/  /'
