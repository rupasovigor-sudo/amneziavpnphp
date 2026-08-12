-- =====================================================================
-- Migration 104: fix awg2 rebuild aborting at git checkout
-- =====================================================================
-- The awg2 installer moves the amneziawg-go source tree to the pinned ref with
-- `git checkout --detach FETCH_HEAD`. But the same installer also edits the
-- source Dockerfile (to align the golang builder tag with go.mod). On a REBUILD
-- the tree already carries that local edit from the previous install, so the
-- plain checkout refuses ("local changes would be overwritten … Aborting"), and
-- under `set -e` the whole install aborts — after the caller has already wiped
-- the running config. Force the move (reset --hard + checkout -f) so a rebuild
-- discards the stale edit; the installer re-applies the Dockerfile change right
-- after. Fresh installs are unaffected (empty tree).
--
-- Idempotent: guarded so re-running cannot double-apply.
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        'git -C "$HOST_CONFIG_DIR/src" checkout -q --detach FETCH_HEAD',
        'git -C "$HOST_CONFIG_DIR/src" reset --hard -q HEAD 2>/dev/null; git -C "$HOST_CONFIG_DIR/src" checkout -f -q --detach FETCH_HEAD'
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%checkout -q --detach FETCH_HEAD%'
  AND install_script NOT LIKE '%checkout -f -q --detach FETCH_HEAD%';
