-- =====================================================================
-- Migration 124: refresh amneziawg-go before every AWG2 image rebuild
-- =====================================================================
-- The original installer cloned the source only on the first deployment.
-- Every later "update AWG" rebuilt the already-present working tree without
-- fetching upstream, so Docker successfully produced the same old image and
-- the panel reported a false success.  Always resolve AWG2_REF (master by
-- default), discard the installer-owned Dockerfile edit, and check out the
-- fetched commit before building.
--
-- Idempotent: the marker prevents inserting the refresh block twice.
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        'fi

# Align the builder image with the Go version go.mod requires:',
        'fi

# AWG2_SOURCE_REFRESH_V1: an update must build the requested upstream ref,
# not the source tree left behind by the previous installation.
AWG2_REF="${AWG2_REF:-master}"
git -C "$HOST_CONFIG_DIR/src" reset --hard -q HEAD 2>/dev/null || true
git -C "$HOST_CONFIG_DIR/src" fetch -q --depth=1 origin "$AWG2_REF"
git -C "$HOST_CONFIG_DIR/src" checkout -f -q --detach FETCH_HEAD

# Align the builder image with the Go version go.mod requires:'
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git%'
  AND install_script NOT LIKE '%AWG2_SOURCE_REFRESH_V1%';
