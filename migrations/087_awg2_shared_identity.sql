-- =====================================================================
-- Migration 087: awg2 install accepts a shared (pool) server identity
-- =====================================================================
-- For failover pools every member must run the SAME awg2 identity. Make the
-- server keypair, preshared key and interface address overridable via env so
-- ServerPool::addMember can deploy a member with the pool's identity instead of
-- generating a fresh one. The AmneziaWG obfuscation params (Jc/S1.../H1.../I1..)
-- are already env-overridable. Idempotent: each REPLACE is a no-op once applied.
-- =====================================================================

UPDATE protocols SET install_script = REPLACE(install_script,
  'PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" awg genkey)',
  'PRIVATE_KEY="${SERVER_PRIVATE_KEY:-$(docker exec "$CONTAINER_NAME" awg genkey)}"')
WHERE slug = 'awg2';

UPDATE protocols SET install_script = REPLACE(install_script,
  'PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" awg pubkey)',
  'PUBLIC_KEY="${SERVER_PUBLIC_KEY:-$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" awg pubkey)}"')
WHERE slug = 'awg2';

UPDATE protocols SET install_script = REPLACE(install_script,
  'PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" awg genpsk)',
  'PRESHARED_KEY="${SERVER_PRESHARED_KEY:-$(docker exec "$CONTAINER_NAME" awg genpsk)}"')
WHERE slug = 'awg2';

UPDATE protocols SET install_script = REPLACE(install_script,
  'Address = 10.8.1.1/24',
  'Address = ${SERVER_ADDRESS:-10.8.1.1/24}')
WHERE slug = 'awg2';
