-- =====================================================================
-- Migration 103: raise awg0 txqueuelen via PostUp
-- =====================================================================
-- awg0 shipped with the default 500-packet transmit queue. amneziawg-go runs in
-- USERSPACE and the servers have a single core, so during a burst — loading a
-- video is exactly that — the queue drains slower than it fills and packets are
-- dropped on the way to clients. One production server had accumulated 131089
-- tx_dropped over ~3 days (0.22% of 58M packets), with zero drops at idle:
-- the loss is entirely burst-shaped, which is why video stalls part-way while
-- pages load fine. QUIC (Instagram video) suffers far more from this than TCP.
--
-- 2000 gives 4x the burst headroom without the bufferbloat a very deep queue
-- would add. This is mitigation, not a cure: the real ceiling is the single
-- core (~190 Mbit/s measured through the tunnel for ALL clients combined).
--
-- Idempotent: guarded by NOT LIKE so re-running cannot stack the setting.
-- =====================================================================

UPDATE protocols
SET install_script = REPLACE(
        install_script,
        'PostUp = iptables -A FORWARD -i %i -j ACCEPT;',
        'PostUp = ip link set %i txqueuelen 2000; iptables -A FORWARD -i %i -j ACCEPT;'
    ),
    updated_at = NOW()
WHERE slug = 'awg2'
  AND install_script LIKE '%PostUp = iptables -A FORWARD -i %'
  AND install_script NOT LIKE '%txqueuelen%';
