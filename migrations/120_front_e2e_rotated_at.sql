-- =====================================================================
-- Migration 120: remember when the front port was last auto-rotated
-- =====================================================================
-- FrontProbe rotates on >= 2 consecutive data-path failures, at most once
-- an hour. Keying that on the exact streak value broke when an unrelated
-- run bumped the counter (found in the live test). Idempotent.
-- =====================================================================

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'pool_fronts' AND column_name = 'e2e_rotated_at');
SET @s := IF(@c = 0, 'ALTER TABLE pool_fronts ADD COLUMN e2e_rotated_at DATETIME NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
