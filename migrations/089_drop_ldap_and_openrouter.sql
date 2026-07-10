-- =====================================================================
-- Migration 089: remove decommissioned features (LDAP + OpenRouter)
-- =====================================================================
-- The LDAP auth integration, the OpenRouter-powered auto-translation, the
-- QR decoder tool and the AI protocol-assistant were removed from the panel.
-- This drops the now-unused LDAP tables and clears the OpenRouter API key.
--
-- Kept on purpose:
--   * translations           — still powers all UI localization via t()
--   * ai_generations          — still read by ProtocolService stats
--   * users.ldap_dn / ldap_synced columns — harmless, left to avoid a
--     destructive column drop on the users table
-- Idempotent: DROP TABLE IF EXISTS + DELETE.
-- =====================================================================

DROP TABLE IF EXISTS ldap_group_mappings;
DROP TABLE IF EXISTS ldap_configs;

DELETE FROM api_keys WHERE service_name = 'openrouter';
