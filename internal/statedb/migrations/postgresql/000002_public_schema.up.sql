-- Truster <https://truster.dev>
-- Copyright The Truster Authors
-- SPDX-License-Identifier: Apache-2.0

BEGIN; -- Keep protocol state in the dedicated database's public schema.

ALTER TABLE truster_state.oauth_states SET SCHEMA public;
ALTER TABLE truster_state.auth_codes SET SCHEMA public;
ALTER TABLE truster_state.flow_credentials SET SCHEMA public;
ALTER TABLE truster_state.upstream_credentials SET SCHEMA public;
ALTER TABLE truster_state.otp_challenges SET SCHEMA public;
ALTER TABLE truster_state.otp_sends SET SCHEMA public;
ALTER TABLE truster_state.refresh_grants SET SCHEMA public;
ALTER TABLE truster_state.refresh_tokens SET SCHEMA public;
ALTER TABLE truster_state.grant_actions SET SCHEMA public;
ALTER TABLE truster_state.identity_selections SET SCHEMA public;
ALTER TABLE truster_state.pushed_requests SET SCHEMA public;
DROP SCHEMA truster_state;

COMMIT;
