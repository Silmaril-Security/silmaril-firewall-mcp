# Developer Quickstart

This page is for Silmaril operators who deploy or run the MCP server. Customer setup is hosted and URL-only; start with the [README](../README.md) and [customer guide](customer-guide.md) instead.

1. Configure the Firewall MCP audience and public OAuth client in `firewall-ui`.
2. Deploy or run `firewall-ui` with `SILMARIL_MCP_API_ENABLED=true`.
3. Configure this repo with `FIREWALL_UI_BASE_URL`, `MCP_PUBLIC_BASE_URL`, and `MCP_OAUTH_STATE_SECRET`. Set `MCP_AUTH0_ORGANIZATION` only for an explicit single-org deployment; shared hosted deployments should leave it unset so Auth0 Universal Login can prompt for or discover the user's organization. `MCP_PUBLIC_BASE_URL` is the trusted public origin advertised through OAuth discovery. `MCP_OAUTH_STATE_SECRET` signs hosted OAuth bridge state and must be a high-entropy secret.
   For localhost testing, the Auth0 public MCP client must allow `http://localhost:3002/oauth/callback`; otherwise Auth0 will reject the local bridge with a callback URL mismatch.
4. Run the MCP server locally on a different port from `firewall-ui`:

```sh
npm install
FIREWALL_UI_BASE_URL=http://localhost:3000 MCP_PUBLIC_BASE_URL=http://localhost:3002 MCP_OAUTH_STATE_SECRET=dev-only-change-me PORT=3002 npm run dev
```

5. Add the local server to an MCP client:

```sh
codex mcp add silmaril-firewall --url http://localhost:3002/mcp
```

6. Start with aggregate tools:

```txt
list_firewalls
get_firewall
get_schema
get_metrics
list_findings
list_suspicious_users
get_investigation_packet
```

Use `get_finding` or `get_finding_trace` only after a compact evidence path is insufficient.

## Operator Notes

`firewall-ui` exposes `GET /api/mcp/v1/config` for MCP-server diagnostics and OAuth discovery support. It returns non-secret issuer, resource, scope, enabled-state, and public-client metadata.

Configure the Auth0 application used by `firewall-ui` as organization-scoped for shared hosted deployments. Use `organization_usage=require` with an organization prompt or discovery flow such as `organization_require_behavior=pre_login_prompt`, so Auth0 selects the organization before minting a token with `org_id`.

The MCP host advertises itself as the authorization server for MCP clients. Its local registration endpoint returns the configured public client, its authorize route redirects to Silmaril login with a fixed hosted callback, and its token route forwards the authorization-code exchange with the client's PKCE verifier.

When `MCP_AUTH0_ORGANIZATION` is unset and the client does not send an Auth0 organization ID, the MCP OAuth bridge forwards no `organization` parameter so Auth0 can prompt for or discover the organization. If a client explicitly sends `organization=org_...`, the bridge passes it through. Non-ID organization values are rejected locally instead of being forwarded to Auth0.

## Activity Telemetry

Public `/mcp` tool handlers can emit a minimal adoption event after the response
using `MCP_ACTIVITY_ENABLED=true` and `MCP_ACTIVITY_INGEST_KEY`. The key must be
at least 32 characters and exactly match the server-only key configured in
`firewall-ui`. Enabled-but-incomplete configuration is rejected. Each logical
tool call sends only tool name and success/error outcome with a 1.5-second
timeout and no retry; initialization, tool discovery, argument validation
failures, and `/admin/mcp` are excluded. Telemetry failure never changes tool
results.

The separate `/admin/mcp` resource exposes only
`get_mcp_adoption_summary` and `list_mcp_activity`. Before constructing that
server, the host calls `firewall-ui` to require `firewalls:read` and a verified
global Silmaril admin claim. Its protected-resource metadata is at
`/.well-known/oauth-protected-resource/admin-mcp`.

## Local Validation

```sh
npm run lint
npm run typecheck
npm test
npm run build
```

`npm test` runs an SDK client over Streamable HTTP with mocked `firewall-ui` responses and verifies bearer forwarding, Origin rejection, normalized errors, suspicious-user category forwarding, schema/default exposure, JA4-unavailable diagnostics, minimal one-per-call activity emission, admin preflight isolation, and non-logging of payload canaries.
