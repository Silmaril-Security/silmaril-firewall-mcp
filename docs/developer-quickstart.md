# Developer Quickstart

This page is for Silmaril operators who deploy or run the MCP server. Customer setup is hosted and URL-only; start with the [README](../README.md) and [customer guide](customer-guide.md) instead.

1. Configure the Firewall MCP audience and public OAuth client in `firewall-ui`.
2. Deploy or run `firewall-ui` with `SILMARIL_MCP_API_ENABLED=true`.
3. Configure this repo with `FIREWALL_UI_BASE_URL`, `MCP_PUBLIC_BASE_URL`, and `MCP_OAUTH_STATE_SECRET`. The secret must contain at least 32 high-entropy bytes; it signs OAuth client/state artifacts and encrypts the resource-bound MCP access and refresh credentials. Set `MCP_AUTH0_ORGANIZATION` only for an explicit single-org deployment; shared hosted deployments should leave it unset so Auth0 Universal Login can prompt for or discover the user's organization. `MCP_PUBLIC_BASE_URL` is the trusted public origin advertised through OAuth discovery.

For Vercel, configure Preview and Production independently. Each environment must point `FIREWALL_UI_BASE_URL` at the matching firewall-ui environment and `MCP_PUBLIC_BASE_URL` at its own stable public alias. Use different `MCP_OAUTH_STATE_SECRET` values for Preview and Production. Register the stable aliases and `/oauth/callback` URLs in Auth0; do not register ephemeral deployment URLs. The MCP project needs Auth0 public-client settings only and receives no AWS role or AWS credentials.
   For localhost testing, the Auth0 public MCP client must allow `http://localhost:3002/oauth/callback`; otherwise Auth0 will reject the local bridge with a callback URL mismatch.
   Configure `MCP_AUDIT_URL` before enabling full finding or trace detail. Those
   tools fail closed when the audit sink is absent, times out, or rejects an
   event.
4. Run the MCP server locally on a different port from `firewall-ui`:

```sh
npm install
FIREWALL_UI_BASE_URL=http://localhost:3001 MCP_PUBLIC_BASE_URL=http://localhost:3002 MCP_OAUTH_STATE_SECRET=dev-only-change-me-with-32-bytes-minimum PORT=3002 npm run dev
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

## Vercel Environment Contract

Configure stable aliases before adding Auth0 callbacks. Do not substitute an
ephemeral Vercel deployment URL.

| Variable | Preview | Production |
|---|---|---|
| `FIREWALL_UI_BASE_URL` | Stable firewall-ui Preview alias | `https://app.silmaril.dev` |
| `MCP_PUBLIC_BASE_URL` | Stable MCP Preview alias | `https://firewall-mcp.silmaril.dev` |
| `MCP_OAUTH_STATE_SECRET` | Preview-only 32+ byte secret | Separate Production 32+ byte secret |
| `MCP_AUTH0_ORGANIZATION` | Unset for shared organization discovery | Unset for shared organization discovery |

Register `${MCP_PUBLIC_BASE_URL}/oauth/callback` for each stable alias in the
matching Auth0 public application. The MCP Vercel project must not receive
`AWS_ROLE_ARN`, AWS access keys, or any other AWS permission; every evidence
request goes through the matching firewall-ui environment with Auth0 OAuth.

## Operator Notes

`firewall-ui` exposes `GET /api/mcp/v1/config` for MCP-server diagnostics and OAuth discovery support. It returns non-secret issuer, resource, scope, enabled-state, and public-client metadata.

Configure the Auth0 application used by `firewall-ui` as organization-scoped for shared hosted deployments. Use `organization_usage=require` with an organization prompt or discovery flow such as `organization_require_behavior=pre_login_prompt`, so Auth0 selects the organization before minting a token with `org_id`.

Enable **Allow Offline Access** on the Auth0 API for the Firewall MCP audience.
On the public Auth0 MCP application, enable the Refresh Token grant and rotating,
expiring refresh tokens. For clients registered to use that grant, the OAuth
bridge adds `offline_access` only to its upstream Auth0 authorization request. It
does not advertise that authorization-server scope as a Firewall MCP resource
permission or return it in the MCP credential scope.

The MCP host advertises itself as the authorization server for MCP clients. Its
registration endpoint returns a unique signed client handle bound to exact HTTP
loopback callbacks; it never exposes the shared Auth0 client ID. Every
authorization rejects `prompt=none`, requires S256 PKCE, and redirects directly
to Auth0 for the only consent prompt through the fixed hosted callback. The
bridge passes the validated dynamic client name and a display-safe callback as
`ext-mcp-client-name` and `ext-mcp-client-callback`; the Auth0 hosted consent
template must render both values so the user can identify the client receiving
access. Treat both display values as untrusted text and rely on Auth0 template
escaping. The token endpoint verifies the returned Auth0 JWT signature, issuer,
audience, and expiry before issuing an encrypted credential bound to either
`/mcp` or `/admin/mcp`. The
inbound MCP credential is never forwarded to `firewall-ui`. Redirects are
disabled on every credential-bearing server-to-server request.

When a client omits `scope` during registration, it receives aggregate scopes
only: `firewalls:read`, `metrics:read`, and `findings:read`. Full finding and
trace access therefore requires explicit scope consent. Refresh credentials are
bound to the dynamic client and original resource, refresh requests cannot
expand scopes, and the bridge requires Auth0 refresh-token rotation before
returning a replacement credential.

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

## Security Limits And Audit

The MCP route rejects invalid credentials before JSON-RPC handling, rejects
JSON-RPC batches and non-JSON or oversized requests, and applies an actor/client
token bucket before upstream work. Higher-amplification tools consume weighted
quota. `MCP_RATE_LIMIT_REQUESTS_PER_SECOND` defaults to 5,
`MCP_RATE_LIMIT_BURST` defaults to 10, and `MCP_MAX_REQUEST_BYTES` defaults to
256,000. Platform-level Vercel rate controls should remain enabled because the
application bucket is per warm runtime instance.

All upstream requests have a deadline controlled by
`MCP_UPSTREAM_TIMEOUT_MS` (10 seconds by default). Public OAuth configuration is
cached for `MCP_PUBLIC_CONFIG_CACHE_MS` (30 seconds by default) to bound
discovery amplification.

`get_finding` and `get_finding_trace` return evidence only after
`MCP_AUDIT_URL` accepts one metadata-only event. The event includes a unique
event ID, actor subject/email, tenant, organization, OAuth client, target IDs,
reason, outcome, timestamp, correlation ID, token ID, and deployment version.
It excludes access tokens, payloads, and traces. `MCP_AUDIT_TIMEOUT_MS`
defaults to 3 seconds.

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

`npm test` runs an SDK client over Streamable HTTP with mocked `firewall-ui` and
Auth0 responses. It verifies credential/resource binding, callback and PKCE
binding, Auth0-hosted client identity, signed JWT validation, refresh isolation, HTTP
401/403/429 behavior, batch/request caps, downstream credential separation,
normalized errors, admin preflight isolation, durable attributed sensitive
audit, and non-logging of payload canaries.
