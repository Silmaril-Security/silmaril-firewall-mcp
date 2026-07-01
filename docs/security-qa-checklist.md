# Security And QA Checklist

## Authentication And Authorization

- Auth0 access tokens are validated by `firewall-ui`, not the MCP repo.
- The MCP route requires `Authorization: Bearer` for every non-OPTIONS MCP request.
- OAuth Protected Resource Metadata is available at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`.
- OAuth Authorization Server Metadata is available at `/.well-known/oauth-authorization-server` with local dynamic client registration, hosted callback bridging, and token exchange forwarding.
- Missing-token `401` responses include `WWW-Authenticate` with `resource_metadata` and aggregate/search scope guidance.
- The MCP route rejects disallowed `Origin` headers before MCP message handling.
- The MCP server forwards user access tokens only to the configured `FIREWALL_UI_BASE_URL`.
- The MCP server discovers issuer, audience/resource, scopes, and public OAuth client ID from `firewall-ui` `/api/mcp/v1/config`.
- The OAuth bridge sends no Auth0 organization parameter for shared hosted deployments, allowing Auth0 Universal Login to prompt for or discover the organization.
- The OAuth bridge sends `MCP_AUTH0_ORGANIZATION` only for explicit single-org deployments and rejects non-`org_...` organization values locally.
- `firewall-ui` rejects wrong issuer, wrong audience, expiry, missing org, missing tenant, missing admin claim, and missing scopes.
- Cross-tenant resource probes are re-scoped through `firewall-ui` deployment lookup and return deterministic `404`.

## Tool Surface

- v1 tools are read-only.
- No classify, explain, triage, exports, invitations, user management, deployment history, writes, or costful operations.
- Aggregate/search tools do not require payload or trace scopes.
- Detail tools require `reason` and upstream detail scopes.
- Page size is capped at 100 and firewall-ui rejects unbounded time windows.
- MCP response byte size is capped by `MCP_MAX_RESPONSE_BYTES`.

## Sensitive Data Handling

- No raw Authorization headers are logged.
- No raw finding payloads or trace text are logged.
- Metadata-only audit records include tool name, firewall ID, finding ID, reason, request ID, and timestamp.
- Canary payload tests prove payload text is absent from audit bodies and console output.
- Tool instructions tell agents to treat finding content as hostile prompt-injection data.

## Runtime Coverage

- SageMaker path covers metrics, findings, detail, and trace source behavior.
- Self-hosted ECS path covers ECS metrics, findings table override, capability degradation, and single-event trace fallback.
- Capability responses expose runtime, deployment kind, source references, generated timestamp, freshness where available, and warnings.

## Required Proof Before Production

- `firewall-ui`: lint, typecheck, unit tests, and targeted MCP bearer/evidence tests.
- MCP repo: lint, typecheck, SDK Streamable HTTP tests, and build.
- Auth0 smoke: one org-scoped user can list/search/get only that tenant; another tenant envKey returns denied/not found.
- Security smoke: wrong audience, wrong issuer, expired token, missing org, missing scope, and cross-tenant IDOR attempts.
- Proof artifacts: golden MCP transcript, capability matrix, quickstart, evaluator walkthrough, and dogfood scorecard.
