# Security And QA Checklist

## Authentication And Authorization

- Auth0 access-token signatures, issuer, audience, and expiry are validated at token exchange and again by `firewall-ui` when the separate downstream credential is used.
- The MCP route decrypts and validates a resource-bound MCP bearer before every non-OPTIONS request. Direct Auth0 JWTs and malformed, expired, or wrong-resource credentials fail at the HTTP boundary with `401`.
- OAuth Protected Resource Metadata is available at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`.
- OAuth Authorization Server Metadata is available at `/.well-known/oauth-authorization-server` with unique signed dynamic registrations, exact loopback callback binding, Auth0-hosted consent that displays the validated dynamic client name and display-safe callback, hosted callback bridging, and encrypted token exchange.
- Missing-token `401` responses include `WWW-Authenticate` with `resource_metadata` and aggregate/search scope guidance.
- The MCP route rejects disallowed `Origin` headers before MCP message handling.
- The MCP server never forwards the inbound MCP bearer. It extracts and forwards only the separately wrapped Auth0 credential to the configured `FIREWALL_UI_BASE_URL`.
- The MCP server discovers issuer, audience/resource, scopes, and public OAuth client ID from `firewall-ui` `/api/mcp/v1/config`.
- The OAuth bridge sends no Auth0 organization parameter for shared hosted deployments, allowing Auth0 Universal Login to prompt for or discover the organization.
- The OAuth bridge sends the validated dynamic client name and a display-safe callback as sanitized Auth0 `ext-` parameters. The hosted consent template renders and escapes both values before approval.
- The OAuth bridge sends `MCP_AUTH0_ORGANIZATION` only for explicit single-org deployments and rejects non-`org_...` organization values locally.
- `firewall-ui` rejects wrong issuer, wrong audience, expiry, missing org, missing tenant, missing admin claim, and missing scopes.
- Cross-tenant resource probes are re-scoped through `firewall-ui` deployment lookup and return deterministic `404`.
- Managed-pilot authority is derived from the verified Auth0 organization and tenant. Every currently active runtime key bound to that pair is included; caller-supplied tenant or key selectors cannot widen the boundary.
- Firewall-scoped upstream responses carry a non-sensitive `data_scope` attestation. The MCP proxy fails closed when it is missing and rejects pilot attestations that do not match the authenticated tenant.
- `/admin/mcp` has separate protected-resource metadata and calls the `firewall-ui` admin-access endpoint before constructing or exposing its two tools.

## Tool Surface

- v1 tools are read-only.
- No classify, explain, triage, exports, invitations, user management, deployment history, writes, or costful operations.
- Aggregate/search tools do not require payload or trace scopes.
- `list_suspicious_users` requires only aggregate findings access upstream and returns minimized evidence handles, derived abuse categories, bot-farming scores, and missing-metadata diagnostics.
- Bot-farming correlation is a prioritization boost only; suspicious-user inclusion must come from true-positive abuse evidence.
- Suspicious-user score fields use explicit 0-100 percentage names such as `suspicious_score_percent`, `bot_farming.score_percent`, and `bot_farming.signals.*.score_percent`.
- Detail tools require `reason` and upstream detail scopes.
- Detail tools are marked restricted, are excluded from read-only auto-approval hints, and require explicit OAuth detail scopes.
- Page size is capped at 100 and firewall-ui rejects unbounded time windows.
- JSON-RPC batches, non-JSON requests, and request bodies over `MCP_MAX_REQUEST_BYTES` are rejected before MCP processing.
- Per-actor/client weighted quotas return deterministic `429` before upstream fan-out; Vercel platform rate controls provide the distributed outer limit.
- MCP response byte size is capped by `MCP_MAX_RESPONSE_BYTES`.
- Managed-pilot conversation search uses the existing shared vector index with mandatory scope-schema, scope-ID, generation, time, and active API-key filters. Hydration rechecks the scope-bound control record and applies the same active API-key set to Athena.
- Public activity telemetry emits once per logical handler call and excludes initialization, discovery, input validation failures, and all admin MCP calls.

## Sensitive Data Handling

- No raw Authorization headers are logged.
- No raw finding payloads or trace text are logged.
- Sensitive detail is withheld unless a durable audit sink accepts one uniquely identified event.
- Metadata-only audit records include actor, tenant, organization, OAuth client, tool, target IDs, reason, outcome, timestamp, correlation ID, token ID, and deployment version.
- Canary payload tests prove payload text is absent from audit bodies and console output.
- Tool instructions tell agents to treat finding content as hostile prompt-injection data.
- JA4 and other fingerprint-derived fields are not exposed by the MCP server; when absent, firewall-ui returns unavailable signal diagnostics instead of zero scores.
- Activity bodies contain only schema version, tool name, and success/error. They never contain identities, arguments, results, target IDs, queries, reasons, payloads, traces, IPs, or user agents; identity is derived by `firewall-ui` from the verified bearer.
- Activity POSTs use a server-only shared key, a 1.5-second timeout, no retries, and fail open without logging credentials or event details.
- Sensitive audit POSTs have a bounded deadline and fail closed without logging credentials, payloads, or traces.

## Runtime Coverage

- SageMaker path covers metrics, findings, detail, and trace source behavior.
- Self-hosted ECS path covers ECS metrics, findings table override, capability degradation, and single-event trace fallback.
- Capability responses expose runtime, deployment kind, source references, generated timestamp, freshness where available, and warnings.

## Required Proof Before Production

- `firewall-ui`: lint, typecheck, unit tests, and targeted MCP bearer/evidence tests.
- MCP repo: lint, typecheck, SDK Streamable HTTP tests, suspicious-user category/schema tests, and build.
- Auth0 smoke: one org-scoped user can list/search/get only that tenant; another tenant envKey returns denied/not found.
- Managed-pilot smoke: rotate the active-key set, verify old cursors fail closed, verify cross-pilot handles return not found, and confirm metrics, rollups, findings, conversation search, and hydration contain only the selected pilot's key set.
- Security smoke: malformed/direct/wrong-resource MCP credentials, wrong upstream audience/issuer/signature, expiry, missing org, missing scope, callback substitution, refresh replay, batch/oversize requests, quota exhaustion, and cross-tenant IDOR attempts.
- Proof artifacts: golden MCP transcript, capability matrix, quickstart, evaluator walkthrough, and dogfood scorecard.
- Auth0 smoke includes visually confirming that hosted consent shows the requesting dynamic client name and callback before approval.
