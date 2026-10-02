# Security And QA Checklist

## Authentication And Authorization

- Auth0 access-token signatures, issuer, audience, and expiry are validated at token exchange and again by `firewall-ui` when the separate downstream credential is used.
- The MCP route decrypts and validates a resource-bound MCP bearer before every non-OPTIONS request. Direct Auth0 JWTs and malformed, expired, or wrong-resource credentials fail at the HTTP boundary with `401`.
- OAuth Protected Resource Metadata is available at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`.
- OAuth Authorization Server Metadata is available at `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` with unique signed dynamic registrations, exact loopback callback binding, Auth0-hosted consent that displays the validated dynamic client name and display-safe callback, hosted callback bridging, and encrypted token exchange.
- Missing-token `401` responses include `WWW-Authenticate` with `resource_metadata`. The public challenge `scope` is `firewalls:read metrics:read findings:read`. The admin challenge `scope` is `firewalls:read`. Protected-resource `scopes_supported` follows firewall-ui for `/mcp`, and is only `firewalls:read` for `/admin/mcp`.
- The MCP route rejects disallowed `Origin` headers before MCP message handling. A missing `Origin` is allowed. The built-in allowlist is `https://chatgpt.com`, `https://chat.openai.com`, and `https://codex.openai.com`, extended by `MCP_ADDITIONAL_ALLOWED_ORIGINS` and `MCP_ALLOWED_ORIGINS`.
- The MCP server never forwards the inbound MCP bearer. It extracts and forwards only the separately wrapped Auth0 credential to the configured `FIREWALL_UI_BASE_URL`.
- The MCP server discovers issuer, audience/resource, scopes, and public OAuth client ID from `firewall-ui` `/api/mcp/v1/config`.
- The OAuth bridge sends no Auth0 organization parameter for shared hosted deployments, allowing Auth0 Universal Login to prompt for or discover the organization.
- The OAuth bridge sends the validated dynamic client name and a display-safe callback as sanitized Auth0 `ext-` parameters. The hosted consent template renders and escapes both values before approval.
- The OAuth bridge sends `MCP_AUTH0_ORGANIZATION` only for explicit single-org deployments and rejects non-`org_...` organization values locally.
- `firewall-ui` rejects wrong issuer, wrong audience, expiry, missing org, missing tenant, missing admin claim, and missing scopes.
- Cross-tenant resource probes are re-scoped through `firewall-ui` deployment lookup and return deterministic `404`.
- Managed-pilot authority is derived from the verified Auth0 organization and tenant. Every currently active runtime key bound to that pair is included; caller-supplied tenant or key selectors cannot widen the boundary.
- Tenant-scoped evidence responses carry a non-sensitive `data_scope` attestation. The MCP proxy fails closed when `kind`, `firewall_id`, or `tenant` is missing. A `pilot_tenant` attestation for a different tenant fails with `502` `upstream_scope_mismatch` unless the scope-neutral `/api/mcp/v1/principal` preflight attests `is_admin: true`. Missing or malformed principal attestations fail closed, and `get_schema` remains separately gated by `firewalls:read`.
- `/admin/mcp` has separate protected-resource metadata and calls `GET /api/mcp/v1/admin/access` before constructing or exposing `get_mcp_adoption_summary` and `list_mcp_activity`. Calling those tools also requires `firewalls:read`.

## Tool Surface

- v1 tools are read-only.
- No classify, explain, triage, exports, invitations, user management, deployment history, writes, or costful operations.
- Aggregate/search tools do not require payload or trace scopes.
- `list_suspicious_users` requires only aggregate findings access upstream and returns minimized evidence handles, derived abuse categories, bot-farming scores, and missing-metadata diagnostics.
- Bot-farming correlation is a prioritization boost only; suspicious-user inclusion must come from true-positive abuse evidence.
- Suspicious-user score fields use explicit 0-100 percentage names such as `suspicious_score_percent`, `bot_farming.score_percent`, and `bot_farming.signals.*.score_percent`.
- `get_finding` requires `findings:detail` and `payload:read`. `get_finding_trace` and `get_conversation` require `trace:read`. All three require a `reason` of 8 to 512 characters.
- Those three tools are marked restricted, are excluded from read-only auto-approval hints, and require the scopes above. Conversation search and topic tools require `conversations:read` and stay read-only.
- `list_findings` `pageSize`, conversation search `page_size`, and topic-detail `page_size` are capped at 100. Topic-list `page_size` is capped at 50. Finding `range` is one of `5m`, `15m`, `30m`, `1h`, `3h`, `6h`, `12h`, `1d`, `3d`, `1w`, or `30d`. Conversation search and topics use `1d`, `7d`, `30d`, or `90d`.
- JSON-RPC batches, non-JSON requests, and request bodies over `MCP_MAX_REQUEST_BYTES` are rejected before MCP processing.
- Per-actor/client weighted quotas return deterministic `429` before upstream fan-out. Costs above 1 are `list_suspicious_users` 5; `group_findings`, `search_conversations`, and `get_conversation` 3; `get_investigation_packet`, `get_finding`, `get_finding_trace`, `list_conversation_topics`, and `get_conversation_topic` 2. Vercel platform rate controls provide the distributed outer limit.
- MCP response byte size is capped by `MCP_MAX_RESPONSE_BYTES`.
- Managed-pilot conversation search uses the existing shared vector index with mandatory scope-schema, scope-ID, generation, time, and active API-key filters. Hydration rechecks the scope-bound control record and applies the same active API-key set to Athena.
- Public activity telemetry emits once per logical handler call and excludes initialization, discovery, input validation failures, and all admin MCP calls.

## Sensitive Data Handling

- No raw Authorization headers are logged.
- No raw finding payloads or trace text are logged.
- Sensitive detail is withheld unless a durable audit sink accepts one uniquely identified event.
- Metadata-only audit records include actor, tenant, organization, OAuth client, tool, `target_firewall_id`, reason, outcome, timestamp, correlation ID, token ID, and deployment version. Finding tools add `target_finding_id`. `get_conversation` adds a SHA-256 of the handle (`target_reference_sha256`) and does not record the raw handle.
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
