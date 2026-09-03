# Runtime Capability Matrix

| Capability | SageMaker Tenant | Self-Hosted ECS Tenant | Managed Pilot Tenant |
| --- | --- | --- | --- |
| Firewall inventory | Available via `firewall-ui` deployment registry | Available via `firewall-ui` deployment registry | One logical managed firewall for the authenticated organization and tenant |
| Metrics | SageMaker and CloudWatch endpoint metrics through `firewall-ui` | ECS/service metrics through `firewall-ui` ops source | Only metrics for currently active API keys bound to the authenticated organization and tenant |
| Findings search | Aurora findings table derived from envKey | Aurora findings table override from deployment registry | Shared physical findings table with mandatory trusted API-key scope |
| Findings totals/groups | Aurora aggregate queries | Aurora aggregate queries against override table | Same trusted API-key scope as findings search |
| Conversation search | Registered tenant conversation index | Registered tenant conversation index | Shared physical vector index filtered by organization/tenant scope and active API-key IDs |
| Conversation hydration | Scope-bound opaque handle and capture query | Scope-bound opaque handle and capture query | Scope-bound handle plus active API-key predicate on the raw capture query |
| Owner/tag filtering | Trusted runtime identity across available history | Trusted one-way API key attribution from the owner-filter runtime release forward; older unattributed rows are excluded | Restricted to keys already inside the managed-pilot boundary |
| Suspicious users | Derived in `firewall-ui` from true-positive abuse evidence, category labels, and available bot-farming signals | Same, using the tenant findings table override | Derived only from pilot-scoped findings |
| Investigation packet | Full compact packet with runtime metadata and trace availability | Full compact packet with degraded trace availability metadata | Finding and nearby metrics are independently pilot scoped |
| Full finding detail | Requires `findings:detail` and `payload:read` plus reason | Same | Same, within the pilot key boundary |
| Full trace | Available when the SageMaker/capture trace source exists | Degraded single-event fallback in v1 | Degraded single-event fallback from an authorized pilot finding in v1 |
| Deployment history | Out of scope for MCP v1 | Out of scope for MCP v1 | Out of scope for MCP v1 |
| Writes/classification/triage | Out of scope for MCP v1 | Out of scope for MCP v1 | Out of scope for MCP v1 |

Every response is expected to preserve runtime honesty through `runtime`, `deployment_kind`, `opsSource.kind` or `source_refs.ops_source_kind`, `capabilities`, `generated_at`, `freshness` when applicable, and `warnings`.

Every firewall-scoped response also carries a non-sensitive `data_scope` attestation. The MCP proxy requires that attestation and rejects a managed-pilot response whose tenant does not match the authenticated MCP tenant. Scope IDs, API-key IDs, physical deployment IDs, and AWS resource identifiers are not exposed by that attestation.

Self-hosted trace fallback is not a synthetic full trace. It is a single event reconstructed from the authorized finding payload and must include degraded diagnostics.

Suspicious-user bot-farming correlation is a prioritization layer, not a new alert source. Missing planned signals such as JA4 must be represented as unavailable diagnostics by `firewall-ui`; the MCP server forwards that shape without synthesizing scores. Suspicious score and bot-farming score fields are exposed as 0-100 percentages with explicit `_percent` names.
