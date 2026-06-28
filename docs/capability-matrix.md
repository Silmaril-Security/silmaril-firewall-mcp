# Runtime Capability Matrix

| Capability | SageMaker Tenant | Self-Hosted ECS Tenant |
| --- | --- | --- |
| Firewall inventory | Available via `firewall-ui` deployment registry | Available via `firewall-ui` deployment registry |
| Metrics | SageMaker and CloudWatch endpoint metrics through `firewall-ui` | ECS/service metrics through `firewall-ui` ops source |
| Findings search | Aurora findings table derived from envKey | Aurora findings table override from deployment registry |
| Findings totals/groups | Aurora aggregate queries | Aurora aggregate queries against override table |
| Investigation packet | Full compact packet with runtime metadata and trace availability | Full compact packet with degraded trace availability metadata |
| Full finding detail | Requires `findings:detail` and `payload:read` plus reason | Same |
| Full trace | Available when the SageMaker/capture trace source exists | Degraded single-event fallback in v1 |
| Deployment history | Out of scope for MCP v1 | Out of scope for MCP v1 |
| Writes/classification/triage | Out of scope for MCP v1 | Out of scope for MCP v1 |

Every response is expected to preserve runtime honesty through `runtime`, `deployment_kind`, `opsSource.kind` or `source_refs.ops_source_kind`, `capabilities`, `generated_at`, `freshness` when applicable, and `warnings`.

Self-hosted trace fallback is not a synthetic full trace. It is a single event reconstructed from the authorized finding payload and must include degraded diagnostics.
