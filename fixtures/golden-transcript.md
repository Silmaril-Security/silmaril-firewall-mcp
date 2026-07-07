# Golden MCP Transcript

This transcript is intentionally compact and uses fixture IDs. Full payload text is omitted unless a detail tool is explicitly called with a reason.

```txt
client -> initialize
server -> instructions:
  Read-only tenant-scoped evidence interface. Prefer aggregate, metrics, and search tools before full payloads or traces.

client -> tools/list
server -> tools:
  list_firewalls
  get_firewall
  get_schema
  get_metrics
  list_findings
  list_suspicious_users
  get_finding_totals
  group_findings
  get_investigation_packet
  get_finding
  get_finding_trace

client -> tools/call list_firewalls {}
server -> structuredContent.items[0]:
  firewall_id: yc-prod-us-west-2
  runtime: sagemaker
  capabilities.trace.state: available
  generated_at: 2026-06-27T00:00:00.000Z

client -> tools/call get_investigation_packet {
  firewall_id: "yc-prod-us-west-2",
  finding_id: "qa-find-001"
}
server -> structuredContent:
  finding.evidence_id: yc-prod-us-west-2:qa-find-001
  finding.text_preview: <redacted preview>
  trace_capability.state: available
  detail_minimization.payload_opened: false
  detail_minimization.trace_opened: false

client -> tools/call list_suspicious_users {
  firewall_id: "clickup-alpha-us-west-2",
  range: "30d",
  categories: ["model_distillation", "nsfw_content_abuse"],
  limit: 10
}
server -> structuredContent.users[0]:
  user_id: <metadata user id>
  user_id_kind: metadata.userId
  primary_abuse_category: model_distillation
  abuse_category_counts.model_distillation: <count>
  abuse_category_counts.nsfw_content_abuse: <count>
  suspicious_score_percent: <0-100 user priority score>
  top_finding_score_percent: <0-100 highest finding score>
  findings.suspicious: <count>
  bot_farming.score_percent: <0-100 available-signal score>
  bot_farming.max_possible_score_percent: <0-100 all-planned-signal score>
  bot_farming.signals.shared_ja4_fingerprint.available: false
  bot_farming.signals.shared_ja4_fingerprint.score_percent: null
  evidence_handles[0].evidence_id: <firewall_id>:<finding_id>
  evidence_handles[0].finding_score_percent: <0-100 finding score>

client -> tools/call get_finding {
  firewall_id: "yc-prod-us-west-2",
  finding_id: "qa-find-001",
  reason: "Preview evidence is insufficient for incident report citation."
}
server -> structuredContent:
  access.reason: Preview evidence is insufficient for incident report citation.
  finding.evidence_id: yc-prod-us-west-2:qa-find-001
  finding.text: <full authorized payload>
```

For self-hosted tenants without multi-event trace source:

```txt
client -> tools/call get_finding_trace {
  firewall_id: "yc-litellm-alpha-us-west-2",
  finding_id: "qa-find-001",
  reason: "Need to confirm trace availability for readiness review."
}
server -> structuredContent:
  trace_completeness: degraded
  trace.events.length: 1
  trace.diagnostics.export.reason: Trace reconstructed from the finding payload; multi-event trace is unavailable for self_hosted_ecs.
```
