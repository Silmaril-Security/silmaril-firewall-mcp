import { randomUUID } from 'node:crypto';
import type { ServerConfig } from './config';
import { FirewallApiError } from './firewall-ui-client';
import type { McpActorContext } from './auth-context';

export interface DetailAuditEvent {
  tool: 'get_finding' | 'get_finding_trace';
  firewallId: string;
  findingId: string;
  reason: string;
  requestId: string | number;
  outcome: 'success' | 'error';
  actor: McpActorContext;
}

export function assertSensitiveAuditConfigured(config: ServerConfig): void {
  if (!config.auditUrl) {
    throw new FirewallApiError(
      503,
      'sensitive_audit_unavailable',
      'Sensitive evidence is unavailable because durable audit is not configured.',
    );
  }
}

export async function auditDetailAccess(event: DetailAuditEvent, config: ServerConfig, signal?: AbortSignal) {
  assertSensitiveAuditConfigured(config);

  let response: Response;
  try {
    response = await fetch(config.auditUrl!, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        schema_version: 1,
        event_id: randomUUID(),
        occurred_at: new Date().toISOString(),
        actor_subject: event.actor.subject,
        actor_email: event.actor.actorEmail,
        tenant: event.actor.tenant,
        organization: event.actor.organization,
        oauth_client_id: event.actor.clientId,
        token_id: event.actor.tokenId,
        tool_name: event.tool,
        target_firewall_id: event.firewallId,
        target_finding_id: event.findingId,
        reason: event.reason,
        outcome: event.outcome,
        correlation_id: String(event.requestId),
        deployment_version: config.deploymentVersion,
      }),
      redirect: 'error',
      signal: AbortSignal.any([
        signal ?? new AbortController().signal,
        AbortSignal.timeout(config.auditTimeoutMs),
      ]),
    });
  } catch {
    throw new FirewallApiError(
      503,
      'sensitive_audit_unavailable',
      'Sensitive evidence was withheld because its audit event could not be persisted.',
    );
  }
  if (!response.ok) {
    throw new FirewallApiError(
      503,
      'sensitive_audit_unavailable',
      'Sensitive evidence was withheld because its audit event was rejected.',
    );
  }
}
