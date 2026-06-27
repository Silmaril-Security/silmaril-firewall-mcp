import type { ServerConfig } from './config';

export interface DetailAuditEvent {
  tool: 'get_finding' | 'get_finding_trace';
  firewallId: string;
  findingId: string;
  reason: string;
  requestId: string | number;
}

export async function auditDetailAccess(event: DetailAuditEvent, config: ServerConfig, signal?: AbortSignal) {
  if (!config.auditUrl) return;

  await fetch(config.auditUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      ...event,
      at: new Date().toISOString(),
    }),
    signal,
  }).catch(() => undefined);
}
