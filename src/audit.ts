import type { ServerConfig } from './config';

export interface DetailAuditEvent {
  tool: 'get_finding' | 'get_finding_trace';
  firewallId: string;
  findingId: string;
  reason: string;
  requestId: string | number;
}

const AUDIT_TIMEOUT_MS = 1_500;

function timeoutSignal(parent?: AbortSignal): AbortSignal {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), AUDIT_TIMEOUT_MS);
  const abort = () => {
    clearTimeout(timeout);
    controller.abort();
  };
  if (parent?.aborted) abort();
  else parent?.addEventListener('abort', abort, { once: true });
  controller.signal.addEventListener('abort', () => clearTimeout(timeout), { once: true });
  return controller.signal;
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
    signal: timeoutSignal(signal),
  }).catch(() => undefined);
}
