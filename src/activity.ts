import type { ServerConfig } from './config';

export type McpActivityOutcome = 'success' | 'error';

export interface McpActivityEvent {
  toolName: string;
  outcome: McpActivityOutcome;
  token: string;
}

const ACTIVITY_TIMEOUT_MS = 1_500;

export async function submitMcpActivity(
  event: McpActivityEvent,
  config: ServerConfig,
): Promise<void> {
  if (!config.activityEnabled || !config.activityIngestKey) return;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ACTIVITY_TIMEOUT_MS);
  try {
    await fetch(new URL('/api/mcp/v1/activity/events', `${config.firewallUiBaseUrl}/`), {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${event.token}`,
        'content-type': 'application/json',
        'x-silmaril-mcp-activity-key': config.activityIngestKey,
      },
      body: JSON.stringify({
        version: 1,
        tool_name: event.toolName,
        outcome: event.outcome,
      }),
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
    });
  } catch {
    // Activity telemetry is deliberately fail-open and never changes tool behavior.
  } finally {
    clearTimeout(timeout);
  }
}
