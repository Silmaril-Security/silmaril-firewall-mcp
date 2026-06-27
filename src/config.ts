export interface ServerConfig {
  firewallUiBaseUrl: string;
  allowedOrigins: string[];
  maxResponseBytes: number;
  mcpAudience: string | null;
  auditUrl: string | null;
}

function splitList(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function numberEnv(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function readConfig(): ServerConfig {
  return {
    firewallUiBaseUrl: process.env.FIREWALL_UI_BASE_URL?.trim() || 'http://localhost:3000',
    allowedOrigins: splitList(process.env.MCP_ALLOWED_ORIGINS),
    maxResponseBytes: numberEnv(process.env.MCP_MAX_RESPONSE_BYTES, 1_000_000),
    mcpAudience: process.env.AUTH0_MCP_AUDIENCE?.trim() || null,
    auditUrl: process.env.MCP_AUDIT_URL?.trim() || null,
  };
}
