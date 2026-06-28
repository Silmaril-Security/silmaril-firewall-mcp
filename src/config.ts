export interface ServerConfig {
  firewallUiBaseUrl: string;
  allowedOrigins: string[];
  maxResponseBytes: number;
  mcpAudience: string | null;
  auditUrl: string | null;
}

const DEFAULT_MAX_RESPONSE_BYTES = 1_000_000;
const HARD_MAX_RESPONSE_BYTES = 5_000_000;

function splitList(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function numberEnv(value: string | undefined, fallback: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), max);
}

export function readConfig(): ServerConfig {
  return {
    firewallUiBaseUrl: process.env.FIREWALL_UI_BASE_URL?.trim() || 'http://localhost:3000',
    allowedOrigins: splitList(process.env.MCP_ALLOWED_ORIGINS),
    maxResponseBytes: numberEnv(
      process.env.MCP_MAX_RESPONSE_BYTES,
      DEFAULT_MAX_RESPONSE_BYTES,
      HARD_MAX_RESPONSE_BYTES,
    ),
    mcpAudience: process.env.AUTH0_MCP_AUDIENCE?.trim() || null,
    auditUrl: process.env.MCP_AUDIT_URL?.trim() || null,
  };
}
