export interface ServerConfig {
  firewallUiBaseUrl: string;
  publicBaseUrl: string | null;
  auth0Organization: string | null;
  oauthStateSecret: string | null;
  allowedOrigins: string[];
  maxResponseBytes: number;
  auditUrl: string | null;
  activityEnabled: boolean;
  activityIngestKey: string | null;
}

const DEFAULT_MAX_RESPONSE_BYTES = 1_000_000;
const HARD_MAX_RESPONSE_BYTES = 5_000_000;
const DEFAULT_ALLOWED_ORIGINS = [
  'https://chatgpt.com',
  'https://chat.openai.com',
  'https://codex.openai.com',
] as const;

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

function requiredUrlEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function optionalBaseUrl(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

function unique(items: readonly string[]): string[] {
  return [...new Set(items)];
}

function booleanEnv(name: string): boolean {
  const value = process.env[name]?.trim().toLowerCase();
  if (!value || value === '0' || value === 'false') return false;
  if (value === '1' || value === 'true') return true;
  throw new Error(`${name} must be true, false, 1, or 0.`);
}

export function readConfig(): ServerConfig {
  const activityEnabled = booleanEnv('MCP_ACTIVITY_ENABLED');
  const activityIngestKey = process.env.MCP_ACTIVITY_INGEST_KEY?.trim() || null;
  if (activityEnabled && (!activityIngestKey || activityIngestKey.length < 32)) {
    throw new Error('MCP_ACTIVITY_INGEST_KEY must contain at least 32 characters when MCP_ACTIVITY_ENABLED=true.');
  }

  return {
    firewallUiBaseUrl: requiredUrlEnv('FIREWALL_UI_BASE_URL'),
    publicBaseUrl: optionalBaseUrl(process.env.MCP_PUBLIC_BASE_URL),
    auth0Organization: process.env.MCP_AUTH0_ORGANIZATION?.trim() || null,
    oauthStateSecret: process.env.MCP_OAUTH_STATE_SECRET?.trim() || null,
    allowedOrigins: unique([
      ...DEFAULT_ALLOWED_ORIGINS,
      ...splitList(process.env.MCP_ADDITIONAL_ALLOWED_ORIGINS),
      ...splitList(process.env.MCP_ALLOWED_ORIGINS),
    ]),
    maxResponseBytes: numberEnv(
      process.env.MCP_MAX_RESPONSE_BYTES,
      DEFAULT_MAX_RESPONSE_BYTES,
      HARD_MAX_RESPONSE_BYTES,
    ),
    auditUrl: process.env.MCP_AUDIT_URL?.trim() || null,
    activityEnabled,
    activityIngestKey,
  };
}
