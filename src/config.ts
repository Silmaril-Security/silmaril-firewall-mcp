export interface ServerConfig {
  firewallUiBaseUrl: string;
  publicBaseUrl: string | null;
  auth0Organization: string | null;
  allowedOrigins: string[];
  maxResponseBytes: number;
  auditUrl: string | null;
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

export function readConfig(): ServerConfig {
  return {
    firewallUiBaseUrl: requiredUrlEnv('FIREWALL_UI_BASE_URL'),
    publicBaseUrl: optionalBaseUrl(process.env.MCP_PUBLIC_BASE_URL),
    auth0Organization: process.env.MCP_AUTH0_ORGANIZATION?.trim() || null,
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
  };
}
