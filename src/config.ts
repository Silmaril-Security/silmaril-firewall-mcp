export interface ServerConfig {
  firewallUiBaseUrl: string;
  publicBaseUrl: string | null;
  auth0Organization: string | null;
  oauthStateSecret: string | null;
  allowedOrigins: string[];
  maxRequestBytes: number;
  maxResponseBytes: number;
  upstreamTimeoutMs: number;
  publicConfigCacheMs: number;
  rateLimitRequestsPerSecond: number;
  rateLimitBurst: number;
  auditUrl: string | null;
  auditTimeoutMs: number;
  deploymentVersion: string;
  activityEnabled: boolean;
  activityIngestKey: string | null;
}

const DEFAULT_MAX_REQUEST_BYTES = 256_000;
const HARD_MAX_REQUEST_BYTES = 1_000_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_000_000;
const HARD_MAX_RESPONSE_BYTES = 5_000_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 10_000;
const HARD_MAX_UPSTREAM_TIMEOUT_MS = 30_000;
const DEFAULT_PUBLIC_CONFIG_CACHE_MS = 30_000;
const HARD_MAX_PUBLIC_CONFIG_CACHE_MS = 300_000;
const DEFAULT_RATE_LIMIT_REQUESTS_PER_SECOND = 5;
const HARD_MAX_RATE_LIMIT_REQUESTS_PER_SECOND = 20;
const DEFAULT_RATE_LIMIT_BURST = 10;
const HARD_MAX_RATE_LIMIT_BURST = 100;
const DEFAULT_AUDIT_TIMEOUT_MS = 3_000;
const HARD_MAX_AUDIT_TIMEOUT_MS = 10_000;
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

function deploymentVersion(): string {
  return (
    process.env.VERCEL_GIT_COMMIT_SHA?.trim() ||
    process.env.GIT_COMMIT_SHA?.trim() ||
    process.env.npm_package_version?.trim() ||
    'unknown'
  );
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
    maxRequestBytes: numberEnv(
      process.env.MCP_MAX_REQUEST_BYTES,
      DEFAULT_MAX_REQUEST_BYTES,
      HARD_MAX_REQUEST_BYTES,
    ),
    maxResponseBytes: numberEnv(
      process.env.MCP_MAX_RESPONSE_BYTES,
      DEFAULT_MAX_RESPONSE_BYTES,
      HARD_MAX_RESPONSE_BYTES,
    ),
    upstreamTimeoutMs: numberEnv(
      process.env.MCP_UPSTREAM_TIMEOUT_MS,
      DEFAULT_UPSTREAM_TIMEOUT_MS,
      HARD_MAX_UPSTREAM_TIMEOUT_MS,
    ),
    publicConfigCacheMs: numberEnv(
      process.env.MCP_PUBLIC_CONFIG_CACHE_MS,
      DEFAULT_PUBLIC_CONFIG_CACHE_MS,
      HARD_MAX_PUBLIC_CONFIG_CACHE_MS,
    ),
    rateLimitRequestsPerSecond: numberEnv(
      process.env.MCP_RATE_LIMIT_REQUESTS_PER_SECOND,
      DEFAULT_RATE_LIMIT_REQUESTS_PER_SECOND,
      HARD_MAX_RATE_LIMIT_REQUESTS_PER_SECOND,
    ),
    rateLimitBurst: numberEnv(
      process.env.MCP_RATE_LIMIT_BURST,
      DEFAULT_RATE_LIMIT_BURST,
      HARD_MAX_RATE_LIMIT_BURST,
    ),
    auditUrl: process.env.MCP_AUDIT_URL?.trim() || null,
    auditTimeoutMs: numberEnv(
      process.env.MCP_AUDIT_TIMEOUT_MS,
      DEFAULT_AUDIT_TIMEOUT_MS,
      HARD_MAX_AUDIT_TIMEOUT_MS,
    ),
    deploymentVersion: deploymentVersion(),
    activityEnabled,
    activityIngestKey,
  };
}
