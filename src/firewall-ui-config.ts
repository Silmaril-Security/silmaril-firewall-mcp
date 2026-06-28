import { z } from 'zod';
import type { ServerConfig } from './config';

export const DEFAULT_AUTHORIZATION_SCOPES = [
  'firewalls:read',
  'metrics:read',
  'findings:read',
] as const;

const CACHE_MS = 60_000;
const MAX_PUBLIC_CONFIG_BYTES = 64_000;

const PublicConfigSchema = z.object({
  version: z.literal('v1'),
  enabled: z.boolean(),
  issuer: z.string().url(),
  authorization_servers: z.array(z.string().url()).min(1),
  audience: z.string().min(1),
  resource: z.string().min(1),
  scopes: z.array(z.string().min(1)).min(1),
  oauth: z.object({
    client_id: z.string().min(1).nullable(),
    client_id_source: z.string().min(1),
  }).optional(),
});

export type FirewallMcpPublicConfig = z.infer<typeof PublicConfigSchema>;

let cachedConfig:
  | { config: FirewallMcpPublicConfig; baseUrl: string; expiresAt: number }
  | null = null;

function configUrl(config: ServerConfig): URL {
  return new URL('/api/mcp/v1/config', `${config.firewallUiBaseUrl}/`);
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentLength = response.headers.get('content-length');
  if (contentLength && Number(contentLength) > MAX_PUBLIC_CONFIG_BYTES) {
    throw new Error('firewall-ui MCP config exceeded the response size cap.');
  }

  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_PUBLIC_CONFIG_BYTES) {
    throw new Error('firewall-ui MCP config exceeded the response size cap.');
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error('firewall-ui MCP config returned invalid JSON.');
  }
}

export function resetFirewallMcpConfigCacheForTests() {
  cachedConfig = null;
}

export async function getFirewallMcpPublicConfig(
  config: ServerConfig,
  signal?: AbortSignal,
): Promise<FirewallMcpPublicConfig> {
  const now = Date.now();
  if (
    cachedConfig &&
    cachedConfig.baseUrl === config.firewallUiBaseUrl &&
    cachedConfig.expiresAt > now
  ) {
    return cachedConfig.config;
  }

  const response = await fetch(configUrl(config), {
    method: 'GET',
    headers: { accept: 'application/json' },
    cache: 'no-store',
    signal,
  });

  if (!response.ok) {
    throw new Error(`firewall-ui MCP config returned HTTP ${response.status}.`);
  }

  const parsed = PublicConfigSchema.parse(await readBoundedJson(response));
  cachedConfig = {
    config: parsed,
    baseUrl: config.firewallUiBaseUrl,
    expiresAt: now + CACHE_MS,
  };
  return parsed;
}
