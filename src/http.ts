import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { readConfig, type ServerConfig } from './config';
import {
  getFirewallMcpPublicConfig,
  type FirewallMcpPublicConfig,
} from './firewall-ui-config';
import { wwwAuthenticateHeader } from './oauth-metadata';
import { createFirewallMcpServer } from './server';

const CORS_ALLOW_HEADERS = [
  'authorization',
  'content-type',
  'last-event-id',
  'mcp-session-id',
  'mcp-protocol-version',
].join(', ');

const CORS_EXPOSE_HEADERS = [
  'mcp-session-id',
  'mcp-protocol-version',
  'www-authenticate',
].join(', ');

function json(
  status: number,
  code: string,
  message: string,
  origin: string | null,
  headers?: HeadersInit,
): Response {
  return withCors(new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...(headers ?? {}),
    },
  }), origin);
}

function withCors(response: Response, origin: string | null): Response {
  const headers = new Headers(response.headers);
  if (origin) headers.set('access-control-allow-origin', origin);
  headers.set('access-control-allow-methods', 'GET, POST, DELETE, OPTIONS');
  headers.set('access-control-allow-headers', CORS_ALLOW_HEADERS);
  headers.set('access-control-expose-headers', CORS_EXPOSE_HEADERS);
  headers.set('vary', 'Origin');
  headers.set('cache-control', 'no-store');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function allowedOrigin(req: Request, config: ServerConfig): { ok: true; origin: string | null } | { ok: false; origin: string | null } {
  const origin = req.headers.get('origin');
  if (!origin) return { ok: true, origin: null };
  return { ok: config.allowedOrigins.includes(origin), origin };
}

function bearerToken(req: Request): string | null {
  const header = req.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || null;
}

function authInfo(token: string, publicConfig: FirewallMcpPublicConfig): AuthInfo {
  const info: AuthInfo = {
    token,
    clientId: 'auth0-user-oauth',
    scopes: [],
  };
  try {
    info.resource = new URL(publicConfig.resource || publicConfig.audience);
  } catch {
    // firewall-ui owns audience validation; malformed upstream config should not leak into logs.
  }
  return info;
}

export async function handleMcpRequest(req: Request): Promise<Response> {
  const config = readConfig();
  const origin = allowedOrigin(req, config);
  if (!origin.ok) {
    return json(403, 'origin_forbidden', 'Origin is not allowed for this MCP server.', origin.origin);
  }

  if (req.method === 'OPTIONS') {
    return withCors(new Response(null, { status: 204 }), origin.origin);
  }

  const token = bearerToken(req);
  if (!token) {
    return json(401, 'token_missing', 'Missing bearer token.', origin.origin, {
      'www-authenticate': wwwAuthenticateHeader(req, config),
    });
  }

  let publicConfig: FirewallMcpPublicConfig;
  try {
    publicConfig = await getFirewallMcpPublicConfig(config, req.signal);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'MCP OAuth config is unavailable.';
    return json(503, 'mcp_oauth_config_unavailable', message, origin.origin);
  }

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  const server = createFirewallMcpServer(config);
  await server.connect(transport);

  const response = await transport.handleRequest(req, {
    authInfo: authInfo(token, publicConfig),
  });
  return withCors(response, origin.origin);
}
