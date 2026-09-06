import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { z } from 'zod';
import { readConfig, type ServerConfig } from './config';
import {
  type McpResourceKind,
  wwwAuthenticateHeader,
} from './oauth-metadata';
import { createFirewallMcpServer } from './server';
import { assertAdminAccess, createAdminMcpServer } from './admin-server';
import { submitMcpActivity } from './activity';
import { FirewallApiError, firewallGetJson } from './firewall-ui-client';
import {
  McpCredentialError,
  validateMcpAccessToken,
  type McpCredential,
} from './oauth-credentials';
import { consumeRateLimit } from './rate-limit';
import { decodeUtf8, readBoundedBody } from './bounded-body';

export type DeferActivity = (task: () => Promise<void>) => void;

export interface McpRequestOptions {
  mode?: 'public' | 'admin';
  defer?: DeferActivity;
}

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

const TOOL_SCOPES: Record<string, readonly string[]> = {
  list_firewalls: ['firewalls:read'],
  get_firewall: ['firewalls:read'],
  get_schema: ['firewalls:read'],
  get_metrics: ['metrics:read'],
  list_findings: ['findings:read'],
  list_suspicious_users: ['findings:read'],
  get_finding_totals: ['findings:read'],
  group_findings: ['findings:read'],
  get_investigation_packet: ['findings:read'],
  get_finding: ['findings:detail', 'payload:read'],
  get_finding_trace: ['trace:read'],
  search_conversations: ['conversations:read'],
  get_conversation: ['trace:read'],
  list_conversation_topics: ['conversations:read'],
  get_conversation_topic: ['conversations:read'],
  get_mcp_adoption_summary: ['firewalls:read'],
  list_mcp_activity: ['firewalls:read'],
};

const TOOL_COSTS: Record<string, number> = {
  list_suspicious_users: 5,
  group_findings: 3,
  get_investigation_packet: 2,
  get_finding: 2,
  get_finding_trace: 2,
  search_conversations: 3,
  get_conversation: 3,
  list_conversation_topics: 2,
  get_conversation_topic: 2,
};

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

const PrincipalSchema = z.object({
  subject: z.string().trim().min(1),
  organization_id: z.string().trim().min(1),
  tenant: z.string().trim().min(1),
  is_admin: z.boolean(),
});

type VerifiedPrincipal = z.infer<typeof PrincipalSchema>;

function authInfo(
  token: string,
  credential: McpCredential,
  principal?: VerifiedPrincipal,
): AuthInfo {
  return {
    token,
    clientId: credential.client_id,
    scopes: credential.scopes,
    expiresAt: credential.exp,
    resource: new URL(credential.resource),
    extra: {
      downstreamToken: credential.downstream_token,
      subject: credential.subject,
      organization: principal?.organization_id ?? credential.organization,
      tenant: principal?.tenant ?? credential.tenant,
      isAdmin: principal?.is_admin ?? false,
      actorEmail: credential.actor_email,
      tokenId: credential.token_id,
    },
  };
}

async function readBoundedMcpBody(
  req: Request,
  config: ServerConfig,
): Promise<{ request: Request; message: unknown } | Response> {
  const contentType = req.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    return json(415, 'unsupported_media_type', 'MCP POST requests require application/json.', req.headers.get('origin'));
  }
  const contentLength = Number(req.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > config.maxRequestBytes) {
    return json(413, 'request_too_large', 'MCP request exceeded the request size cap.', req.headers.get('origin'));
  }
  let body: Uint8Array;
  try {
    body = await readBoundedBody(
      req.body,
      config.maxRequestBytes,
      'MCP request exceeded the request size cap.',
    );
  } catch {
    return json(413, 'request_too_large', 'MCP request exceeded the request size cap.', req.headers.get('origin'));
  }
  let message: unknown;
  try {
    message = JSON.parse(decodeUtf8(body));
  } catch {
    return json(400, 'invalid_json', 'MCP request body is not valid JSON.', req.headers.get('origin'));
  }
  if (Array.isArray(message)) {
    return json(400, 'batch_not_supported', 'JSON-RPC batching is not supported by MCP Streamable HTTP.', req.headers.get('origin'));
  }
  const transportBody = new ArrayBuffer(body.byteLength);
  new Uint8Array(transportBody).set(body);
  return {
    message,
    request: new Request(req, {
      body: transportBody,
      signal: req.signal,
    }),
  };
}

function requiredScopes(message: unknown): readonly string[] {
  if (!message || typeof message !== 'object') return [];
  const record = message as { method?: unknown; params?: { name?: unknown } };
  if (record.method !== 'tools/call' || typeof record.params?.name !== 'string') return [];
  return TOOL_SCOPES[record.params.name] ?? [];
}

function requestCost(message: unknown): number {
  if (!message || typeof message !== 'object') return 1;
  const record = message as { method?: unknown; params?: { name?: unknown } };
  if (record.method !== 'tools/call' || typeof record.params?.name !== 'string') return 1;
  return TOOL_COSTS[record.params.name] ?? 1;
}

async function assertPublicAccess(
  credential: McpCredential,
  config: ServerConfig,
  signal?: AbortSignal,
): Promise<VerifiedPrincipal | undefined> {
  const payload = await firewallGetJson<unknown>({
    path: '/api/mcp/v1/schema',
    token: credential.downstream_token,
    config,
    signal,
  });
  const parsed = z.object({ principal: PrincipalSchema.optional() }).safeParse(payload);
  if (!parsed.success) {
    throw new FirewallApiError(
      502,
      'upstream_scope_unverified',
      'firewall-ui response did not include a valid authenticated principal.',
    );
  }
  const principal = parsed.data.principal;
  // Older firewall-ui versions do not attest a principal. Preserve tenant-only
  // checks in that case; never infer global admin authority from client input.
  if (!principal) return undefined;
  if (
    principal.subject !== credential.subject
    || (credential.organization !== undefined && principal.organization_id !== credential.organization)
    || (credential.tenant !== undefined && principal.tenant !== credential.tenant)
  ) {
    throw new FirewallApiError(
      502,
      'upstream_scope_mismatch',
      'firewall-ui authenticated principal did not match the MCP credential.',
    );
  }
  return principal;
}

export async function handleMcpRequest(
  req: Request,
  options: McpRequestOptions = {},
): Promise<Response> {
  const config = readConfig();
  const mode: McpResourceKind = options.mode ?? 'public';
  const origin = allowedOrigin(req, config);
  if (!origin.ok) {
    return json(403, 'origin_forbidden', 'Origin is not allowed for this MCP server.', origin.origin);
  }

  if (req.method === 'OPTIONS') {
    return withCors(new Response(null, { status: 204 }), origin.origin);
  }

  const token = bearerToken(req);
  if (!token) {
    let challenge: string;
    try {
      challenge = wwwAuthenticateHeader(config, mode);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'MCP OAuth metadata is unavailable.';
      return json(503, 'mcp_oauth_metadata_unavailable', message, origin.origin);
    }

    return json(401, 'token_missing', 'Missing bearer token.', origin.origin, {
      'www-authenticate': challenge,
    });
  }

  let credential: McpCredential;
  try {
    credential = validateMcpAccessToken(token, mode, config);
  } catch (err) {
    const message = err instanceof McpCredentialError
      ? err.message
      : 'Bearer token validation is unavailable.';
    const status = err instanceof McpCredentialError ? 401 : 503;
    return json(status, status === 401 ? 'token_invalid' : 'token_validation_unavailable', message, origin.origin, status === 401 ? {
      'www-authenticate': wwwAuthenticateHeader(config, mode, 'invalid_token'),
    } : undefined);
  }

  let transportRequest = req;
  let message: unknown = null;
  if (req.method === 'POST') {
    const parsed = await readBoundedMcpBody(req, config);
    if (parsed instanceof Response) return parsed;
    transportRequest = parsed.request;
    message = parsed.message;
  }

  const rateKey = `${mode}:${credential.client_id}:${credential.subject}`;
  const rateLimit = consumeRateLimit(rateKey, config, requestCost(message));
  if (!rateLimit.allowed) {
    return json(429, 'rate_limit_exceeded', 'MCP request quota exceeded.', origin.origin, {
      'retry-after': String(rateLimit.retryAfterSeconds),
    });
  }

  const scopes = requiredScopes(message);
  const missingScopes = scopes.filter((scope) => !credential.scopes.includes(scope));
  if (missingScopes.length > 0) {
    return json(403, 'insufficient_scope', `Required scope: ${missingScopes.join(' ')}.`, origin.origin, {
      'www-authenticate': wwwAuthenticateHeader(config, mode, 'insufficient_scope', scopes),
    });
  }

  let principal: VerifiedPrincipal | undefined;
  if (mode === 'admin') {
    try {
      await assertAdminAccess(credential.downstream_token, config, req.signal);
    } catch (err) {
      if (err instanceof FirewallApiError) {
        return json(err.status, err.code, err.message, origin.origin);
      }
      return json(503, 'mcp_admin_access_unavailable', 'MCP admin authorization is unavailable.', origin.origin);
    }
  } else {
    try {
      principal = await assertPublicAccess(credential, config, req.signal);
    } catch (err) {
      if (err instanceof FirewallApiError) {
        const headers = err.status === 401 ? {
          'www-authenticate': wwwAuthenticateHeader(config, mode, 'invalid_token'),
        } : undefined;
        return json(err.status, err.code, err.message, origin.origin, headers);
      }
      return json(503, 'mcp_access_validation_unavailable', 'MCP access validation is unavailable.', origin.origin);
    }
  }

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  const server = mode === 'admin'
    ? createAdminMcpServer(config)
    : createFirewallMcpServer(config, (event) => {
      if (!config.activityEnabled || !options.defer) return;
      options.defer(() => submitMcpActivity(event, config));
    });
  await server.connect(transport);

  const response = await transport.handleRequest(transportRequest, {
    authInfo: authInfo(token, credential, principal),
  });
  return withCors(response, origin.origin);
}
