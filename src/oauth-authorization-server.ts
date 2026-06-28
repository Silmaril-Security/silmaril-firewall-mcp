import { z } from 'zod';
import type { ServerConfig } from './config';
import {
  getFirewallMcpPublicConfig,
  type FirewallMcpPublicConfig,
} from './firewall-ui-config';
import { publicBaseUrl } from './oauth-metadata';

const MAX_REGISTRATION_BYTES = 64_000;
const MAX_TOKEN_REQUEST_BYTES = 64_000;
const BRIDGE_STATE_VERSION = 1;

const UpstreamAuthorizationServerMetadataSchema = z.object({
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  grant_types_supported: z.array(z.string()).optional(),
  response_types_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
}).passthrough();

const ClientRegistrationRequestSchema = z.object({
  redirect_uris: z.array(z.string().url()).optional(),
  grant_types: z.array(z.string().min(1)).optional(),
  response_types: z.array(z.string().min(1)).optional(),
  scope: z.string().min(1).optional(),
  client_name: z.string().min(1).optional(),
  token_endpoint_auth_method: z.string().min(1).optional(),
}).passthrough();

const BridgeStateSchema = z.object({
  v: z.literal(BRIDGE_STATE_VERSION),
  redirect_uri: z.string().url(),
  state: z.string().optional(),
});

type UpstreamAuthorizationServerMetadata = z.infer<typeof UpstreamAuthorizationServerMetadataSchema>;
type ClientRegistrationRequest = z.infer<typeof ClientRegistrationRequestSchema>;
type BridgeState = z.infer<typeof BridgeStateSchema>;

function json(payload: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(payload), {
    ...init,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...(init?.headers ?? {}),
    },
  });
}

function authorizationServerMetadataUrl(issuer: string, path: string): URL {
  return new URL(path, issuer.endsWith('/') ? issuer : `${issuer}/`);
}

async function readBoundedJson(req: Request): Promise<unknown> {
  const contentLength = req.headers.get('content-length');
  if (contentLength && Number(contentLength) > MAX_REGISTRATION_BYTES) {
    throw new Error('registration request exceeded the response size cap.');
  }

  const text = await req.text();
  if (new TextEncoder().encode(text).byteLength > MAX_REGISTRATION_BYTES) {
    throw new Error('registration request exceeded the response size cap.');
  }

  try {
    return JSON.parse(text || '{}');
  } catch {
    throw new Error('registration request returned invalid JSON.');
  }
}

async function readBoundedForm(req: Request): Promise<URLSearchParams> {
  const contentLength = req.headers.get('content-length');
  if (contentLength && Number(contentLength) > MAX_TOKEN_REQUEST_BYTES) {
    throw new Error('token request exceeded the response size cap.');
  }

  const text = await req.text();
  if (new TextEncoder().encode(text).byteLength > MAX_TOKEN_REQUEST_BYTES) {
    throw new Error('token request exceeded the response size cap.');
  }

  return new URLSearchParams(text);
}

function valuesOrFallback(values: string[] | undefined, fallback: string[]): string[] {
  return values && values.length > 0 ? values : fallback;
}

function redirect(location: URL | string): Response {
  return new Response(null, {
    status: 302,
    headers: {
      location: location.toString(),
      'cache-control': 'no-store',
    },
  });
}

function bridgeCallbackUrl(config: ServerConfig): string {
  return new URL('/oauth/callback', publicBaseUrl(config)).toString();
}

function encodeBridgeState(state: BridgeState): string {
  return Buffer.from(JSON.stringify(state), 'utf8').toString('base64url');
}

function decodeBridgeState(value: string | null): BridgeState {
  if (!value) throw new Error('Missing OAuth bridge state.');
  try {
    return BridgeStateSchema.parse(JSON.parse(Buffer.from(value, 'base64url').toString('utf8')));
  } catch {
    throw new Error('Invalid OAuth bridge state.');
  }
}

function isLoopbackRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
    return url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]';
  } catch {
    return false;
  }
}

function appendIfPresent(target: URLSearchParams, source: URLSearchParams, name: string): void {
  const value = source.get(name);
  if (value) target.set(name, value);
}

async function fetchUpstreamAuthorizationServerMetadata(
  upstream: FirewallMcpPublicConfig,
  signal?: AbortSignal,
): Promise<UpstreamAuthorizationServerMetadata> {
  const issuer = upstream.authorization_servers[0] ?? upstream.issuer;
  const candidates = [
    authorizationServerMetadataUrl(issuer, '/.well-known/oauth-authorization-server'),
    authorizationServerMetadataUrl(issuer, '/.well-known/openid-configuration'),
  ];

  let lastStatus: number | null = null;
  for (const url of candidates) {
    const response = await fetch(url, {
      method: 'GET',
      headers: { accept: 'application/json' },
      cache: 'no-store',
      signal,
    });
    lastStatus = response.status;
    if (!response.ok) continue;

    const body = await response.json();
    return UpstreamAuthorizationServerMetadataSchema.parse(body);
  }

  throw new Error(`upstream OAuth metadata returned HTTP ${lastStatus ?? 'unknown'}.`);
}

export function authorizationServerIssuer(config: ServerConfig): string {
  return publicBaseUrl(config);
}

export async function handleAuthorizationServerMetadataRequest(
  req: Request,
  config: ServerConfig,
): Promise<Response> {
  try {
    const upstream = await getFirewallMcpPublicConfig(config, req.signal);
    const upstreamMetadata = await fetchUpstreamAuthorizationServerMetadata(upstream, req.signal);
    const issuer = authorizationServerIssuer(config);

    return json({
      issuer,
      authorization_endpoint: new URL('/oauth/authorize', issuer).toString(),
      token_endpoint: new URL('/oauth/token', issuer).toString(),
      registration_endpoint: new URL('/oauth/register', issuer).toString(),
      response_types_supported: valuesOrFallback(
        upstreamMetadata.response_types_supported?.filter((item) => item === 'code'),
        ['code'],
      ),
      grant_types_supported: valuesOrFallback(
        upstreamMetadata.grant_types_supported?.filter((item) =>
          item === 'authorization_code' || item === 'refresh_token'),
        ['authorization_code', 'refresh_token'],
      ),
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: valuesOrFallback(
        upstreamMetadata.code_challenge_methods_supported,
        ['S256'],
      ),
      scopes_supported: upstream.scopes,
      silmaril_upstream_issuer: upstream.issuer,
      silmaril_upstream_authorization_servers: upstream.authorization_servers,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'MCP OAuth authorization metadata is unavailable.';
    return json({
      error: {
        code: 'mcp_oauth_authorization_metadata_unavailable',
        message,
      },
    }, { status: 503 });
  }
}

export async function handleAuthorizationRequest(
  req: Request,
  config: ServerConfig,
): Promise<Response> {
  if (req.method !== 'GET') {
    return json({
      error: 'method_not_allowed',
      error_description: 'OAuth authorization requires GET.',
    }, {
      status: 405,
      headers: { allow: 'GET' },
    });
  }

  const url = new URL(req.url);
  const redirectUri = url.searchParams.get('redirect_uri');
  if (!redirectUri || !isLoopbackRedirectUri(redirectUri)) {
    return json({
      error: 'invalid_request',
      error_description: 'redirect_uri must be a loopback callback URL.',
    }, { status: 400 });
  }

  if (url.searchParams.get('response_type') !== 'code') {
    return json({
      error: 'unsupported_response_type',
      error_description: 'Only authorization code flow is supported.',
    }, { status: 400 });
  }

  try {
    const upstream = await getFirewallMcpPublicConfig(config, req.signal);
    const upstreamMetadata = await fetchUpstreamAuthorizationServerMetadata(upstream, req.signal);
    const clientId = upstream.oauth?.client_id;
    if (!clientId) {
      return json({
        error: 'server_error',
        error_description: 'firewall-ui MCP OAuth client ID is not configured.',
      }, { status: 503 });
    }

    const bridgeState = encodeBridgeState({
      v: BRIDGE_STATE_VERSION,
      redirect_uri: redirectUri,
      state: url.searchParams.get('state') ?? undefined,
    });
    const authorizationUrl = new URL(upstreamMetadata.authorization_endpoint);
    authorizationUrl.searchParams.set('response_type', 'code');
    authorizationUrl.searchParams.set('client_id', clientId);
    authorizationUrl.searchParams.set('redirect_uri', bridgeCallbackUrl(config));
    authorizationUrl.searchParams.set('state', bridgeState);
    authorizationUrl.searchParams.set('scope', url.searchParams.get('scope') || upstream.scopes.join(' '));
    authorizationUrl.searchParams.set('audience', upstream.resource || upstream.audience);
    appendIfPresent(authorizationUrl.searchParams, url.searchParams, 'code_challenge');
    appendIfPresent(authorizationUrl.searchParams, url.searchParams, 'code_challenge_method');
    appendIfPresent(authorizationUrl.searchParams, url.searchParams, 'prompt');
    appendIfPresent(authorizationUrl.searchParams, url.searchParams, 'login_hint');
    const organization = url.searchParams.get('organization') || config.auth0Organization;
    if (organization) authorizationUrl.searchParams.set('organization', organization);

    return redirect(authorizationUrl);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'MCP OAuth authorization is unavailable.';
    return json({
      error: 'server_error',
      error_description: message,
    }, { status: 503 });
  }
}

export async function handleOAuthCallbackRequest(req: Request): Promise<Response> {
  if (req.method !== 'GET') {
    return json({
      error: 'method_not_allowed',
      error_description: 'OAuth callback requires GET.',
    }, {
      status: 405,
      headers: { allow: 'GET' },
    });
  }

  const url = new URL(req.url);
  let bridgeState: BridgeState;
  try {
    bridgeState = decodeBridgeState(url.searchParams.get('state'));
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid OAuth bridge state.';
    return json({
      error: 'invalid_request',
      error_description: message,
    }, { status: 400 });
  }

  if (!isLoopbackRedirectUri(bridgeState.redirect_uri)) {
    return json({
      error: 'invalid_request',
      error_description: 'Stored redirect_uri is not a loopback callback URL.',
    }, { status: 400 });
  }

  const callbackUrl = new URL(bridgeState.redirect_uri);
  for (const name of ['code', 'error', 'error_description', 'error_uri']) {
    appendIfPresent(callbackUrl.searchParams, url.searchParams, name);
  }
  if (bridgeState.state) callbackUrl.searchParams.set('state', bridgeState.state);

  return redirect(callbackUrl);
}

export async function handleTokenRequest(
  req: Request,
  config: ServerConfig,
): Promise<Response> {
  if (req.method !== 'POST') {
    return json({
      error: 'method_not_allowed',
      error_description: 'OAuth token exchange requires POST.',
    }, {
      status: 405,
      headers: { allow: 'POST' },
    });
  }

  let params: URLSearchParams;
  try {
    params = await readBoundedForm(req);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid token request.';
    return json({
      error: 'invalid_request',
      error_description: message,
    }, { status: 400 });
  }

  try {
    const upstream = await getFirewallMcpPublicConfig(config, req.signal);
    const upstreamMetadata = await fetchUpstreamAuthorizationServerMetadata(upstream, req.signal);
    const clientId = upstream.oauth?.client_id;
    if (!clientId) {
      return json({
        error: 'server_error',
        error_description: 'firewall-ui MCP OAuth client ID is not configured.',
      }, { status: 503 });
    }

    const grantType = params.get('grant_type');
    const upstreamParams = new URLSearchParams();
    upstreamParams.set('client_id', clientId);

    if (grantType === 'authorization_code') {
      const code = params.get('code');
      if (!code) {
        return json({
          error: 'invalid_request',
          error_description: 'authorization_code grant requires code.',
        }, { status: 400 });
      }
      upstreamParams.set('grant_type', 'authorization_code');
      upstreamParams.set('code', code);
      upstreamParams.set('redirect_uri', bridgeCallbackUrl(config));
      appendIfPresent(upstreamParams, params, 'code_verifier');
    } else if (grantType === 'refresh_token') {
      const refreshToken = params.get('refresh_token');
      if (!refreshToken) {
        return json({
          error: 'invalid_request',
          error_description: 'refresh_token grant requires refresh_token.',
        }, { status: 400 });
      }
      upstreamParams.set('grant_type', 'refresh_token');
      upstreamParams.set('refresh_token', refreshToken);
      appendIfPresent(upstreamParams, params, 'scope');
    } else {
      return json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code and refresh_token grants are supported.',
      }, { status: 400 });
    }

    const upstreamResponse = await fetch(upstreamMetadata.token_endpoint, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: upstreamParams.toString(),
      cache: 'no-store',
      signal: req.signal,
    });

    return new Response(await upstreamResponse.text(), {
      status: upstreamResponse.status,
      headers: {
        'content-type': upstreamResponse.headers.get('content-type') ?? 'application/json',
        'cache-control': 'no-store',
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'MCP OAuth token exchange is unavailable.';
    return json({
      error: 'server_error',
      error_description: message,
    }, { status: 503 });
  }
}

export async function handleClientRegistrationRequest(
  req: Request,
  config: ServerConfig,
): Promise<Response> {
  if (req.method !== 'POST') {
    return json({
      error: 'method_not_allowed',
      error_description: 'Dynamic client registration requires POST.',
    }, {
      status: 405,
      headers: { allow: 'POST' },
    });
  }

  let registration: ClientRegistrationRequest;
  try {
    registration = ClientRegistrationRequestSchema.parse(await readBoundedJson(req));
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid dynamic client registration request.';
    return json({
      error: 'invalid_client_metadata',
      error_description: message,
    }, { status: 400 });
  }

  try {
    const upstream = await getFirewallMcpPublicConfig(config, req.signal);
    const clientId = upstream.oauth?.client_id;
    if (!clientId) {
      return json({
        error: 'server_error',
        error_description: 'firewall-ui MCP OAuth client ID is not configured.',
      }, { status: 503 });
    }

    return json({
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: registration.redirect_uris ?? [],
      grant_types: registration.grant_types ?? ['authorization_code', 'refresh_token'],
      response_types: registration.response_types ?? ['code'],
      token_endpoint_auth_method: 'none',
      scope: registration.scope ?? upstream.scopes.join(' '),
      client_name: registration.client_name ?? 'Silmaril Firewall MCP Client',
    }, { status: 201 });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'MCP OAuth client registration is unavailable.';
    return json({
      error: 'server_error',
      error_description: message,
    }, { status: 503 });
  }
}
