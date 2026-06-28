import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
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
const BRIDGE_STATE_MAX_AGE_MS = 10 * 60_000;
const BRIDGE_CODE_MAX_AGE_MS = 10 * 60_000;
const SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token'];
const SUPPORTED_RESPONSE_TYPES = ['code'];
const SUPPORTED_TOKEN_ENDPOINT_AUTH_METHOD = 'none';
const SUPPORTED_CODE_CHALLENGE_METHODS = ['S256'];

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
  client_id: z.string().min(1),
  code_challenge: z.string().min(1),
  code_challenge_method: z.literal('S256'),
  iat: z.number().int().nonnegative(),
  nonce: z.string().min(1),
  state: z.string().optional(),
});

const BridgeCodeSchema = z.object({
  v: z.literal(BRIDGE_STATE_VERSION),
  code: z.string().min(1),
  redirect_uri: z.string().url(),
  client_id: z.string().min(1),
  code_challenge: z.string().min(1),
  code_challenge_method: z.literal('S256'),
  iat: z.number().int().nonnegative(),
  nonce: z.string().min(1),
});

type UpstreamAuthorizationServerMetadata = z.infer<typeof UpstreamAuthorizationServerMetadataSchema>;
type ClientRegistrationRequest = z.infer<typeof ClientRegistrationRequestSchema>;
type BridgeState = z.infer<typeof BridgeStateSchema>;
type BridgeCode = z.infer<typeof BridgeCodeSchema>;

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

function invalidClientMetadata(description: string): Response {
  return json({
    error: 'invalid_client_metadata',
    error_description: description,
  }, { status: 400 });
}

function unsupportedRegistrationValues(
  field: string,
  values: string[] | undefined,
  supported: string[],
): Response | null {
  if (!values) return null;
  if (values.length === 0 || values.some((value) => !supported.includes(value))) {
    return invalidClientMetadata(`${field} must only include ${supported.join(', ')}.`);
  }
  return null;
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

function stateSigningSecret(config: ServerConfig): string {
  if (!config.oauthStateSecret) {
    throw new Error('MCP_OAUTH_STATE_SECRET is required for OAuth bridge state signing.');
  }
  return config.oauthStateSecret;
}

function signStatePayload(payload: string, config: ServerConfig): string {
  return createHmac('sha256', stateSigningSecret(config))
    .update(payload)
    .digest('base64url');
}

function safeEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  return aBuffer.length === bBuffer.length && timingSafeEqual(aBuffer, bBuffer);
}

function encodeBridgeState(state: BridgeState, config: ServerConfig): string {
  const payload = Buffer.from(JSON.stringify(state), 'utf8').toString('base64url');
  return `${payload}.${signStatePayload(payload, config)}`;
}

function decodeBridgeState(value: string | null, config: ServerConfig): BridgeState {
  if (!value) throw new Error('Missing OAuth bridge state.');
  try {
    const [payload, signature, extra] = value.split('.');
    if (!payload || !signature || extra !== undefined) throw new Error('Malformed OAuth bridge state.');
    if (!safeEqual(signature, signStatePayload(payload, config))) {
      throw new Error('Invalid OAuth bridge state signature.');
    }
    const state = BridgeStateSchema.parse(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')));
    if (Date.now() - state.iat > BRIDGE_STATE_MAX_AGE_MS) {
      throw new Error('Expired OAuth bridge state.');
    }
    return state;
  } catch {
    throw new Error('Invalid OAuth bridge state.');
  }
}

function encodeBridgeCode(code: BridgeCode, config: ServerConfig): string {
  const payload = Buffer.from(JSON.stringify(code), 'utf8').toString('base64url');
  return `${payload}.${signStatePayload(payload, config)}`;
}

function decodeBridgeCode(value: string, config: ServerConfig): BridgeCode {
  try {
    const [payload, signature, extra] = value.split('.');
    if (!payload || !signature || extra !== undefined) throw new Error('Malformed OAuth bridge code.');
    if (!safeEqual(signature, signStatePayload(payload, config))) {
      throw new Error('Invalid OAuth bridge code signature.');
    }
    const code = BridgeCodeSchema.parse(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')));
    if (Date.now() - code.iat > BRIDGE_CODE_MAX_AGE_MS) {
      throw new Error('Expired OAuth bridge code.');
    }
    return code;
  } catch {
    throw new Error('Invalid OAuth bridge code.');
  }
}

function s256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
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
        SUPPORTED_RESPONSE_TYPES,
      ),
      grant_types_supported: valuesOrFallback(
        upstreamMetadata.grant_types_supported?.filter((item) =>
          item === 'authorization_code' || item === 'refresh_token'),
        SUPPORTED_GRANT_TYPES,
      ),
      token_endpoint_auth_methods_supported: [SUPPORTED_TOKEN_ENDPOINT_AUTH_METHOD],
      code_challenge_methods_supported: valuesOrFallback(
        upstreamMetadata.code_challenge_methods_supported?.filter((item) =>
          SUPPORTED_CODE_CHALLENGE_METHODS.includes(item)),
        SUPPORTED_CODE_CHALLENGE_METHODS,
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
  const requestedClientId = url.searchParams.get('client_id');
  if (!requestedClientId) {
    return json({
      error: 'invalid_request',
      error_description: 'client_id is required.',
    }, { status: 400 });
  }

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

  const codeChallenge = url.searchParams.get('code_challenge');
  if (!codeChallenge || url.searchParams.get('code_challenge_method') !== 'S256') {
    return json({
      error: 'invalid_request',
      error_description: 'S256 PKCE is required for authorization code flow.',
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
    if (requestedClientId !== clientId) {
      return json({
        error: 'invalid_request',
        error_description: 'client_id must match the registered MCP OAuth client.',
      }, { status: 400 });
    }

    const bridgeState = encodeBridgeState({
      v: BRIDGE_STATE_VERSION,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      iat: Date.now(),
      nonce: randomUUID(),
      state: url.searchParams.get('state') ?? undefined,
    }, config);
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

export async function handleOAuthCallbackRequest(
  req: Request,
  config: ServerConfig,
): Promise<Response> {
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
    bridgeState = decodeBridgeState(url.searchParams.get('state'), config);
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
  for (const name of ['error', 'error_description', 'error_uri']) {
    appendIfPresent(callbackUrl.searchParams, url.searchParams, name);
  }
  const code = url.searchParams.get('code');
  if (code) {
    callbackUrl.searchParams.set('code', encodeBridgeCode({
      v: BRIDGE_STATE_VERSION,
      code,
      redirect_uri: bridgeState.redirect_uri,
      client_id: bridgeState.client_id,
      code_challenge: bridgeState.code_challenge,
      code_challenge_method: 'S256',
      iat: Date.now(),
      nonce: randomUUID(),
    }, config));
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
    const requestedClientId = params.get('client_id');
    const grantType = params.get('grant_type');
    const upstreamParams = new URLSearchParams();
    upstreamParams.set('client_id', clientId);

    if (grantType === 'authorization_code') {
      if (requestedClientId !== clientId) {
        return json({
          error: 'invalid_client',
          error_description: 'client_id must match the registered MCP OAuth client.',
        }, { status: 400 });
      }
      const code = params.get('code');
      if (!code) {
        return json({
          error: 'invalid_request',
          error_description: 'authorization_code grant requires code.',
        }, { status: 400 });
      }
      const codeVerifier = params.get('code_verifier');
      if (!codeVerifier) {
        return json({
          error: 'invalid_request',
          error_description: 'authorization_code grant requires code_verifier.',
        }, { status: 400 });
      }
      const redirectUri = params.get('redirect_uri');
      if (!redirectUri || !isLoopbackRedirectUri(redirectUri)) {
        return json({
          error: 'invalid_request',
          error_description: 'authorization_code grant requires the original loopback redirect_uri.',
        }, { status: 400 });
      }
      let bridgeCode: BridgeCode;
      try {
        bridgeCode = decodeBridgeCode(code, config);
      } catch {
        return json({
          error: 'invalid_grant',
          error_description: 'authorization code is invalid or expired.',
        }, { status: 400 });
      }
      if (bridgeCode.client_id !== requestedClientId || bridgeCode.redirect_uri !== redirectUri) {
        return json({
          error: 'invalid_grant',
          error_description: 'authorization code is not bound to this client or redirect_uri.',
        }, { status: 400 });
      }
      if (!safeEqual(s256Challenge(codeVerifier), bridgeCode.code_challenge)) {
        return json({
          error: 'invalid_grant',
          error_description: 'code_verifier does not match the authorization request.',
        }, { status: 400 });
      }
      upstreamParams.set('grant_type', 'authorization_code');
      upstreamParams.set('code', bridgeCode.code);
      upstreamParams.set('redirect_uri', bridgeCallbackUrl(config));
      upstreamParams.set('code_verifier', codeVerifier);
    } else if (grantType === 'refresh_token') {
      if (requestedClientId && requestedClientId !== clientId) {
        return json({
          error: 'invalid_client',
          error_description: 'client_id must match the registered MCP OAuth client.',
        }, { status: 400 });
      }
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

    if (registration.redirect_uris?.some((uri) => !isLoopbackRedirectUri(uri))) {
      return invalidClientMetadata('redirect_uris must be loopback callback URLs.');
    }

    const grantTypesError = unsupportedRegistrationValues(
      'grant_types',
      registration.grant_types,
      SUPPORTED_GRANT_TYPES,
    );
    if (grantTypesError) return grantTypesError;

    const responseTypesError = unsupportedRegistrationValues(
      'response_types',
      registration.response_types,
      SUPPORTED_RESPONSE_TYPES,
    );
    if (responseTypesError) return responseTypesError;

    if (
      registration.token_endpoint_auth_method &&
      registration.token_endpoint_auth_method !== SUPPORTED_TOKEN_ENDPOINT_AUTH_METHOD
    ) {
      return invalidClientMetadata('token_endpoint_auth_method must be none.');
    }

    return json({
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: registration.redirect_uris ?? [],
      grant_types: registration.grant_types ?? [...SUPPORTED_GRANT_TYPES],
      response_types: registration.response_types ?? [...SUPPORTED_RESPONSE_TYPES],
      token_endpoint_auth_method: SUPPORTED_TOKEN_ENDPOINT_AUTH_METHOD,
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
