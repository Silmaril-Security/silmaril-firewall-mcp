import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import {
  createLocalJWKSet,
  jwtVerify,
  type JSONWebKeySet,
  type JWTVerifyOptions,
} from 'jose';
import { z } from 'zod';
import type { ServerConfig } from './config';
import {
  DEFAULT_AUTHORIZATION_SCOPES,
  getFirewallMcpPublicConfig,
  type FirewallMcpPublicConfig,
} from './firewall-ui-config';
import {
  issueMcpCredential,
  mcpResource,
  validateMcpRefreshToken,
} from './oauth-credentials';
import { publicBaseUrl } from './oauth-metadata';
import { decodeUtf8, readBoundedBody } from './bounded-body';

const MAX_REGISTRATION_BYTES = 64_000;
const MAX_TOKEN_REQUEST_BYTES = 64_000;
const MAX_UPSTREAM_TOKEN_BYTES = 64_000;
const MAX_UPSTREAM_JWKS_BYTES = 256_000;
const JWKS_CACHE_MS = 5 * 60_000;
const ARTIFACT_VERSION = 2;
const REGISTRATION_MAX_AGE_MS = 30 * 24 * 60 * 60_000;
const BRIDGE_STATE_MAX_AGE_MS = 10 * 60_000;
const BRIDGE_CODE_MAX_AGE_MS = 10 * 60_000;
const SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token'];
const SUPPORTED_RESPONSE_TYPES = ['code'];
const SUPPORTED_TOKEN_ENDPOINT_AUTH_METHOD = 'none';
const SUPPORTED_CODE_CHALLENGE_METHODS = ['S256'];
const PKCE_VALUE_RE = /^[A-Za-z0-9._~-]{43,128}$/;

const UpstreamAuthorizationServerMetadataSchema = z.object({
  issuer: z.string().url().optional(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  jwks_uri: z.string().url(),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  grant_types_supported: z.array(z.string()).optional(),
  response_types_supported: z.array(z.string()).optional(),
}).passthrough();

const ClientRegistrationRequestSchema = z.object({
  redirect_uris: z.array(z.string().max(2_048).url()).min(1).max(8),
  grant_types: z.array(z.string().min(1)).optional(),
  response_types: z.array(z.string().min(1)).optional(),
  scope: z.string().min(1).max(2_048).optional(),
  client_name: z.string().min(1).max(128).optional(),
  token_endpoint_auth_method: z.string().min(1).optional(),
}).passthrough();

const ClientRegistrationSchema = z.object({
  v: z.literal(ARTIFACT_VERSION),
  registration_id: z.string().uuid(),
  redirect_uris: z.array(z.string().url()).min(1).max(8),
  grant_types: z.array(z.string()),
  response_types: z.array(z.string()),
  scope: z.string().min(1),
  client_name: z.string().min(1),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
});

const BridgeStateSchema = z.object({
  v: z.literal(ARTIFACT_VERSION),
  redirect_uri: z.string().url(),
  client_id: z.string().min(1),
  client_name: z.string().min(1),
  code_challenge: z.string().regex(PKCE_VALUE_RE),
  code_challenge_method: z.literal('S256'),
  resource: z.string().url(),
  scope: z.string().min(1),
  organization: z.string().optional(),
  iat: z.number().int().nonnegative(),
  nonce: z.string().uuid(),
  state: z.string().max(1_024).optional(),
});

const BridgeCodeSchema = BridgeStateSchema.omit({
  client_name: true,
  organization: true,
  state: true,
}).extend({
  code: z.string().min(1),
});

const UpstreamTokenResponseSchema = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1).optional(),
  token_type: z.string().min(1).default('Bearer'),
  expires_in: z.number().int().positive().max(86_400),
  scope: z.string().optional(),
});

const UpstreamAccessClaimsSchema = z.object({
  sub: z.string().min(1),
  iss: z.string().url(),
  aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  exp: z.number().int().positive(),
  scope: z.string().optional(),
  permissions: z.array(z.string()).optional(),
  email: z.string().email().optional(),
  org_id: z.string().min(1).optional(),
  tenant: z.string().min(1).optional(),
  tenant_id: z.string().min(1).optional(),
  jti: z.string().min(1).optional(),
}).passthrough();

const JsonWebKeySetSchema = z.object({
  keys: z.array(z.record(z.string(), z.unknown())).min(1).max(32),
});

type UpstreamAuthorizationServerMetadata = z.infer<typeof UpstreamAuthorizationServerMetadataSchema>;
type ClientRegistrationRequest = z.infer<typeof ClientRegistrationRequestSchema>;
type ClientRegistration = z.infer<typeof ClientRegistrationSchema>;
type BridgeState = z.infer<typeof BridgeStateSchema>;
type BridgeCode = z.infer<typeof BridgeCodeSchema>;
type UpstreamAccessClaims = z.infer<typeof UpstreamAccessClaimsSchema>;
const jwksCache = new Map<string, { value: JSONWebKeySet; expiresAt: number }>();

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

function hasContentType(req: Request, expected: string): boolean {
  return req.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() === expected;
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

function authorizationServerMetadataUrl(issuer: string, path: string): URL {
  return new URL(path, issuer.endsWith('/') ? issuer : `${issuer}/`);
}

async function readBoundedText(req: Request, maxBytes: number, label: string): Promise<string> {
  const contentLength = Number(req.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new Error(`${label} exceeded the request size cap.`);
  }
  return decodeUtf8(await readBoundedBody(
    req.body,
    maxBytes,
    `${label} exceeded the request size cap.`,
  ));
}

async function readBoundedJson(req: Request): Promise<unknown> {
  const text = await readBoundedText(req, MAX_REGISTRATION_BYTES, 'registration request');
  try {
    return JSON.parse(text || '{}');
  } catch {
    throw new Error('registration request contained invalid JSON.');
  }
}

async function readBoundedForm(req: Request): Promise<URLSearchParams> {
  return new URLSearchParams(await readBoundedText(req, MAX_TOKEN_REQUEST_BYTES, 'OAuth request'));
}

async function readBoundedResponseJson(response: Response): Promise<unknown> {
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > MAX_UPSTREAM_TOKEN_BYTES) {
    throw new Error('upstream OAuth response exceeded the response size cap.');
  }
  const text = decodeUtf8(await readBoundedBody(
    response.body,
    MAX_UPSTREAM_TOKEN_BYTES,
    'upstream OAuth response exceeded the response size cap.',
  ));
  try {
    return JSON.parse(text || '{}');
  } catch {
    throw new Error('upstream OAuth response contained invalid JSON.');
  }
}

async function readBoundedJsonResponse(
  response: Response,
  maxBytes: number,
  label: string,
): Promise<unknown> {
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new Error(`${label} exceeded the response size cap.`);
  }
  const text = decodeUtf8(await readBoundedBody(
    response.body,
    maxBytes,
    `${label} exceeded the response size cap.`,
  ));
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} contained invalid JSON.`);
  }
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

function bridgeCallbackUrl(config: ServerConfig): string {
  return new URL('/oauth/callback', publicBaseUrl(config)).toString();
}

function signingSecret(config: ServerConfig): string {
  if (!config.oauthStateSecret || Buffer.byteLength(config.oauthStateSecret, 'utf8') < 32) {
    throw new Error('MCP_OAUTH_STATE_SECRET must contain at least 32 bytes.');
  }
  return config.oauthStateSecret;
}

function signature(payload: string, purpose: string, config: ServerConfig): string {
  return createHmac('sha256', signingSecret(config))
    .update(`${purpose}\0${payload}`)
    .digest('base64url');
}

function safeEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  return aBuffer.length === bBuffer.length && timingSafeEqual(aBuffer, bBuffer);
}

function encodeSigned(payload: unknown, purpose: string, config: ServerConfig): string {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `${purpose}.${encoded}.${signature(encoded, purpose, config)}`;
}

function decodeSigned<T>(
  value: string | null,
  purpose: string,
  schema: z.ZodType<T>,
  maxAgeMs: number,
  config: ServerConfig,
): T {
  try {
    if (!value) throw new Error('Missing signed value.');
    const [actualPurpose, encoded, actualSignature, extra] = value.split('.');
    if (actualPurpose !== purpose || !encoded || !actualSignature || extra !== undefined) {
      throw new Error('Malformed signed value.');
    }
    if (!safeEqual(actualSignature, signature(encoded, purpose, config))) {
      throw new Error('Invalid signature.');
    }
    const parsed = schema.parse(JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')));
    const issuedAt = (parsed as { iat?: unknown }).iat;
    const expiresAt = (parsed as { exp?: unknown }).exp;
    if (typeof issuedAt !== 'number' || Date.now() - issuedAt > maxAgeMs || issuedAt > Date.now() + 60_000) {
      throw new Error('Expired signed value.');
    }
    if (typeof expiresAt === 'number' && expiresAt <= Date.now()) {
      throw new Error('Expired signed value.');
    }
    return parsed;
  } catch {
    throw new Error('Invalid or expired signed OAuth value.');
  }
}

function encodeRegistration(registration: ClientRegistration, config: ServerConfig): string {
  return encodeSigned(registration, 'dcr2', config);
}

function decodeRegistration(value: string | null, config: ServerConfig): ClientRegistration {
  return decodeSigned(value, 'dcr2', ClientRegistrationSchema, REGISTRATION_MAX_AGE_MS, config);
}

function encodeBridgeState(state: BridgeState, config: ServerConfig): string {
  return encodeSigned(state, 'state2', config);
}

function decodeBridgeState(value: string | null, config: ServerConfig): BridgeState {
  return decodeSigned(value, 'state2', BridgeStateSchema, BRIDGE_STATE_MAX_AGE_MS, config);
}

function encodeBridgeCode(code: BridgeCode, config: ServerConfig): string {
  return encodeSigned(code, 'code2', config);
}

function decodeBridgeCode(value: string, config: ServerConfig): BridgeCode {
  return decodeSigned(value, 'code2', BridgeCodeSchema, BRIDGE_CODE_MAX_AGE_MS, config);
}

function s256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

function validPkceValue(value: string | null): value is string {
  return Boolean(value && PKCE_VALUE_RE.test(value));
}

function isLoopbackRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' || url.hash || url.username || url.password) return false;
    return url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]';
  } catch {
    return false;
  }
}

function scopes(value: string): string[] {
  return [...new Set(value.split(/\s+/).map((item) => item.trim()).filter(Boolean))];
}

function appendIfPresent(target: URLSearchParams, source: URLSearchParams, name: string): void {
  const value = source.get(name);
  if (value) target.set(name, value);
}

function resolveAuth0Organization(
  value: string | null,
  config: ServerConfig,
): { ok: true; organization: string | null } | { ok: false; response: Response } {
  const requested = value?.trim();
  if (!requested) {
    if (!config.auth0Organization) return { ok: true, organization: null };
    if (config.auth0Organization.startsWith('org_')) {
      return { ok: true, organization: config.auth0Organization };
    }
    return {
      ok: false,
      response: json({
        error: 'server_error',
        error_description: 'MCP_AUTH0_ORGANIZATION must be an Auth0 organization id.',
      }, { status: 503 }),
    };
  }
  if (requested.startsWith('org_')) return { ok: true, organization: requested };
  return {
    ok: false,
    response: json({
      error: 'invalid_request',
      error_description: 'organization must be an Auth0 organization id.',
    }, { status: 400 }),
  };
}

function requestSignal(config: ServerConfig, signal?: AbortSignal): AbortSignal {
  return AbortSignal.any([
    signal ?? new AbortController().signal,
    AbortSignal.timeout(config.upstreamTimeoutMs),
  ]);
}

function assertUpstreamEndpoint(value: string, issuer: string, label: string): void {
  const endpoint = new URL(value);
  const expected = new URL(issuer);
  if (endpoint.protocol !== 'https:' || endpoint.origin !== expected.origin) {
    throw new Error(`${label} must be HTTPS and share the configured issuer origin.`);
  }
}

async function fetchUpstreamAuthorizationServerMetadata(
  upstream: FirewallMcpPublicConfig,
  config: ServerConfig,
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
      redirect: 'error',
      signal: requestSignal(config, signal),
    });
    lastStatus = response.status;
    if (!response.ok) continue;
    const metadata = UpstreamAuthorizationServerMetadataSchema.parse(await response.json());
    if (
      metadata.issuer &&
      metadata.issuer.replace(/\/+$/, '') !== issuer.replace(/\/+$/, '')
    ) {
      throw new Error('upstream OAuth metadata issuer did not match the configured issuer.');
    }
    assertUpstreamEndpoint(metadata.authorization_endpoint, issuer, 'authorization_endpoint');
    assertUpstreamEndpoint(metadata.token_endpoint, issuer, 'token_endpoint');
    assertUpstreamEndpoint(metadata.jwks_uri, issuer, 'jwks_uri');
    return metadata;
  }
  throw new Error(`upstream OAuth metadata returned HTTP ${lastStatus ?? 'unknown'}.`);
}

function resourceForRequest(value: string | null, config: ServerConfig): string | null {
  const requested = value || mcpResource(config, 'public');
  const allowed = [mcpResource(config, 'public'), mcpResource(config, 'admin')];
  return allowed.includes(requested) ? requested : null;
}

function htmlEscape(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character] ?? character);
}

function consentPage(
  state: BridgeState,
  upstreamAuthorizationIssuer: string,
  config: ServerConfig,
): Response {
  const transaction = encodeBridgeState(state, config);
  const authorizationOrigin = new URL(upstreamAuthorizationIssuer).origin;
  const scopeItems = scopes(state.scope)
    .map((scope) => `<li>${htmlEscape(scope)}</li>`)
    .join('');
  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Silmaril Firewall MCP</title>
<style>body{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1.5rem;color:#171717}code{word-break:break-all}button{padding:.7rem 1rem;margin-right:.5rem}ul{line-height:1.7}</style></head>
<body><main><h1>Authorize MCP client</h1>
<p><strong>${htmlEscape(state.client_name)}</strong> is requesting access to <code>${htmlEscape(state.resource)}</code>.</p>
<ul>${scopeItems}</ul>
<p>You will authenticate with Silmaril after approving this client-specific request.</p>
<form method="post" action="${htmlEscape(new URL('/oauth/authorize', publicBaseUrl(config)).toString())}">
<input type="hidden" name="transaction" value="${htmlEscape(transaction)}">
<button type="submit" name="decision" value="approve">Approve and continue</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></main></body></html>`;
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${authorizationOrigin}; base-uri 'none'; frame-ancestors 'none'`,
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    },
  });
}

function clientErrorRedirect(state: BridgeState, error: string, description: string): Response {
  const callback = new URL(state.redirect_uri);
  callback.searchParams.set('error', error);
  callback.searchParams.set('error_description', description);
  if (state.state) callback.searchParams.set('state', state.state);
  return redirect(callback);
}

async function upstreamJwks(
  metadata: UpstreamAuthorizationServerMetadata,
  config: ServerConfig,
  signal?: AbortSignal,
): Promise<JSONWebKeySet> {
  const cached = jwksCache.get(metadata.jwks_uri);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const response = await fetch(metadata.jwks_uri, {
    method: 'GET',
    headers: { accept: 'application/json' },
    cache: 'no-store',
    redirect: 'error',
    signal: requestSignal(config, signal),
  });
  if (!response.ok) throw new Error(`upstream JWKS returned HTTP ${response.status}.`);
  const parsed = JsonWebKeySetSchema.parse(
    await readBoundedJsonResponse(response, MAX_UPSTREAM_JWKS_BYTES, 'upstream JWKS'),
  ) as JSONWebKeySet;
  jwksCache.set(metadata.jwks_uri, {
    value: parsed,
    expiresAt: Date.now() + JWKS_CACHE_MS,
  });
  return parsed;
}

async function validateUpstreamClaims(
  token: string,
  upstream: FirewallMcpPublicConfig,
  metadata: UpstreamAuthorizationServerMetadata,
  config: ServerConfig,
  signal?: AbortSignal,
): Promise<UpstreamAccessClaims> {
  const expectedIssuer = upstream.issuer.replace(/\/+$/, '');
  const options: JWTVerifyOptions = {
      issuer: [expectedIssuer, `${expectedIssuer}/`],
      audience: upstream.resource || upstream.audience,
      algorithms: ['RS256'],
  };
  let verified;
  try {
    verified = await jwtVerify(
      token,
      createLocalJWKSet(await upstreamJwks(metadata, config, signal)),
      options,
    );
  } catch {
    // A cached JWKS may straddle Auth0 key rotation. Refresh once, then fail.
    jwksCache.delete(metadata.jwks_uri);
    verified = await jwtVerify(
      token,
      createLocalJWKSet(await upstreamJwks(metadata, config, signal)),
      options,
    );
  }
  return UpstreamAccessClaimsSchema.parse(verified.payload);
}

function claimString(claims: UpstreamAccessClaims, names: string[]): string | undefined {
  for (const name of names) {
    const value = claims[name];
    if (typeof value === 'string' && value) return value;
  }
  return undefined;
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
    const metadata = await fetchUpstreamAuthorizationServerMetadata(upstream, config, req.signal);
    const issuer = authorizationServerIssuer(config);
    return json({
      issuer,
      authorization_endpoint: new URL('/oauth/authorize', issuer).toString(),
      token_endpoint: new URL('/oauth/token', issuer).toString(),
      registration_endpoint: new URL('/oauth/register', issuer).toString(),
      response_types_supported: valuesOrFallback(
        metadata.response_types_supported?.filter((item) => item === 'code'),
        SUPPORTED_RESPONSE_TYPES,
      ),
      grant_types_supported: valuesOrFallback(
        metadata.grant_types_supported?.filter((item) => SUPPORTED_GRANT_TYPES.includes(item)),
        SUPPORTED_GRANT_TYPES,
      ),
      token_endpoint_auth_methods_supported: [SUPPORTED_TOKEN_ENDPOINT_AUTH_METHOD],
      code_challenge_methods_supported: valuesOrFallback(
        metadata.code_challenge_methods_supported?.filter((item) =>
          SUPPORTED_CODE_CHALLENGE_METHODS.includes(item)),
        SUPPORTED_CODE_CHALLENGE_METHODS,
      ),
      scopes_supported: upstream.scopes,
    });
  } catch (err) {
    return json({
      error: {
        code: 'mcp_oauth_authorization_metadata_unavailable',
        message: err instanceof Error ? err.message : 'MCP OAuth authorization metadata is unavailable.',
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
    }, { status: 405, headers: { allow: 'GET, POST' } });
  }
  const url = new URL(req.url);
  if (url.searchParams.get('prompt') === 'none') {
    return json({
      error: 'interaction_required',
      error_description: 'Silmaril requires explicit consent for every dynamically registered client.',
    }, { status: 400 });
  }
  let registration: ClientRegistration;
  try {
    registration = decodeRegistration(url.searchParams.get('client_id'), config);
  } catch {
    return json({
      error: 'invalid_request',
      error_description: 'client_id is not a valid Silmaril dynamic client registration.',
    }, { status: 400 });
  }
  const redirectUri = url.searchParams.get('redirect_uri');
  if (!redirectUri || !registration.redirect_uris.includes(redirectUri)) {
    return json({
      error: 'invalid_request',
      error_description: 'redirect_uri must exactly match this client registration.',
    }, { status: 400 });
  }
  if (url.searchParams.get('response_type') !== 'code') {
    return json({
      error: 'unsupported_response_type',
      error_description: 'Only authorization code flow is supported.',
    }, { status: 400 });
  }
  const codeChallenge = url.searchParams.get('code_challenge');
  if (!validPkceValue(codeChallenge) || url.searchParams.get('code_challenge_method') !== 'S256') {
    return json({
      error: 'invalid_request',
      error_description: 'S256 PKCE is required for authorization code flow.',
    }, { status: 400 });
  }
  const resource = resourceForRequest(url.searchParams.get('resource'), config);
  if (!resource) {
    return json({
      error: 'invalid_target',
      error_description: 'resource must identify the public or admin Silmaril MCP endpoint.',
    }, { status: 400 });
  }
  try {
    const upstream = await getFirewallMcpPublicConfig(config, req.signal);
    const requestedScopes = scopes(url.searchParams.get('scope') || registration.scope);
    const registeredScopes = scopes(registration.scope);
    const resourceScopes = resource === mcpResource(config, 'admin')
      ? ['firewalls:read']
      : upstream.scopes;
    if (requestedScopes.length === 0 || requestedScopes.some((scope) =>
      !registeredScopes.includes(scope) || !resourceScopes.includes(scope))) {
      return json({
        error: 'invalid_scope',
        error_description: 'Requested scopes must be registered and supported by Silmaril.',
      }, { status: 400 });
    }
    const organization = resolveAuth0Organization(url.searchParams.get('organization'), config);
    if (!organization.ok) return organization.response;
    return consentPage({
      v: ARTIFACT_VERSION,
      redirect_uri: redirectUri,
      client_id: url.searchParams.get('client_id')!,
      client_name: registration.client_name,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      resource,
      scope: requestedScopes.join(' '),
      organization: organization.organization ?? undefined,
      iat: Date.now(),
      nonce: randomUUID(),
      state: url.searchParams.get('state') ?? undefined,
    }, upstream.authorization_servers[0] ?? upstream.issuer, config);
  } catch (err) {
    return json({
      error: 'server_error',
      error_description: err instanceof Error ? err.message : 'MCP OAuth authorization is unavailable.',
    }, { status: 503 });
  }
}

export async function handleAuthorizationConsentRequest(
  req: Request,
  config: ServerConfig,
): Promise<Response> {
  if (req.method !== 'POST') {
    return json({
      error: 'method_not_allowed',
      error_description: 'OAuth consent requires POST.',
    }, { status: 405, headers: { allow: 'GET, POST' } });
  }
  if (!hasContentType(req, 'application/x-www-form-urlencoded')) {
    return json({
      error: 'invalid_request',
      error_description: 'OAuth consent requires application/x-www-form-urlencoded.',
    }, { status: 415 });
  }
  try {
    const params = await readBoundedForm(req);
    const state = decodeBridgeState(params.get('transaction'), config);
    const registration = decodeRegistration(state.client_id, config);
    if (!registration.redirect_uris.includes(state.redirect_uri)) {
      return json({
        error: 'invalid_request',
        error_description: 'Consent transaction callback no longer matches the client registration.',
      }, { status: 400 });
    }
    if (params.get('decision') !== 'approve') {
      return clientErrorRedirect(state, 'access_denied', 'The user denied this MCP client request.');
    }
    const upstream = await getFirewallMcpPublicConfig(config, req.signal);
    const metadata = await fetchUpstreamAuthorizationServerMetadata(upstream, config, req.signal);
    const upstreamClientId = upstream.oauth?.client_id;
    if (!upstreamClientId) throw new Error('firewall-ui MCP OAuth client ID is not configured.');
    const authorizationUrl = new URL(metadata.authorization_endpoint);
    authorizationUrl.searchParams.set('response_type', 'code');
    authorizationUrl.searchParams.set('client_id', upstreamClientId);
    authorizationUrl.searchParams.set('redirect_uri', bridgeCallbackUrl(config));
    authorizationUrl.searchParams.set('state', encodeBridgeState(state, config));
    authorizationUrl.searchParams.set('scope', state.scope);
    authorizationUrl.searchParams.set('audience', upstream.resource || upstream.audience);
    authorizationUrl.searchParams.set('code_challenge', state.code_challenge);
    authorizationUrl.searchParams.set('code_challenge_method', 'S256');
    authorizationUrl.searchParams.set('prompt', 'consent');
    if (state.organization) authorizationUrl.searchParams.set('organization', state.organization);
    return redirect(authorizationUrl);
  } catch (err) {
    return json({
      error: 'invalid_request',
      error_description: err instanceof Error ? err.message : 'Invalid OAuth consent transaction.',
    }, { status: 400 });
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
    }, { status: 405, headers: { allow: 'GET' } });
  }
  const url = new URL(req.url);
  let state: BridgeState;
  try {
    state = decodeBridgeState(url.searchParams.get('state'), config);
    const registration = decodeRegistration(state.client_id, config);
    if (!registration.redirect_uris.includes(state.redirect_uri)) {
      throw new Error('callback mismatch');
    }
  } catch {
    return json({
      error: 'invalid_request',
      error_description: 'Invalid OAuth bridge state.',
    }, { status: 400 });
  }
  const callback = new URL(state.redirect_uri);
  for (const name of ['error', 'error_description', 'error_uri']) {
    appendIfPresent(callback.searchParams, url.searchParams, name);
  }
  const code = url.searchParams.get('code');
  if (code) {
    callback.searchParams.set('code', encodeBridgeCode({
      v: ARTIFACT_VERSION,
      code,
      redirect_uri: state.redirect_uri,
      client_id: state.client_id,
      code_challenge: state.code_challenge,
      code_challenge_method: 'S256',
      resource: state.resource,
      scope: state.scope,
      iat: Date.now(),
      nonce: randomUUID(),
    }, config));
  }
  if (state.state) callback.searchParams.set('state', state.state);
  return redirect(callback);
}

function localTokenResponse(
  upstreamBody: z.infer<typeof UpstreamTokenResponseSchema>,
  claims: UpstreamAccessClaims,
  clientId: string,
  resource: string,
  requestedScopes: string[],
  refreshToken: string | undefined,
  config: ServerConfig,
): Response {
  const now = Math.floor(Date.now() / 1000);
  const returnedScopes = scopes(
    upstreamBody.scope ||
    claims.scope ||
    claims.permissions?.join(' ') ||
    requestedScopes.join(' '),
  ).filter((scope) => requestedScopes.includes(scope));
  const expiresIn = Math.max(1, Math.min(upstreamBody.expires_in, claims.exp - now));
  const identity = {
    client_id: clientId,
    resource,
    scopes: returnedScopes,
    subject: claims.sub,
    organization: claimString(claims, ['org_id', 'https://silmaril.security/org_id']),
    tenant: claimString(claims, ['tenant', 'tenant_id', 'https://silmaril.security/tenant']),
    actor_email: claims.email,
    token_id: claims.jti,
  };
  const response: Record<string, unknown> = {
    access_token: issueMcpCredential({
      kind: 'access',
      downstream_token: upstreamBody.access_token,
      ...identity,
      expiresInSeconds: expiresIn,
    }, config),
    token_type: 'Bearer',
    expires_in: expiresIn,
    scope: returnedScopes.join(' '),
  };
  if (refreshToken) {
    response.refresh_token = issueMcpCredential({
      kind: 'refresh',
      downstream_token: refreshToken,
      ...identity,
    }, config);
  }
  return json(response);
}

export async function handleTokenRequest(
  req: Request,
  config: ServerConfig,
): Promise<Response> {
  if (req.method !== 'POST') {
    return json({
      error: 'method_not_allowed',
      error_description: 'OAuth token exchange requires POST.',
    }, { status: 405, headers: { allow: 'POST' } });
  }
  if (!hasContentType(req, 'application/x-www-form-urlencoded')) {
    return json({
      error: 'invalid_request',
      error_description: 'OAuth token exchange requires application/x-www-form-urlencoded.',
    }, { status: 415 });
  }
  let params: URLSearchParams;
  try {
    params = await readBoundedForm(req);
  } catch (err) {
    return json({
      error: 'invalid_request',
      error_description: err instanceof Error ? err.message : 'Invalid token request.',
    }, { status: 400 });
  }
  try {
    const requestedClientId = params.get('client_id');
    let registration: ClientRegistration;
    try {
      registration = decodeRegistration(requestedClientId, config);
    } catch {
      return json({
        error: 'invalid_client',
        error_description: 'client_id is not a valid Silmaril dynamic client registration.',
      }, { status: 400 });
    }
    const upstream = await getFirewallMcpPublicConfig(config, req.signal);
    const metadata = await fetchUpstreamAuthorizationServerMetadata(upstream, config, req.signal);
    const upstreamClientId = upstream.oauth?.client_id;
    if (!upstreamClientId) throw new Error('firewall-ui MCP OAuth client ID is not configured.');
    const grantType = params.get('grant_type');
    const upstreamParams = new URLSearchParams({
      client_id: upstreamClientId,
    });
    let resource: string;
    let requestedScopes: string[];

    if (grantType === 'authorization_code') {
      const code = params.get('code');
      const verifier = params.get('code_verifier');
      const redirectUri = params.get('redirect_uri');
      if (!code || !validPkceValue(verifier) || !redirectUri) {
        return json({
          error: 'invalid_request',
          error_description: 'authorization_code grant requires code, code_verifier, and redirect_uri.',
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
      if (
        bridgeCode.client_id !== requestedClientId ||
        bridgeCode.redirect_uri !== redirectUri ||
        !registration.redirect_uris.includes(redirectUri)
      ) {
        return json({
          error: 'invalid_grant',
          error_description: 'authorization code is not bound to this client or redirect_uri.',
        }, { status: 400 });
      }
      if (!safeEqual(s256Challenge(verifier), bridgeCode.code_challenge)) {
        return json({
          error: 'invalid_grant',
          error_description: 'code_verifier does not match the authorization request.',
        }, { status: 400 });
      }
      resource = bridgeCode.resource;
      requestedScopes = scopes(bridgeCode.scope);
      upstreamParams.set('grant_type', 'authorization_code');
      upstreamParams.set('code', bridgeCode.code);
      upstreamParams.set('redirect_uri', bridgeCallbackUrl(config));
      upstreamParams.set('code_verifier', verifier);
    } else if (grantType === 'refresh_token') {
      const refreshToken = params.get('refresh_token');
      if (!refreshToken) {
        return json({
          error: 'invalid_request',
          error_description: 'refresh_token grant requires refresh_token.',
        }, { status: 400 });
      }
      let credential;
      try {
        credential = validateMcpRefreshToken(refreshToken, requestedClientId!, config);
      } catch {
        return json({
          error: 'invalid_grant',
          error_description: 'refresh token is invalid, expired, or belongs to another client.',
        }, { status: 400 });
      }
      resource = credential.resource;
      requestedScopes = scopes(params.get('scope') || credential.scopes.join(' '));
      if (requestedScopes.some((scope) => !credential.scopes.includes(scope))) {
        return json({
          error: 'invalid_scope',
          error_description: 'Refresh requests cannot expand the original grant.',
        }, { status: 400 });
      }
      upstreamParams.set('grant_type', 'refresh_token');
      upstreamParams.set('refresh_token', credential.downstream_token);
      if (params.get('scope')) upstreamParams.set('scope', requestedScopes.join(' '));
    } else {
      return json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code and refresh_token grants are supported.',
      }, { status: 400 });
    }
    if (params.get('resource') && params.get('resource') !== resource) {
      return json({
        error: 'invalid_target',
        error_description: 'resource does not match the original grant.',
      }, { status: 400 });
    }
    const upstreamResponse = await fetch(metadata.token_endpoint, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: upstreamParams.toString(),
      cache: 'no-store',
      redirect: 'error',
      signal: requestSignal(config, req.signal),
    });
    const rawBody = await readBoundedResponseJson(upstreamResponse);
    if (!upstreamResponse.ok) {
      return json(rawBody, { status: upstreamResponse.status });
    }
    const upstreamBody = UpstreamTokenResponseSchema.parse(rawBody);
    if (grantType === 'refresh_token' && !upstreamBody.refresh_token) {
      throw new Error('upstream refresh-token rotation is required.');
    }
    const claims = await validateUpstreamClaims(
      upstreamBody.access_token,
      upstream,
      metadata,
      config,
      req.signal,
    );
    return localTokenResponse(
      upstreamBody,
      claims,
      requestedClientId!,
      resource,
      requestedScopes,
      upstreamBody.refresh_token,
      config,
    );
  } catch (err) {
    return json({
      error: 'server_error',
      error_description: err instanceof Error ? err.message : 'MCP OAuth token exchange is unavailable.',
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
    }, { status: 405, headers: { allow: 'POST' } });
  }
  if (!hasContentType(req, 'application/json')) {
    return json({
      error: 'invalid_client_metadata',
      error_description: 'Dynamic client registration requires application/json.',
    }, { status: 415 });
  }
  let registration: ClientRegistrationRequest;
  try {
    registration = ClientRegistrationRequestSchema.parse(await readBoundedJson(req));
  } catch (err) {
    return json({
      error: 'invalid_client_metadata',
      error_description: err instanceof Error ? err.message : 'Invalid dynamic client registration request.',
    }, { status: 400 });
  }
  if (registration.redirect_uris.some((uri) => !isLoopbackRedirectUri(uri))) {
    return invalidClientMetadata('redirect_uris must be exact HTTP loopback callback URLs without fragments.');
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
  try {
    const upstream = await getFirewallMcpPublicConfig(config, req.signal);
    const registeredScopes = scopes(
      registration.scope ?? DEFAULT_AUTHORIZATION_SCOPES.join(' '),
    );
    if (
      registeredScopes.length === 0 ||
      registeredScopes.some((scope) => !upstream.scopes.includes(scope))
    ) {
      return invalidClientMetadata('scope must contain only supported Silmaril scopes.');
    }
    const issuedAt = Date.now();
    const client = {
      v: 2 as const,
      registration_id: randomUUID(),
      redirect_uris: registration.redirect_uris,
      grant_types: registration.grant_types ?? [...SUPPORTED_GRANT_TYPES],
      response_types: registration.response_types ?? [...SUPPORTED_RESPONSE_TYPES],
      scope: registeredScopes.join(' '),
      client_name: registration.client_name ?? 'Silmaril Firewall MCP Client',
      iat: issuedAt,
      exp: issuedAt + REGISTRATION_MAX_AGE_MS,
    };
    return json({
      client_id: encodeRegistration(client, config),
      client_id_issued_at: Math.floor(issuedAt / 1000),
      client_secret_expires_at: 0,
      redirect_uris: client.redirect_uris,
      grant_types: client.grant_types,
      response_types: client.response_types,
      token_endpoint_auth_method: SUPPORTED_TOKEN_ENDPOINT_AUTH_METHOD,
      scope: client.scope,
      client_name: client.client_name,
    }, { status: 201 });
  } catch (err) {
    return json({
      error: 'server_error',
      error_description: err instanceof Error ? err.message : 'MCP OAuth client registration is unavailable.',
    }, { status: 503 });
  }
}
