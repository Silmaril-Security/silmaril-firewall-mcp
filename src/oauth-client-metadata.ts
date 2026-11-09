import { Resolver } from 'node:dns/promises';
import type { ClientRequest, IncomingMessage } from 'node:http';
import {
  request as httpsRequest,
  type RequestOptions as HttpsRequestOptions,
} from 'node:https';
import { isIP } from 'node:net';
import { Address4, Address6 } from 'ip-address';
import { z } from 'zod';
import {
  isAllowedOAuthRedirectUri,
  isSafeLoopbackOAuthRedirectUri,
} from './oauth-redirect-policy';

const CLIENT_METADATA_MAX_BYTES = 64 * 1024;
const CLIENT_METADATA_CACHE_TTL_MS = 5 * 60_000;
const CLIENT_METADATA_CACHE_MAX_ENTRIES = 128;
const CLIENT_METADATA_MAX_DNS_ANSWERS = 32;
const CLIENT_METADATA_MAX_URL_BYTES = 4_096;

const ClientMetadataDocumentSchema = z.object({
  client_id: z.string().min(1).max(CLIENT_METADATA_MAX_URL_BYTES),
  client_name: z.string().min(1).max(128),
  redirect_uris: z.array(z.string().min(1).max(2_048)).min(1).max(8),
  grant_types: z.array(z.string().min(1)).min(1).max(2).optional(),
  response_types: z.array(z.string().min(1)).min(1).max(1).optional(),
  token_endpoint_auth_method: z.string().min(1).optional(),
  scope: z.string().min(1).max(2_048).optional(),
  client_secret: z.unknown().optional(),
  client_secret_expires_at: z.unknown().optional(),
}).passthrough();

type ClientMetadataDocument = z.infer<typeof ClientMetadataDocumentSchema>;

export interface OAuthClient {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scope: string;
  source: 'dcr' | 'cimd';
}

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface PinnedHttpsResponse {
  status: number;
  contentType: string | null;
  cacheControl: string | null;
  expires: string | null;
  date: string | null;
  age: string | null;
  body: Uint8Array;
}

interface ResolverLike {
  resolve4(hostname: string): Promise<string[]>;
  resolve6(hostname: string): Promise<string[]>;
  cancel(): void;
}

type HttpsRequestFactory = (
  url: URL,
  options: HttpsRequestOptions,
  onResponse: (response: IncomingMessage) => void,
) => ClientRequest;

export interface OAuthClientMetadataDependencies {
  now: () => number;
  setTimeout: typeof globalThis.setTimeout;
  clearTimeout: typeof globalThis.clearTimeout;
  resolverFactory: () => ResolverLike;
  httpsRequest: HttpsRequestFactory;
  resolve: (hostname: string, signal: AbortSignal) => Promise<ResolvedAddress[]>;
  request: (
    url: URL,
    address: ResolvedAddress,
    signal: AbortSignal,
  ) => Promise<PinnedHttpsResponse>;
}

export interface ResolveOAuthClientOptions {
  allowedRedirectUris: readonly string[];
  supportedScopes: readonly string[] | (() => Promise<readonly string[]>);
  defaultScopes: readonly string[];
  timeoutMs: number;
  decodeSignedClient: (clientId: string) => OAuthClient;
}

const metadataCache = new Map<string, {
  document: ClientMetadataDocument;
  expiresAt: number;
}>();

function genericMetadataError(): Error {
  return new Error('OAuth client metadata is invalid or unavailable.');
}

function boundedTimeout(timeoutMs: number): number {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return 5_000;
  return Math.max(100, Math.min(timeoutMs, 5_000));
}

function normalizedHostname(hostname: string): string {
  return hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
}

function isPublicAddress(value: string): boolean {
  try {
    const family = isIP(value);
    if (family === 4) return new Address4(value).isGlobal();
    if (family !== 6) return false;
    const address = new Address6(value);
    return !address.isMapped4() && address.isGlobal();
  } catch {
    return false;
  }
}

function isNoDataError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === 'ENODATA' || code === 'ENOENT';
}

async function defaultResolve(
  hostname: string,
  signal: AbortSignal,
): Promise<ResolvedAddress[]> {
  const normalized = normalizedHostname(hostname);
  const literalFamily = isIP(normalized);
  if (literalFamily === 4 || literalFamily === 6) {
    return [{ address: normalized, family: literalFamily }];
  }

  const resolver = dependencies.resolverFactory();
  const onAbort = () => resolver.cancel();
  signal.addEventListener('abort', onAbort, { once: true });
  const resolveFamily = async (
    family: 4 | 6,
  ): Promise<ResolvedAddress[]> => {
    try {
      const values = family === 4
        ? await resolver.resolve4(normalized)
        : await resolver.resolve6(normalized);
      return values.map((address) => ({ address, family }));
    } catch (error) {
      if (isNoDataError(error)) return [];
      throw error;
    }
  };
  try {
    const [ipv4, ipv6] = await Promise.all([
      resolveFamily(4),
      resolveFamily(6),
    ]);
    if (signal.aborted) throw genericMetadataError();
    return [...ipv4, ...ipv6];
  } catch (error) {
    resolver.cancel();
    throw error;
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

function responseHeader(
  response: IncomingMessage,
  name: string,
): string | null {
  const value = response.headers[name];
  return Array.isArray(value) ? value[0] ?? null : value ?? null;
}

function defaultPinnedHttpsRequest(
  url: URL,
  address: ResolvedAddress,
  signal: AbortSignal,
): Promise<PinnedHttpsResponse> {
  return new Promise((resolve, reject) => {
    const owned: { request?: ClientRequest } = {};
    let response: IncomingMessage | undefined;
    let settled = false;
    let ended = false;
    const chunks: Buffer[] = [];
    let bytes = 0;

    const cleanup = () => {
      signal.removeEventListener('abort', onAbort);
      owned.request?.removeListener('error', onRequestError);
      if (response) {
        response.removeListener('data', onData);
        response.removeListener('end', onEnd);
        response.removeListener('error', onResponseError);
        response.removeListener('aborted', onResponseAborted);
        response.removeListener('close', onResponseClose);
      }
    };
    const fail = (error: unknown, destroy = true) => {
      if (settled) return;
      settled = true;
      if (destroy) {
        response?.destroy();
        owned.request?.destroy();
      }
      cleanup();
      reject(error instanceof Error ? error : genericMetadataError());
    };
    const onAbort = () => fail(genericMetadataError());
    const onRequestError = () => fail(genericMetadataError());
    const onResponseError = () => fail(genericMetadataError());
    const onResponseAborted = () => fail(genericMetadataError());
    const onResponseClose = () => {
      if (!ended) fail(genericMetadataError());
    };
    const onData = (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.byteLength;
      if (bytes > CLIENT_METADATA_MAX_BYTES) {
        fail(genericMetadataError());
        return;
      }
      chunks.push(buffer);
    };
    const onEnd = () => {
      if (settled || !response) return;
      ended = true;
      settled = true;
      cleanup();
      resolve({
        status: response.statusCode ?? 0,
        contentType: responseHeader(response, 'content-type'),
        cacheControl: responseHeader(response, 'cache-control'),
        expires: responseHeader(response, 'expires'),
        date: responseHeader(response, 'date'),
        age: responseHeader(response, 'age'),
        body: Buffer.concat(chunks),
      });
    };

    owned.request = dependencies.httpsRequest(url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'user-agent': 'silmaril-firewall-mcp-cimd/1',
      },
      lookup: (_hostname, options, callback) => {
        if (typeof options === 'object' && options.all) {
          callback(null, [address]);
          return;
        }
        callback(null, address.address, address.family);
      },
    }, (incoming) => {
      response = incoming;
      const contentLength = Number(response.headers['content-length']);
      if (Number.isFinite(contentLength) && contentLength > CLIENT_METADATA_MAX_BYTES) {
        fail(genericMetadataError());
        return;
      }
      response.on('data', onData);
      response.once('end', onEnd);
      response.once('error', onResponseError);
      response.once('aborted', onResponseAborted);
      response.once('close', onResponseClose);
    });
    if (settled) {
      owned.request.destroy();
      return;
    }
    owned.request.once('error', onRequestError);
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    owned.request.end();
  });
}

const defaultDependencies: OAuthClientMetadataDependencies = {
  now: Date.now,
  setTimeout: globalThis.setTimeout,
  clearTimeout: globalThis.clearTimeout,
  resolverFactory: () => new Resolver(),
  httpsRequest: httpsRequest as HttpsRequestFactory,
  resolve: defaultResolve,
  request: defaultPinnedHttpsRequest,
};

let dependencies = defaultDependencies;

export function setOAuthClientMetadataDependenciesForTests(
  overrides: Partial<OAuthClientMetadataDependencies>,
): void {
  dependencies = { ...defaultDependencies, ...overrides };
  metadataCache.clear();
}

export function resetOAuthClientMetadataForTests(): void {
  dependencies = defaultDependencies;
  metadataCache.clear();
}

function parseClientIdUrl(clientId: string): URL {
  if (Buffer.byteLength(clientId, 'utf8') > CLIENT_METADATA_MAX_URL_BYTES) {
    throw genericMetadataError();
  }
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    throw genericMetadataError();
  }
  if (
    url.protocol !== 'https:'
    || url.username
    || url.password
    || url.hash
    || !url.hostname
    || url.pathname === '/'
  ) {
    throw genericMetadataError();
  }
  const afterScheme = clientId.slice('https://'.length);
  const pathOffset = afterScheme.search(/[/?#]/u);
  if (pathOffset < 0 || afterScheme[pathOffset] !== '/') {
    throw genericMetadataError();
  }
  const authorityEnd = 'https://'.length + pathOffset;
  const rawPath = clientId
    .slice(authorityEnd)
    .split(/[?#]/u, 1)[0] ?? '';
  for (const segment of rawPath.split('/')) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw genericMetadataError();
    }
    if (decoded === '.' || decoded === '..') throw genericMetadataError();
  }
  return url;
}

function parseJson(body: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    throw genericMetadataError();
  }
}

function cacheDocument(
  clientId: string,
  document: ClientMetadataDocument,
  ttlMs: number,
): void {
  if (ttlMs <= 0) return;
  if (metadataCache.size >= CLIENT_METADATA_CACHE_MAX_ENTRIES) {
    const oldest = metadataCache.keys().next().value;
    if (oldest !== undefined) metadataCache.delete(oldest);
  }
  metadataCache.set(clientId, {
    document,
    expiresAt: dependencies.now() + ttlMs,
  });
}

function cacheTtlMs(response: PinnedHttpsResponse): number {
  const directives = response.cacheControl
    ?.split(',')
    .map((directive) => directive.trim().toLowerCase()) ?? [];
  if (directives.some((directive) =>
    directive === 'no-store' || directive === 'no-cache')) {
    return 0;
  }
  const maxAge = directives
    .map((directive) => /^max-age\s*=\s*"?(\d+)"?$/u.exec(directive)?.[1])
    .find((value) => value !== undefined);
  if (maxAge !== undefined) {
    const age = Math.max(0, Number.parseInt(response.age ?? '0', 10) || 0);
    const seconds = Math.max(0, Number.parseInt(maxAge, 10) - age);
    return Math.min(seconds * 1_000, CLIENT_METADATA_CACHE_TTL_MS);
  }
  if (response.expires) {
    const expiresAt = Date.parse(response.expires);
    if (Number.isFinite(expiresAt)) {
      const responseDate = Date.parse(response.date ?? '');
      const baseTime = Number.isFinite(responseDate)
        ? responseDate
        : dependencies.now();
      const age = Math.max(0, Number.parseInt(response.age ?? '0', 10) || 0);
      return Math.min(
        Math.max(0, expiresAt - baseTime - age * 1_000),
        CLIENT_METADATA_CACHE_TTL_MS,
      );
    }
  }
  return 0;
}

function runUntilAbort<T>(
  work: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) return Promise.reject(genericMetadataError());
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      cleanup();
      reject(genericMetadataError());
    };
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    signal.addEventListener('abort', onAbort, { once: true });
    work.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error) => {
        cleanup();
        reject(error);
      },
    );
  });
}

async function fetchClientMetadata(
  clientId: string,
  requestedTimeoutMs: number,
): Promise<ClientMetadataDocument> {
  const cached = metadataCache.get(clientId);
  if (cached && cached.expiresAt > dependencies.now()) return cached.document;
  if (cached) metadataCache.delete(clientId);

  const url = parseClientIdUrl(clientId);
  const timeoutMs = boundedTimeout(requestedTimeoutMs);
  const deadline = new AbortController();
  const timer = dependencies.setTimeout(() => {
    deadline.abort(genericMetadataError());
  }, timeoutMs);
  try {
    const answers = await runUntilAbort(
      dependencies.resolve(url.hostname, deadline.signal),
      deadline.signal,
    );
    if (
      answers.length === 0
      || answers.length > CLIENT_METADATA_MAX_DNS_ANSWERS
      || answers.some(({ address, family }) =>
        (family !== 4 && family !== 6) || !isPublicAddress(address))
    ) {
      throw genericMetadataError();
    }

    const response = await runUntilAbort(
      dependencies.request(url, answers[0], deadline.signal),
      deadline.signal,
    );
    const contentType = response.contentType
      ?.split(';', 1)[0]
      ?.trim()
      .toLowerCase();
    if (
      response.status < 200
      || response.status >= 300
      || (
        contentType !== 'application/json'
        && !/^application\/[a-z0-9!#$&^_.+-]+\+json$/u.test(contentType ?? '')
      )
      || response.body.byteLength > CLIENT_METADATA_MAX_BYTES
    ) {
      throw genericMetadataError();
    }
    let document: ClientMetadataDocument;
    try {
      document = ClientMetadataDocumentSchema.parse(parseJson(response.body));
    } catch {
      throw genericMetadataError();
    }
    if (document.client_id !== clientId) throw genericMetadataError();
    cacheDocument(clientId, document, cacheTtlMs(response));
    return document;
  } catch {
    throw genericMetadataError();
  } finally {
    deadline.abort(genericMetadataError());
    dependencies.clearTimeout(timer);
  }
}

function uniqueScopes(value: string): string[] {
  return [...new Set(value.split(/\s+/).map((scope) => scope.trim()).filter(Boolean))];
}

function variableLoopbackPortMatch(registered: string, requested: string): boolean {
  if (
    !isSafeLoopbackOAuthRedirectUri(registered)
    || !isSafeLoopbackOAuthRedirectUri(requested)
  ) {
    return false;
  }
  const registeredUrl = new URL(registered);
  const requestedUrl = new URL(requested);
  return (
    registeredUrl.port === ''
    && registeredUrl.protocol === requestedUrl.protocol
    && registeredUrl.hostname === requestedUrl.hostname
    && registeredUrl.pathname === requestedUrl.pathname
    && registeredUrl.search === requestedUrl.search
  );
}

export function isOAuthClientRedirectUriAllowed(
  client: OAuthClient,
  requested: string,
): boolean {
  return client.redirectUris.includes(requested) || (
    client.source === 'cimd'
    && client.redirectUris.some((registered) =>
      variableLoopbackPortMatch(registered, requested))
  );
}

function validatedCimdClient(
  clientId: string,
  document: ClientMetadataDocument,
  options: Omit<ResolveOAuthClientOptions, 'supportedScopes'>,
  supportedScopes: readonly string[],
): OAuthClient {
  const grantTypes = document.grant_types ?? ['authorization_code'];
  const responseTypes = document.response_types ?? ['code'];
  const scopes = uniqueScopes(
    document.scope ?? options.defaultScopes.join(' '),
  );
  if (
    document.client_secret !== undefined
    || document.client_secret_expires_at !== undefined
    || document.token_endpoint_auth_method !== 'none'
    || !grantTypes.includes('authorization_code')
    || grantTypes.some((grant) =>
      grant !== 'authorization_code' && grant !== 'refresh_token')
    || responseTypes.length !== 1
    || responseTypes[0] !== 'code'
    || scopes.length === 0
    || scopes.some((scope) => !supportedScopes.includes(scope))
    || document.redirect_uris.some((uri) =>
      !isAllowedOAuthRedirectUri(uri, options.allowedRedirectUris))
  ) {
    throw genericMetadataError();
  }
  return {
    clientId,
    clientName: document.client_name,
    redirectUris: [...document.redirect_uris],
    grantTypes: [...grantTypes],
    responseTypes: [...responseTypes],
    scope: scopes.join(' '),
    source: 'cimd',
  };
}

export async function resolveOAuthClient(
  clientId: string | null,
  options: ResolveOAuthClientOptions,
): Promise<OAuthClient> {
  if (!clientId) throw genericMetadataError();
  try {
    return options.decodeSignedClient(clientId);
  } catch {
    const document = await fetchClientMetadata(clientId, options.timeoutMs);
    const supportedScopes = typeof options.supportedScopes === 'function'
      ? await options.supportedScopes()
      : options.supportedScopes;
    return validatedCimdClient(clientId, document, options, supportedScopes);
  }
}
