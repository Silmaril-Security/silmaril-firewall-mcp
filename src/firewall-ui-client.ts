import type { ServerConfig } from './config';

export class FirewallApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export interface FirewallRequestOptions {
  path: string;
  token: string;
  config: ServerConfig;
  signal?: AbortSignal;
}

function joinPath(baseUrl: string, path: string): URL {
  const base = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  return new URL(path.replace(/^\//, ''), base);
}

async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  const contentLength = response.headers.get('content-length');
  if (contentLength && Number(contentLength) > maxBytes) {
    throw new FirewallApiError(413, 'upstream_response_too_large', 'firewall-ui response exceeded the MCP response size cap.');
  }

  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let bytesRead = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytesRead += value.byteLength;
      if (bytesRead > maxBytes) {
        await reader.cancel();
        throw new FirewallApiError(413, 'upstream_response_too_large', 'firewall-ui response exceeded the MCP response size cap.');
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
  } finally {
    reader.releaseLock();
  }

  chunks.push(decoder.decode());
  return chunks.join('');
}

export async function firewallGetJson<T>({
  path,
  token,
  config,
  signal,
}: FirewallRequestOptions): Promise<T> {
  const response = await fetch(joinPath(config.firewallUiBaseUrl, path), {
    method: 'GET',
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
    },
    cache: 'no-store',
    signal,
  });

  const text = await readBoundedText(response, config.maxResponseBytes);
  let parsed: unknown = null;
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new FirewallApiError(response.status, 'upstream_invalid_json', 'firewall-ui returned invalid JSON.');
    }
  }

  if (!response.ok) {
    const error = parsed && typeof parsed === 'object' && 'error' in parsed
      ? (parsed as { error?: { code?: unknown; message?: unknown } }).error
      : null;
    throw new FirewallApiError(
      response.status,
      typeof error?.code === 'string' ? error.code : 'upstream_error',
      typeof error?.message === 'string' ? error.message : 'firewall-ui request failed.',
    );
  }

  return parsed as T;
}

export function pathWithQuery(path: string, params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value));
    }
  }
  const query = search.toString();
  return query ? `${path}?${query}` : path;
}

export function enc(value: string): string {
  return encodeURIComponent(value);
}
