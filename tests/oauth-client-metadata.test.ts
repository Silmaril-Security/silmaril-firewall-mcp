import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type { ClientRequest, IncomingMessage } from 'node:http';
import { PassThrough } from 'node:stream';
import test, { afterEach } from 'node:test';
import {
  resetOAuthClientMetadataForTests,
  resolveOAuthClient,
  setOAuthClientMetadataDependenciesForTests,
  type OAuthClientMetadataDependencies,
  type PinnedHttpsResponse,
  type ResolvedAddress,
} from '../src/oauth-client-metadata';

const CLIENT_ID = 'https://client.example/oauth/client-metadata.json';
const PUBLIC_ADDRESS: ResolvedAddress = { address: '93.184.216.34', family: 4 };

class ControlledRequest extends EventEmitter {
  destroyed = false;
  ended = false;
  onEnd: (() => void) | undefined;

  end(): this {
    this.ended = true;
    this.onEnd?.();
    return this;
  }

  destroy(): this {
    if (this.destroyed) return this;
    this.destroyed = true;
    this.emit('close');
    return this;
  }
}

function controlledResponse(
  headers: Record<string, string> = { 'content-type': 'application/json' },
): PassThrough & Pick<IncomingMessage, 'statusCode' | 'headers'> {
  const response = new PassThrough() as PassThrough
    & Pick<IncomingMessage, 'statusCode' | 'headers'>;
  response.statusCode = 200;
  response.headers = headers;
  return response;
}

function trackedDeadline() {
  const active = new Set<ReturnType<typeof setTimeout>>();
  return {
    active,
    setTimeout: ((callback: (...args: unknown[]) => void, delay?: number) => {
      const timer = setTimeout(() => {
        active.delete(timer);
        callback();
      }, delay);
      active.add(timer);
      return timer;
    }) as typeof globalThis.setTimeout,
    clearTimeout: ((timer: ReturnType<typeof setTimeout>) => {
      active.delete(timer);
      clearTimeout(timer);
    }) as typeof globalThis.clearTimeout,
  };
}

function metadata(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLIENT_ID,
    client_name: 'Cursor',
    redirect_uris: ['http://127.0.0.1/oauth/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope: 'firewalls:read metrics:read',
    ...overrides,
  };
}

function response(
  body: unknown = metadata(),
  overrides: Partial<PinnedHttpsResponse> = {},
): PinnedHttpsResponse {
  return {
    status: 200,
    contentType: 'application/json; charset=utf-8',
    cacheControl: null,
    expires: null,
    date: null,
    age: null,
    body: new TextEncoder().encode(JSON.stringify(body)),
    ...overrides,
  };
}

function options() {
  return {
    allowedRedirectUris: [] as string[],
    supportedScopes: ['firewalls:read', 'metrics:read'],
    defaultScopes: ['firewalls:read', 'metrics:read'],
    timeoutMs: 1_000,
    decodeSignedClient: () => {
      throw new Error('not a signed registration');
    },
  };
}

afterEach(() => {
  resetOAuthClientMetadataForTests();
});

test('CIMD resolution pins the validated public DNS answer and preserves signed DCR', async () => {
  const pinned: ResolvedAddress[] = [];
  setOAuthClientMetadataDependenciesForTests({
    resolve: async () => [PUBLIC_ADDRESS],
    request: async (_url, address) => {
      pinned.push(address);
      return response();
    },
  });

  const client = await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(client.source, 'cimd');
  assert.equal(client.clientId, CLIENT_ID);
  assert.deepEqual(client.redirectUris, ['http://127.0.0.1/oauth/callback']);
  assert.deepEqual(pinned, [PUBLIC_ADDRESS]);

  let resolved = false;
  setOAuthClientMetadataDependenciesForTests({
    resolve: async () => {
      resolved = true;
      return [PUBLIC_ADDRESS];
    },
  });
  const signed = await resolveOAuthClient('dcr2.signed.value', {
    ...options(),
    decodeSignedClient: (clientId) => ({
      clientId,
      clientName: 'Legacy',
      redirectUris: ['http://127.0.0.1:1455/oauth/callback'],
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      scope: 'firewalls:read',
      source: 'dcr',
    }),
  });
  assert.equal(signed.source, 'dcr');
  assert.equal(resolved, false);
});

test('CIMD rejects an entire DNS answer set containing a non-public address', async (t) => {
  const blockedAnswers: ResolvedAddress[][] = [
    [PUBLIC_ADDRESS, { address: '10.0.0.1', family: 4 }],
    [{ address: '169.254.1.1', family: 4 }],
    [{ address: '198.18.0.1', family: 4 }],
    [{ address: 'fc00::1', family: 6 }],
    [{ address: 'fe80::1', family: 6 }],
    [{ address: '100::1', family: 6 }],
    [{ address: '100:0:0:1::1', family: 6 }],
    [{ address: '2001:2::1', family: 6 }],
    [{ address: '2001:db8::1', family: 6 }],
    [{ address: '3fff::1', family: 6 }],
    [{ address: '5f00::1', family: 6 }],
    [{ address: '::ffff:127.0.0.1', family: 6 }],
    [{ address: '::ffff:93.184.216.34', family: 6 }],
  ];
  for (const answers of blockedAnswers) {
    await t.test(answers.at(-1)?.address ?? 'empty', async () => {
      let requested = false;
      setOAuthClientMetadataDependenciesForTests({
        resolve: async () => answers,
        request: async () => {
          requested = true;
          return response();
        },
      });
      await assert.rejects(
        resolveOAuthClient(CLIENT_ID, options()),
        /invalid or unavailable/,
      );
      assert.equal(requested, false);
    });
  }
});

test('CIMD permits current-registry globally reachable exceptions', async (t) => {
  const publicAnswers: ResolvedAddress[] = [
    { address: '192.0.0.9', family: 4 },
    { address: '192.0.0.10', family: 4 },
    { address: '2001:1::1', family: 6 },
    { address: '2001:3::1', family: 6 },
    { address: '2001:4:112::1', family: 6 },
    { address: '2001:20::1', family: 6 },
    { address: '2001:30::1', family: 6 },
  ];
  for (const answer of publicAnswers) {
    await t.test(answer.address, async () => {
      setOAuthClientMetadataDependenciesForTests({
        resolve: async () => [answer],
        request: async () => response(),
      });
      assert.equal((await resolveOAuthClient(CLIENT_ID, options())).source, 'cimd');
    });
  }
});

test('CIMD cache is exact-keyed, bounded by TTL, and re-resolves before reuse', async () => {
  let now = 1_000;
  let resolution = 0;
  let requests = 0;
  const deps: Partial<OAuthClientMetadataDependencies> = {
    now: () => now,
    resolve: async () => {
      resolution += 1;
      return resolution === 1
        ? [PUBLIC_ADDRESS]
        : [{ address: '127.0.0.1', family: 4 }];
    },
    request: async () => {
      requests += 1;
      return response(metadata(), { cacheControl: 'max-age=300' });
    },
  };
  setOAuthClientMetadataDependenciesForTests(deps);

  await resolveOAuthClient(CLIENT_ID, options());
  now += 299_999;
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(resolution, 1);
  assert.equal(requests, 1);

  now += 2;
  await assert.rejects(resolveOAuthClient(CLIENT_ID, options()), /invalid or unavailable/);
  assert.equal(resolution, 2);
  assert.equal(requests, 1);
});

test('CIMD cache respects no-store and bounded max-age headers', async () => {
  let now = 1_000;
  let requests = 0;
  const install = (headers: Partial<PinnedHttpsResponse>) => {
    setOAuthClientMetadataDependenciesForTests({
      now: () => now,
      resolve: async () => [PUBLIC_ADDRESS],
      request: async () => {
        requests += 1;
        return response(metadata(), headers);
      },
    });
  };

  install({ cacheControl: 'no-store' });
  await resolveOAuthClient(CLIENT_ID, options());
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(requests, 2);

  requests = 0;
  install({ cacheControl: null });
  await resolveOAuthClient(CLIENT_ID, options());
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(requests, 2);

  requests = 0;
  install({ cacheControl: 'no-cache' });
  await resolveOAuthClient(CLIENT_ID, options());
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(requests, 2);

  requests = 0;
  install({ cacheControl: 'public, max-age=1' });
  await resolveOAuthClient(CLIENT_ID, options());
  now += 999;
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(requests, 1);
  now += 2;
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(requests, 2);

  requests = 0;
  install({ cacheControl: 'max-age=86400' });
  await resolveOAuthClient(CLIENT_ID, options());
  now += 5 * 60_000 - 1;
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(requests, 1);
  now += 2;
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(requests, 2);

  requests = 0;
  install({ cacheControl: 'max-age=60', age: '60' });
  await resolveOAuthClient(CLIENT_ID, options());
  await resolveOAuthClient(CLIENT_ID, options());
  assert.equal(requests, 2);
});

test('CIMD rejects redirects, oversized bodies, malformed JSON, and wrong content types', async (t) => {
  const cases: Array<[string, PinnedHttpsResponse]> = [
    ['redirect', response({}, { status: 302 })],
    ['oversized', response({}, { body: new Uint8Array(64 * 1024 + 1) })],
    ['malformed', response({}, { body: new TextEncoder().encode('{') })],
    ['content-type', response({}, { contentType: 'text/plain' })],
  ];
  for (const [name, fixture] of cases) {
    await t.test(name, async () => {
      setOAuthClientMetadataDependenciesForTests({
        resolve: async () => [PUBLIC_ADDRESS],
        request: async () => fixture,
      });
      await assert.rejects(resolveOAuthClient(CLIENT_ID, options()), /invalid or unavailable/);
    });
  }
});

test('CIMD requires exact identity, public-client auth, code flow, allowed callbacks, and supported scopes', async (t) => {
  const cases: Array<[string, Record<string, unknown>]> = [
    ['identity', { client_id: `${CLIENT_ID}?other=1` }],
    ['client name', { client_name: undefined }],
    ['secret auth', { token_endpoint_auth_method: 'client_secret_basic' }],
    ['client secret', { client_secret: 'not-allowed' }],
    ['grant', { grant_types: ['client_credentials'] }],
    ['response', { response_types: ['token'] }],
    ['callback', { redirect_uris: ['https://unapproved.example/callback'] }],
    ['scope', { scope: 'firewalls:read unknown:scope' }],
  ];
  for (const [name, override] of cases) {
    await t.test(name, async () => {
      setOAuthClientMetadataDependenciesForTests({
        resolve: async () => [PUBLIC_ADDRESS],
        request: async () => response(metadata(override)),
      });
      await assert.rejects(resolveOAuthClient(CLIENT_ID, options()), /invalid or unavailable/);
    });
  }
});

test('CIMD applies RFC 7591 code-flow defaults and authorization-server scope policy', async () => {
  setOAuthClientMetadataDependenciesForTests({
    resolve: async () => [PUBLIC_ADDRESS],
    request: async () => response(metadata({
      grant_types: undefined,
      response_types: undefined,
      scope: undefined,
    }), {
      contentType: 'application/oauth-client-metadata+json',
    }),
  });

  const client = await resolveOAuthClient(CLIENT_ID, options());
  assert.deepEqual(client.grantTypes, ['authorization_code']);
  assert.deepEqual(client.responseTypes, ['code']);
  assert.equal(client.scope, 'firewalls:read metrics:read');
});

test('CIMD client IDs require HTTPS without credentials or fragments', async () => {
  const invalid = [
    'http://client.example/client.json',
    'https://user@client.example/client.json',
    'https://client.example/client.json#fragment',
    'https://client.example',
    'https://client.example/',
    'https://client.example/a/../client.json',
    'https://client.example/%2e/client.json',
  ];
  setOAuthClientMetadataDependenciesForTests({
    resolve: async () => {
      throw new Error('must not resolve');
    },
  });
  for (const clientId of invalid) {
    await assert.rejects(resolveOAuthClient(clientId, options()), /invalid or unavailable/);
  }
});

test('CIMD absolute deadline cancels default DNS resolution', async () => {
  const deadline = trackedDeadline();
  let cancelCount = 0;
  let reject4: ((error: Error) => void) | undefined;
  let reject6: ((error: Error) => void) | undefined;
  const cancelled = Object.assign(new Error('cancelled'), { code: 'ECANCELLED' });
  setOAuthClientMetadataDependenciesForTests({
    ...deadline,
    resolverFactory: () => ({
      resolve4: async () => new Promise<string[]>((_resolve, reject) => {
        reject4 = reject;
      }),
      resolve6: async () => new Promise<string[]>((_resolve, reject) => {
        reject6 = reject;
      }),
      cancel: () => {
        cancelCount += 1;
        reject4?.(cancelled);
        reject6?.(cancelled);
      },
    }),
    httpsRequest: () => {
      throw new Error('HTTPS must not start before DNS completes.');
    },
  });

  await assert.rejects(
    resolveOAuthClient(CLIENT_ID, { ...options(), timeoutMs: 100 }),
    /invalid or unavailable/,
  );
  assert.ok(cancelCount >= 1);
  assert.equal(deadline.active.size, 0);
});

test('CIMD absolute deadline destroys a default HTTPS request before response', async () => {
  const deadline = trackedDeadline();
  const request = new ControlledRequest();
  setOAuthClientMetadataDependenciesForTests({
    ...deadline,
    resolve: async () => [PUBLIC_ADDRESS],
    httpsRequest: () => request as unknown as ClientRequest,
  });

  await assert.rejects(
    resolveOAuthClient(CLIENT_ID, { ...options(), timeoutMs: 100 }),
    /invalid or unavailable/,
  );
  assert.equal(request.ended, true);
  assert.equal(request.destroyed, true);
  assert.equal(deadline.active.size, 0);
});

test('CIMD absolute deadline destroys a stalled default HTTPS response', async () => {
  const deadline = trackedDeadline();
  const request = new ControlledRequest();
  const body = controlledResponse();
  setOAuthClientMetadataDependenciesForTests({
    ...deadline,
    resolve: async () => [PUBLIC_ADDRESS],
    httpsRequest: (_url, _requestOptions, onResponse) => {
      request.onEnd = () => queueMicrotask(() =>
        onResponse(body as unknown as IncomingMessage));
      return request as unknown as ClientRequest;
    },
  });

  await assert.rejects(
    resolveOAuthClient(CLIENT_ID, { ...options(), timeoutMs: 100 }),
    /invalid or unavailable/,
  );
  assert.equal(request.destroyed, true);
  assert.equal(body.destroyed, true);
  assert.equal(deadline.active.size, 0);
});

test('CIMD absolute deadline stops a continuously trickling default HTTPS body', async () => {
  const deadline = trackedDeadline();
  const request = new ControlledRequest();
  const body = controlledResponse();
  let chunks = 0;
  let trickle: ReturnType<typeof setInterval> | undefined;
  body.once('close', () => {
    if (trickle) clearInterval(trickle);
  });
  setOAuthClientMetadataDependenciesForTests({
    ...deadline,
    resolve: async () => [PUBLIC_ADDRESS],
    httpsRequest: (_url, _requestOptions, onResponse) => {
      request.onEnd = () => queueMicrotask(() => {
        onResponse(body as unknown as IncomingMessage);
        trickle = setInterval(() => {
          chunks += 1;
          body.write(' ');
        }, 10);
      });
      return request as unknown as ClientRequest;
    },
  });

  const startedAt = performance.now();
  await assert.rejects(
    resolveOAuthClient(CLIENT_ID, { ...options(), timeoutMs: 100 }),
    /invalid or unavailable/,
  );
  const elapsed = performance.now() - startedAt;
  const chunksAtAbort = chunks;
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.ok(elapsed >= 75 && elapsed < 500, `deadline elapsed ${elapsed}ms`);
  assert.ok(chunksAtAbort > 1);
  assert.equal(chunks, chunksAtAbort);
  assert.equal(request.destroyed, true);
  assert.equal(body.destroyed, true);
  assert.equal(deadline.active.size, 0);
});

test('CIMD successful default HTTPS completion clears its deadline', async () => {
  const deadline = trackedDeadline();
  const request = new ControlledRequest();
  const body = controlledResponse();
  setOAuthClientMetadataDependenciesForTests({
    ...deadline,
    resolve: async () => [PUBLIC_ADDRESS],
    httpsRequest: (_url, _requestOptions, onResponse) => {
      request.onEnd = () => queueMicrotask(() => {
        onResponse(body as unknown as IncomingMessage);
        body.end(JSON.stringify(metadata()));
      });
      return request as unknown as ClientRequest;
    },
  });

  assert.equal(
    (await resolveOAuthClient(CLIENT_ID, { ...options(), timeoutMs: 100 })).source,
    'cimd',
  );
  await new Promise((resolve) => setTimeout(resolve, 125));
  assert.equal(request.destroyed, false);
  assert.equal(deadline.active.size, 0);
});
