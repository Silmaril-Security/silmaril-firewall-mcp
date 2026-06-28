import assert from 'node:assert/strict';
import test, { afterEach, beforeEach } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { handleMcpRequest } from '../src/http';
import { readConfig } from '../src/config';
import { getFirewallMcpPublicConfig } from '../src/firewall-ui-config';
import { firewallGetJson, FirewallApiError } from '../src/firewall-ui-client';
import { handleProtectedResourceMetadataRequest } from '../src/oauth-metadata';
import {
  handleAuthorizationRequest,
  handleAuthorizationServerMetadataRequest,
  handleClientRegistrationRequest,
  handleOAuthCallbackRequest,
  handleTokenRequest,
} from '../src/oauth-authorization-server';

const originalFetch = globalThis.fetch;
const originalEnv = { ...process.env };

interface UpstreamCall {
  url: string;
  authorization: string | null;
  body: string | null;
}

let upstreamCalls: UpstreamCall[] = [];
let auditCalls: UpstreamCall[] = [];
let tokenCalls: UpstreamCall[] = [];
let publicConfigOverride: Record<string, unknown> = {};

beforeEach(() => {
  upstreamCalls = [];
  auditCalls = [];
  tokenCalls = [];
  publicConfigOverride = {};
  process.env.FIREWALL_UI_BASE_URL = 'https://firewall.test';
  process.env.MCP_ADDITIONAL_ALLOWED_ORIGINS = 'https://codex.test';
  delete process.env.MCP_ALLOWED_ORIGINS;
  delete process.env.AUTH0_MCP_AUDIENCE;
  process.env.MCP_PUBLIC_BASE_URL = 'https://mcp.test';
  delete process.env.MCP_AUTH0_ORGANIZATION;
  delete process.env.MCP_AUDIT_URL;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  process.env = { ...originalEnv };
});

function json(payload: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(payload), {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
}

function requestFrom(input: string | URL | Request, init?: RequestInit): Request {
  return input instanceof Request ? input : new Request(input, init);
}

function installMockFetch() {
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const req = requestFrom(input, init);
    const url = new URL(req.url);

    if (url.hostname === 'mcp.test') {
      return handleMcpRequest(req);
    }

    if (url.hostname === 'audit.test') {
      auditCalls.push({
        url: req.url,
        authorization: req.headers.get('authorization'),
        body: await req.text(),
      });
      return json({ ok: true });
    }

    if (url.hostname === 'tenant.example.auth0.com') {
      if (
        url.pathname === '/.well-known/oauth-authorization-server' ||
        url.pathname === '/.well-known/openid-configuration'
      ) {
        return json({
          issuer: 'https://tenant.example.auth0.com/',
          authorization_endpoint: 'https://tenant.example.auth0.com/authorize',
          token_endpoint: 'https://tenant.example.auth0.com/oauth/token',
          registration_endpoint: 'https://tenant.example.auth0.com/oidc/register',
          code_challenge_methods_supported: ['S256', 'plain'],
          grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
          response_types_supported: ['code', 'token'],
        });
      }

      if (url.pathname === '/oauth/token') {
        tokenCalls.push({
          url: req.url,
          authorization: req.headers.get('authorization'),
          body: await req.text(),
        });
        return json({
          access_token: 'upstream-access-token',
          refresh_token: 'upstream-refresh-token',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'firewalls:read metrics:read',
        });
      }

      throw new Error(`unexpected auth0 fixture path ${url.pathname}`);
    }

    if (url.hostname !== 'firewall.test') {
      throw new Error(`unexpected fetch host ${url.hostname}`);
    }

    upstreamCalls.push({
      url: req.url,
      authorization: req.headers.get('authorization'),
      body: await req.text(),
    });

    if (url.pathname === '/api/mcp/v1/config') {
      return json({
        version: 'v1',
        enabled: true,
        issuer: 'https://tenant.example.auth0.com/',
        authorization_servers: ['https://tenant.example.auth0.com/'],
        audience: 'https://silmaril.security/firewall-ui/mcp-test',
        resource: 'https://silmaril.security/firewall-ui/mcp-test',
        scopes: [
          'firewalls:read',
          'metrics:read',
          'findings:read',
          'findings:detail',
          'payload:read',
          'trace:read',
        ],
        oauth: {
          client_id: 'public-mcp-client-id',
          client_id_source: 'AUTH0_MCP_CLIENT_ID',
        },
        ...publicConfigOverride,
      });
    }

    if (url.pathname === '/api/mcp/v1/firewalls') {
      return json({
        items: [{
          firewall_id: 'yc-prod-us-west-2',
          runtime: 'sagemaker',
          capabilities: { trace: { state: 'available' } },
          generated_at: '2026-06-27T00:00:00.000Z',
        }],
      });
    }

    if (url.pathname === '/api/mcp/v1/firewalls/yc-prod-us-west-2') {
      return json({
        firewall_id: 'yc-prod-us-west-2',
        runtime: 'sagemaker',
        capabilities: { trace: { state: 'available' } },
      });
    }

    if (url.pathname === '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/qa-find-001') {
      return json({
        firewall: { firewall_id: 'yc-prod-us-west-2' },
        finding: {
          evidence_id: 'yc-prod-us-west-2:qa-find-001',
          text: 'CANARY_SECRET_SHOULD_NOT_APPEAR_IN_LOGS',
        },
      });
    }

    if (url.pathname === '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/missing-finding') {
      return json({ error: { code: 'finding_not_found', message: 'Finding not found.' } }, { status: 404 });
    }

    if (url.pathname === '/api/mcp/v1/firewalls/forbidden-prod-us-west-2') {
      return json({ error: { code: 'firewall_not_found', message: 'Firewall not found.' } }, { status: 404 });
    }

    return json({ error: { code: 'not_found', message: 'Unknown fixture path.' } }, { status: 404 });
  }) as typeof fetch;
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(predicate(), true);
}

async function connectedClient() {
  installMockFetch();
  const client = new Client({ name: 'mcp-test-client', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL('https://mcp.test/mcp'), {
    requestInit: {
      headers: {
        authorization: 'Bearer user-access-token',
        origin: 'https://codex.test',
      },
    },
    fetch: globalThis.fetch,
  });
  await client.connect(transport);
  return { client, transport };
}

test('initializes, lists tools, calls list_firewalls, and forwards bearer auth', async () => {
  const { client } = await connectedClient();
  const tools = await client.listTools();
  assert.ok(tools.tools.some((tool) => tool.name === 'list_firewalls'));
  assert.ok(tools.tools.some((tool) => tool.name === 'get_investigation_packet'));

  const result = await client.callTool({ name: 'list_firewalls', arguments: {} });
  assert.equal(result.isError, undefined);
  assert.equal((result.structuredContent as { items: Array<{ firewall_id: string }> }).items[0].firewall_id, 'yc-prod-us-west-2');
  assert.equal(upstreamCalls.at(-1)?.authorization, 'Bearer user-access-token');
});

test('rejects invalid Origin before MCP handling', async () => {
  installMockFetch();
  const response = await handleMcpRequest(new Request('https://mcp.test/mcp', {
    method: 'POST',
    headers: {
      authorization: 'Bearer user-access-token',
      origin: 'https://evil.test',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }));

  assert.equal(response.status, 403);
  assert.equal((await response.json()).error.code, 'origin_forbidden');
});

test('requires bearer auth on MCP requests', async () => {
  const response = await handleMcpRequest(new Request('https://mcp.test/mcp', {
    method: 'POST',
    headers: {
      origin: 'https://codex.test',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }));

  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, 'token_missing');
  const challenge = response.headers.get('www-authenticate') ?? '';
  assert.match(challenge, /^Bearer /);
  assert.match(challenge, /resource_metadata="https:\/\/mcp\.test\/\.well-known\/oauth-protected-resource\/mcp"/);
  assert.match(challenge, /scope="firewalls:read metrics:read findings:read"/);
});

test('rejects OAuth discovery without a configured public base URL', async () => {
  delete process.env.MCP_PUBLIC_BASE_URL;

  const response = await handleMcpRequest(new Request('https://attacker.example/mcp', {
    method: 'POST',
    headers: {
      origin: 'https://codex.test',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }));

  assert.equal(response.status, 503);
  assert.equal((await response.json()).error.code, 'mcp_oauth_metadata_unavailable');
  assert.equal(response.headers.get('www-authenticate'), null);
});

test('serves OAuth protected resource metadata from firewall-ui public config', async () => {
  installMockFetch();

  const response = await handleProtectedResourceMetadataRequest(
    new Request('https://mcp.test/.well-known/oauth-protected-resource/mcp'),
    readConfig(),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.resource, 'https://mcp.test/mcp');
  assert.deepEqual(body.authorization_servers, ['https://mcp.test']);
  assert.deepEqual(body.silmaril_upstream_authorization_servers, ['https://tenant.example.auth0.com/']);
  assert.equal(body.silmaril_oauth_resource, 'https://silmaril.security/firewall-ui/mcp-test');
  assert.equal(body.silmaril_oauth_client_id, 'public-mcp-client-id');
  assert.ok(body.scopes_supported.includes('firewalls:read'));
  assert.ok(body.scopes_supported.includes('trace:read'));
});

test('serves OAuth authorization server metadata with local registration bridge', async () => {
  installMockFetch();

  const response = await handleAuthorizationServerMetadataRequest(
    new Request('https://mcp.test/.well-known/oauth-authorization-server'),
    readConfig(),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.issuer, 'https://mcp.test');
  assert.equal(body.authorization_endpoint, 'https://mcp.test/oauth/authorize');
  assert.equal(body.token_endpoint, 'https://mcp.test/oauth/token');
  assert.equal(body.registration_endpoint, 'https://mcp.test/oauth/register');
  assert.deepEqual(body.response_types_supported, ['code']);
  assert.ok(body.grant_types_supported.includes('authorization_code'));
  assert.ok(body.grant_types_supported.includes('refresh_token'));
  assert.deepEqual(body.token_endpoint_auth_methods_supported, ['none']);
  assert.ok(body.code_challenge_methods_supported.includes('S256'));
  assert.ok(body.scopes_supported.includes('findings:detail'));
});

test('authorization bridge redirects Auth0 back through the fixed MCP callback', async () => {
  installMockFetch();
  process.env.MCP_AUTH0_ORGANIZATION = 'org_silmaril';

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      state: 'codex-state',
      scope: 'firewalls:read metrics:read',
      code_challenge: 'pkce-challenge',
      code_challenge_method: 'S256',
    }).toString()),
    readConfig(),
  );
  const location = new URL(response.headers.get('location') ?? '');

  assert.equal(response.status, 302);
  assert.equal(location.origin, 'https://tenant.example.auth0.com');
  assert.equal(location.pathname, '/authorize');
  assert.equal(location.searchParams.get('client_id'), 'public-mcp-client-id');
  assert.equal(location.searchParams.get('redirect_uri'), 'https://mcp.test/oauth/callback');
  assert.equal(location.searchParams.get('audience'), 'https://silmaril.security/firewall-ui/mcp-test');
  assert.equal(location.searchParams.get('code_challenge'), 'pkce-challenge');
  assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(location.searchParams.get('organization'), 'org_silmaril');

  const callback = await handleOAuthCallbackRequest(
    new Request('https://mcp.test/oauth/callback?' + new URLSearchParams({
      code: 'auth0-code',
      state: location.searchParams.get('state') ?? '',
    }).toString()),
  );
  const callbackLocation = new URL(callback.headers.get('location') ?? '');

  assert.equal(callback.status, 302);
  assert.equal(callbackLocation.origin, 'http://127.0.0.1:1455');
  assert.equal(callbackLocation.pathname, '/oauth/callback');
  assert.equal(callbackLocation.searchParams.get('code'), 'auth0-code');
  assert.equal(callbackLocation.searchParams.get('state'), 'codex-state');
});

test('authorization bridge preserves explicit client organization over default', async () => {
  installMockFetch();
  process.env.MCP_AUTH0_ORGANIZATION = 'org_default';

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      state: 'codex-state',
      organization: 'org_explicit',
    }).toString()),
    readConfig(),
  );
  const location = new URL(response.headers.get('location') ?? '');

  assert.equal(response.status, 302);
  assert.equal(location.searchParams.get('organization'), 'org_explicit');
});

test('authorization bridge rejects non-loopback client callbacks', async () => {
  installMockFetch();

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'https://attacker.test/callback',
    }).toString()),
    readConfig(),
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'invalid_request');
});

test('token bridge exchanges authorization code with fixed MCP callback and PKCE verifier', async () => {
  installMockFetch();

  const response = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'public-mcp-client-id',
        code: 'auth0-code',
        redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
        code_verifier: 'codex-pkce-verifier',
      }).toString(),
    }),
    readConfig(),
  );
  const body = await response.json();
  const upstreamBody = new URLSearchParams(tokenCalls[0].body ?? '');

  assert.equal(response.status, 200);
  assert.equal(body.access_token, 'upstream-access-token');
  assert.equal(tokenCalls.length, 1);
  assert.equal(tokenCalls[0].authorization, null);
  assert.equal(upstreamBody.get('grant_type'), 'authorization_code');
  assert.equal(upstreamBody.get('client_id'), 'public-mcp-client-id');
  assert.equal(upstreamBody.get('code'), 'auth0-code');
  assert.equal(upstreamBody.get('redirect_uri'), 'https://mcp.test/oauth/callback');
  assert.equal(upstreamBody.get('code_verifier'), 'codex-pkce-verifier');
});

test('dynamic client registration returns configured public OAuth client', async () => {
  installMockFetch();

  const response = await handleClientRegistrationRequest(
    new Request('https://mcp.test/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['http://127.0.0.1:1455/oauth/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scope: 'firewalls:read metrics:read',
        client_name: 'Codex',
      }),
    }),
    readConfig(),
  );
  const body = await response.json();

  assert.equal(response.status, 201);
  assert.equal(body.client_id, 'public-mcp-client-id');
  assert.deepEqual(body.redirect_uris, ['http://127.0.0.1:1455/oauth/callback']);
  assert.deepEqual(body.grant_types, ['authorization_code']);
  assert.deepEqual(body.response_types, ['code']);
  assert.equal(body.token_endpoint_auth_method, 'none');
  assert.equal(body.scope, 'firewalls:read metrics:read');
  assert.equal(body.client_name, 'Codex');
});

test('OAuth metadata ignores request-controlled forwarded host headers', async () => {
  installMockFetch();

  const response = await handleProtectedResourceMetadataRequest(
    new Request('https://mcp.test/.well-known/oauth-protected-resource/mcp', {
      headers: {
        'x-forwarded-host': 'attacker.example',
        'x-forwarded-proto': 'https',
      },
    }),
    readConfig(),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.resource, 'https://mcp.test/mcp');
  assert.equal(body.resource.includes('attacker.example'), false);
});

test('refreshes firewall-ui public OAuth config before using it', async () => {
  installMockFetch();
  const config = readConfig();

  const first = await getFirewallMcpPublicConfig(config);
  publicConfigOverride = { enabled: false };

  assert.equal(first.audience, 'https://silmaril.security/firewall-ui/mcp-test');
  await assert.rejects(
    () => getFirewallMcpPublicConfig(config),
    /firewall-ui MCP API is disabled/,
  );
  const configCalls = upstreamCalls.filter((call) =>
    new URL(call.url).pathname === '/api/mcp/v1/config');
  assert.equal(configCalls.length, 2);
  assert.equal(configCalls[0].authorization, null);
  assert.equal(configCalls[1].authorization, null);
});

test('rejects disabled firewall-ui public OAuth config without caching it', async () => {
  installMockFetch();
  publicConfigOverride = { enabled: false };
  const config = readConfig();

  await assert.rejects(
    () => getFirewallMcpPublicConfig(config),
    /firewall-ui MCP API is disabled/,
  );

  publicConfigOverride = {};
  const recovered = await getFirewallMcpPublicConfig(config);
  assert.equal(recovered.enabled, true);
});

test('uses audience as resource for older firewall-ui public config responses', async () => {
  installMockFetch();
  publicConfigOverride = {
    resource: undefined,
    audience: 'https://silmaril.security/firewall-ui/mcp-legacy',
  };

  const config = await getFirewallMcpPublicConfig(readConfig());

  assert.equal(config.audience, 'https://silmaril.security/firewall-ui/mcp-legacy');
  assert.equal(config.resource, 'https://silmaril.security/firewall-ui/mcp-legacy');
});

test('normalizes firewall-ui errors into MCP tool errors', async () => {
  const { client } = await connectedClient();
  const result = await client.callTool({
    name: 'get_firewall',
    arguments: { firewall_id: 'forbidden-prod-us-west-2' },
  });

  assert.equal(result.isError, true);
  const structured = result.structuredContent as { error: { status: number; code: string } };
  assert.equal(structured.error.status, 404);
  assert.equal(structured.error.code, 'firewall_not_found');
});

test('detail access audits metadata only and does not log payload text', async () => {
  const logLines: string[] = [];
  const originalConsole = {
    log: console.log,
    warn: console.warn,
    error: console.error,
  };
  console.log = (...args: unknown[]) => { logLines.push(args.join(' ')); };
  console.warn = (...args: unknown[]) => { logLines.push(args.join(' ')); };
  console.error = (...args: unknown[]) => { logLines.push(args.join(' ')); };
  process.env.MCP_AUDIT_URL = 'https://audit.test/events';

  try {
    const { client } = await connectedClient();
    const result = await client.callTool({
      name: 'get_finding',
      arguments: {
        firewall_id: 'yc-prod-us-west-2',
        finding_id: 'qa-find-001',
        reason: 'Investigating alert evidence citation.',
      },
    });

    assert.equal(result.isError, undefined);
    await waitFor(() => auditCalls.length === 1);
    assert.equal(auditCalls.length, 1);
    assert.match(auditCalls[0].body ?? '', /Investigating alert evidence citation/);
    assert.doesNotMatch(auditCalls[0].body ?? '', /CANARY_SECRET/);
    assert.equal(logLines.join('\n').includes('CANARY_SECRET'), false);
  } finally {
    console.log = originalConsole.log;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
  }
});

test('failed detail reads are not recorded as successful audit events', async () => {
  process.env.MCP_AUDIT_URL = 'https://audit.test/events';
  const { client } = await connectedClient();
  const result = await client.callTool({
    name: 'get_finding',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      finding_id: 'missing-finding',
      reason: 'Investigating a stale finding handle.',
    },
  });

  assert.equal(result.isError, true);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(auditCalls.length, 0);
});

test('response cap is clamped to the hard ceiling', () => {
  process.env.MCP_MAX_RESPONSE_BYTES = '999999999999';
  assert.equal(readConfig().maxResponseBytes, 5_000_000);
});

test('chunked upstream responses are rejected as soon as they exceed the size cap', async () => {
  globalThis.fetch = (async () =>
    new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"value":"'));
        controller.enqueue(new TextEncoder().encode('x'.repeat(32)));
        controller.enqueue(new TextEncoder().encode('"}'));
        controller.close();
      },
    }), {
      headers: { 'content-type': 'application/json' },
    })) as typeof fetch;

  await assert.rejects(
    () => firewallGetJson({
      path: '/api/mcp/v1/firewalls',
      token: 'user-access-token',
      config: {
        firewallUiBaseUrl: 'https://firewall.test',
        allowedOrigins: [],
        maxResponseBytes: 16,
        auditUrl: null,
        publicBaseUrl: null,
        auth0Organization: null,
      },
    }),
    (err) =>
      err instanceof FirewallApiError &&
      err.status === 413 &&
      err.code === 'upstream_response_too_large',
  );
});
