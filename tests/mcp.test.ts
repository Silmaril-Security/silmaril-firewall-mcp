import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
let totalsEnvelope: 'blocked' | 'nested-total' | 'top-level-total' = 'blocked';

beforeEach(() => {
  upstreamCalls = [];
  auditCalls = [];
  tokenCalls = [];
  publicConfigOverride = {};
  totalsEnvelope = 'blocked';
  process.env.FIREWALL_UI_BASE_URL = 'https://firewall.test';
  process.env.MCP_ADDITIONAL_ALLOWED_ORIGINS = 'https://codex.test';
  delete process.env.MCP_ALLOWED_ORIGINS;
  delete process.env.AUTH0_MCP_AUDIENCE;
  process.env.MCP_PUBLIC_BASE_URL = 'https://mcp.test';
  process.env.MCP_OAUTH_STATE_SECRET = 'test-oauth-state-secret-with-enough-entropy';
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

function s256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
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

    if (url.pathname === '/api/mcp/v1/schema') {
      return json({
        version: 'v1',
        scopes: ['firewalls:read', 'metrics:read', 'findings:read'],
        time_ranges: ['5m', '15m', '30m', '1h', '3h', '6h', '12h', '1d', '3d', '1w', '30d'],
        suspicious_users: {
          endpoint: '/api/mcp/v1/firewalls/:envKey/findings/users/suspicious',
          scopes: ['findings:read'],
          abuse_categories: [
            'ai_control_abuse',
            'data_exfiltration',
            'secret_or_prompt_theft',
            'system_or_account_compromise',
            'service_disruption_or_cost_abuse',
            'nsfw_content_abuse',
            'model_distillation',
            'other_harmful_attempt',
          ],
          correlation_signals: [
            'new_user_burst',
            'workspace_churn',
            'limit_burn_proxy',
            'prompt_campaign_reuse',
            'runtime_identity_reuse',
            'shared_ja4_fingerprint',
          ],
          defaults: {
            range: '1d',
            min_findings: 2,
            user_limit: 25,
            candidate_limit: 2000,
            lookback_candidate_limit: 5000,
            lookback_window: '30d',
          },
        },
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

    if (url.pathname === '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings') {
      return json({
        items: [],
        match_count: 0,
        received: Object.fromEntries(url.searchParams),
      });
    }

    if (url.pathname === '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/users/suspicious') {
      return json({
        firewall: { firewall_id: 'yc-prod-us-west-2' },
        time_window: url.searchParams.get('range') ?? '1d',
        filters: {
          abuse_categories: url.searchParams.getAll('category').length
            ? url.searchParams.getAll('category')
            : 'all',
          min_findings: Number(url.searchParams.get('minFindings') ?? 2),
          user_limit: Number(url.searchParams.get('limit') ?? 25),
          candidate_limit: Number(url.searchParams.get('candidateLimit') ?? 2000),
          lookback_candidate_limit: Number(url.searchParams.get('lookbackCandidateLimit') ?? 5000),
          lookback_window: '30d',
        },
        users: [{
          user_id: 'qa-risk-user-001',
          user_id_kind: 'metadata.userId',
          translated_user_id: null,
          workspace_ids: ['qa-workspace-001'],
          primary_workspace_id: 'qa-workspace-001',
          primary_abuse_category: 'model_distillation',
          abuse_category_counts: {
            model_distillation: 2,
            nsfw_content_abuse: 1,
          },
          risk_class_counts: {
            control_abuse: 2,
          },
          suspicious_score: 84,
          findings: { suspicious: 2 },
          conversations: {
            suspicious: 2,
            observed_total_with_findings: 2,
            observed_malicious_percent: 100,
            all_ai_conversation_percent: null,
          },
          account_farming: {
            observed_score: 42,
            max_possible_score: 72,
            signals: {
              new_user_burst: {
                available: true,
                score: 20,
                level: 'strong',
                metrics: { first_seen_users: 3 },
                evidence: ['3 first-seen users share workspace/category/signature'],
                version: 'v1',
              },
              workspace_churn: {
                available: true,
                score: 10,
                level: 'moderate',
                metrics: { distinct_suspicious_users_in_workspace_category: 3 },
                evidence: ['3 suspicious users share workspace/category'],
                version: 'v1',
              },
              limit_burn_proxy: {
                available: true,
                score: 12,
                level: 'moderate',
                metrics: { suspicious_conversations: 2 },
                evidence: ['multiple suspicious conversations'],
                version: 'v1',
              },
              prompt_campaign_reuse: {
                available: true,
                score: 0,
                level: 'none',
                metrics: {},
                evidence: [],
                version: 'v1',
              },
              runtime_identity_reuse: {
                available: false,
                score: null,
                level: 'unavailable',
                metrics: { reason: 'runtime_identity_unavailable' },
                evidence: [],
                version: 'v1',
              },
              shared_ja4_fingerprint: {
                available: false,
                score: null,
                level: 'unavailable',
                metrics: { reason: 'ja4_unavailable' },
                evidence: [],
                version: 'v1',
              },
            },
          },
          reason_codes: ['model_distillation', 'multiple_suspicious_conversations', 'new_user_burst'],
          evidence_handles: [{
            evidence_id: 'yc-prod-us-west-2:qa-risk-find-001',
            finding_id: 'qa-risk-find-001',
            firewall_id: 'yc-prod-us-west-2',
          }],
        }],
        diagnostics: {
          missing_identity_counts: {
            user_id: 0,
            workspace_id: 0,
            conversation_id: 0,
            runtime_identity: 1,
            ja4: 2,
          },
          candidate_findings: 2,
          candidate_findings_truncated: false,
          lookback_findings: 4,
          lookback_findings_truncated: false,
          returned_users: 1,
          matched_users: 1,
        },
        generated_at: '2026-07-07T00:00:00.000Z',
        received: Object.fromEntries(url.searchParams),
        received_category: url.searchParams.getAll('category'),
      });
    }

    if (url.pathname === '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/totals') {
      const triage = url.searchParams.get('triage');
      const counts: Record<string, number> = {
        true_positive: 7,
        false_positive: 3,
        triaged: 10,
        untriaged: 2,
      };
      const count = triage ? counts[triage] ?? 0 : 12;
      if (totalsEnvelope === 'nested-total') {
        return json({
          time_window: url.searchParams.get('range') ?? '1d',
          totals: {
            total: count,
            blockedMetricReady: true,
          },
          generated_at: '2026-06-27T00:00:00.000Z',
          received: Object.fromEntries(url.searchParams),
        });
      }
      if (totalsEnvelope === 'top-level-total') {
        return json({
          time_window: url.searchParams.get('range') ?? '1d',
          total: count,
          blockedMetricReady: true,
          generated_at: '2026-06-27T00:00:00.000Z',
          received: Object.fromEntries(url.searchParams),
        });
      }
      return json({
        time_window: url.searchParams.get('range') ?? '1d',
        totals: {
          blocked: count,
          blockedMetricReady: true,
          total: 50,
        },
        generated_at: '2026-06-27T00:00:00.000Z',
        received: Object.fromEntries(url.searchParams),
      });
    }

    if (url.pathname === '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/group') {
      return json({
        by: url.searchParams.get('by'),
        items: [],
        received: Object.fromEntries(url.searchParams),
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
  assert.ok(tools.tools.some((tool) => tool.name === 'get_schema'));
  assert.ok(tools.tools.some((tool) => tool.name === 'list_suspicious_users'));
  assert.ok(tools.tools.some((tool) => tool.name === 'get_investigation_packet'));

  const result = await client.callTool({ name: 'list_firewalls', arguments: {} });
  assert.equal(result.isError, undefined);
  assert.equal((result.structuredContent as { items: Array<{ firewall_id: string }> }).items[0].firewall_id, 'yc-prod-us-west-2');
  assert.equal(upstreamCalls.at(-1)?.authorization, 'Bearer user-access-token');
});

test('get_schema exposes suspicious-users contract through MCP', async () => {
  const { client } = await connectedClient();
  const result = await client.callTool({ name: 'get_schema', arguments: {} });

  assert.equal(result.isError, undefined);
  const body = result.structuredContent as {
    suspicious_users: {
      endpoint: string;
      scopes: string[];
      abuse_categories: string[];
      correlation_signals: string[];
      defaults: { candidate_limit: number; lookback_candidate_limit: number };
    };
  };
  assert.equal(body.suspicious_users.endpoint, '/api/mcp/v1/firewalls/:envKey/findings/users/suspicious');
  assert.deepEqual(body.suspicious_users.scopes, ['findings:read']);
  assert.ok(body.suspicious_users.abuse_categories.includes('nsfw_content_abuse'));
  assert.ok(body.suspicious_users.abuse_categories.includes('model_distillation'));
  assert.ok(body.suspicious_users.correlation_signals.includes('shared_ja4_fingerprint'));
  assert.equal(body.suspicious_users.defaults.candidate_limit, 2000);
  assert.equal(body.suspicious_users.defaults.lookback_candidate_limit, 5000);

  const lastUrl = new URL(upstreamCalls.at(-1)?.url ?? '');
  assert.equal(lastUrl.pathname, '/api/mcp/v1/schema');
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
  assert.deepEqual(body.code_challenge_methods_supported, ['S256']);
  assert.ok(body.scopes_supported.includes('findings:detail'));
});

test('authorization bridge redirects Auth0 back through the fixed MCP callback', async () => {
  installMockFetch();

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
  assert.equal(location.searchParams.get('organization'), null);

  const callback = await handleOAuthCallbackRequest(
    new Request('https://mcp.test/oauth/callback?' + new URLSearchParams({
      code: 'auth0-code',
      state: location.searchParams.get('state') ?? '',
    }).toString()),
    readConfig(),
  );
  const callbackLocation = new URL(callback.headers.get('location') ?? '');

  assert.equal(callback.status, 302);
  assert.equal(callbackLocation.origin, 'http://127.0.0.1:1455');
  assert.equal(callbackLocation.pathname, '/oauth/callback');
  assert.ok(callbackLocation.searchParams.get('code'));
  assert.notEqual(callbackLocation.searchParams.get('code'), 'auth0-code');
  assert.equal(callbackLocation.searchParams.get('state'), 'codex-state');
});

test('authorization bridge applies explicit single-org deployment override', async () => {
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
  assert.equal(location.searchParams.get('organization'), 'org_silmaril');
});

test('authorization bridge rejects forged callback state', async () => {
  installMockFetch();
  const forgedPayload = Buffer.from(JSON.stringify({
    v: 1,
    redirect_uri: 'http://127.0.0.1:9999/oauth/callback',
    client_id: 'public-mcp-client-id',
    code_challenge: 'pkce-challenge',
    code_challenge_method: 'S256',
    iat: Date.now(),
    nonce: 'forged',
    state: 'attacker-state',
  }), 'utf8').toString('base64url');

  const response = await handleOAuthCallbackRequest(
    new Request('https://mcp.test/oauth/callback?' + new URLSearchParams({
      code: 'auth0-code',
      state: `${forgedPayload}.invalid-signature`,
    }).toString()),
    readConfig(),
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error_description, 'Invalid OAuth bridge state.');
});

test('authorization bridge preserves explicit client Auth0 organization over default', async () => {
  installMockFetch();
  process.env.MCP_AUTH0_ORGANIZATION = 'org_default';

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      state: 'codex-state',
      organization: 'org_clickup',
      code_challenge: 'pkce-challenge',
      code_challenge_method: 'S256',
    }).toString()),
    readConfig(),
  );
  const location = new URL(response.headers.get('location') ?? '');

  assert.equal(response.status, 302);
  assert.equal(location.searchParams.get('organization'), 'org_clickup');
});

test('authorization bridge rejects non-Auth0 organization values locally', async () => {
  installMockFetch();

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      state: 'codex-state',
      organization: 'clickup',
      code_challenge: 'pkce-challenge',
      code_challenge_method: 'S256',
    }).toString()),
    readConfig(),
  );
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, 'invalid_request');
  assert.match(body.error_description, /organization must be an Auth0 organization id/);
});

test('authorization bridge rejects invalid single-org deployment override locally', async () => {
  installMockFetch();
  process.env.MCP_AUTH0_ORGANIZATION = 'clickup';

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      state: 'codex-state',
      code_challenge: 'pkce-challenge',
      code_challenge_method: 'S256',
    }).toString()),
    readConfig(),
  );
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.equal(body.error, 'server_error');
  assert.match(body.error_description, /MCP_AUTH0_ORGANIZATION must be an Auth0 organization id/);
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

test('authorization bridge requires S256 PKCE', async () => {
  installMockFetch();

  const missingChallenge = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
    }).toString()),
    readConfig(),
  );
  const plainChallenge = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      code_challenge: 'pkce-challenge',
      code_challenge_method: 'plain',
    }).toString()),
    readConfig(),
  );

  assert.equal(missingChallenge.status, 400);
  assert.equal((await missingChallenge.json()).error_description, 'S256 PKCE is required for authorization code flow.');
  assert.equal(plainChallenge.status, 400);
  assert.equal((await plainChallenge.json()).error_description, 'S256 PKCE is required for authorization code flow.');
});

test('token bridge exchanges authorization code with fixed MCP callback and PKCE verifier', async () => {
  installMockFetch();
  const codeVerifier = 'codex-pkce-verifier';
  const clientRedirectUri = 'http://127.0.0.1:1455/oauth/callback';
  const authCode = 'token-auth0-code';

  const authorization = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: clientRedirectUri,
      state: 'codex-state',
      code_challenge: s256Challenge(codeVerifier),
      code_challenge_method: 'S256',
    }).toString()),
    readConfig(),
  );
  const authorizationLocation = new URL(authorization.headers.get('location') ?? '');
  const callback = await handleOAuthCallbackRequest(
    new Request('https://mcp.test/oauth/callback?' + new URLSearchParams({
      code: authCode,
      state: authorizationLocation.searchParams.get('state') ?? '',
    }).toString()),
    readConfig(),
  );
  const callbackLocation = new URL(callback.headers.get('location') ?? '');
  const bridgeCode = callbackLocation.searchParams.get('code') ?? '';

  assert.equal(callback.status, 302);
  assert.notEqual(bridgeCode, authCode);

  const response = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'public-mcp-client-id',
        code: bridgeCode,
        redirect_uri: clientRedirectUri,
        code_verifier: codeVerifier,
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
  assert.equal(upstreamBody.get('code'), authCode);
  assert.equal(upstreamBody.get('redirect_uri'), 'https://mcp.test/oauth/callback');
  assert.equal(upstreamBody.get('code_verifier'), codeVerifier);
});

test('token bridge rejects authorization code exchange for a different loopback callback', async () => {
  installMockFetch();
  const codeVerifier = 'codex-pkce-verifier';
  const authCode = 'redirect-mismatch-code';
  const authorization = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: 'public-mcp-client-id',
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      code_challenge: s256Challenge(codeVerifier),
      code_challenge_method: 'S256',
    }).toString()),
    readConfig(),
  );
  const authorizationLocation = new URL(authorization.headers.get('location') ?? '');
  const callback = await handleOAuthCallbackRequest(
    new Request('https://mcp.test/oauth/callback?' + new URLSearchParams({
      code: authCode,
      state: authorizationLocation.searchParams.get('state') ?? '',
    }).toString()),
    readConfig(),
  );
  const bridgeCode = new URL(callback.headers.get('location') ?? '').searchParams.get('code') ?? '';

  const response = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'public-mcp-client-id',
        code: bridgeCode,
        redirect_uri: 'http://127.0.0.1:1456/oauth/callback',
        code_verifier: codeVerifier,
      }).toString(),
    }),
    readConfig(),
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'invalid_grant');
  assert.equal(tokenCalls.length, 0);
});

test('token bridge rejects authorization code exchange without PKCE verifier', async () => {
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
      }).toString(),
    }),
    readConfig(),
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error_description, 'authorization_code grant requires code_verifier.');
  assert.equal(tokenCalls.length, 0);
});

test('token bridge refresh allows omitted client id but rejects mismatches', async () => {
  installMockFetch();

  const response = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: 'stored-refresh-token',
      }).toString(),
    }),
    readConfig(),
  );
  const body = await response.json();
  const upstreamBody = new URLSearchParams(tokenCalls[0].body ?? '');

  assert.equal(response.status, 200);
  assert.equal(body.access_token, 'upstream-access-token');
  assert.equal(tokenCalls.length, 1);
  assert.equal(upstreamBody.get('grant_type'), 'refresh_token');
  assert.equal(upstreamBody.get('client_id'), 'public-mcp-client-id');
  assert.equal(upstreamBody.get('refresh_token'), 'stored-refresh-token');

  const mismatch = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: 'other-client-id',
        refresh_token: 'stored-refresh-token',
      }).toString(),
    }),
    readConfig(),
  );

  assert.equal(mismatch.status, 400);
  assert.equal((await mismatch.json()).error, 'invalid_client');
  assert.equal(tokenCalls.length, 1);
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

test('dynamic client registration rejects callbacks authorize would reject', async () => {
  installMockFetch();

  const response = await handleClientRegistrationRequest(
    new Request('https://mcp.test/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://client.example/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
      }),
    }),
    readConfig(),
  );
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, 'invalid_client_metadata');
  assert.equal(body.error_description, 'redirect_uris must be loopback callback URLs.');
});

test('dynamic client registration rejects unsupported OAuth capabilities', async () => {
  installMockFetch();

  const cases: Array<[Record<string, unknown>, string]> = [
    [{ grant_types: ['client_credentials'], response_types: ['code'] }, 'grant_types must only include authorization_code, refresh_token.'],
    [{ grant_types: ['authorization_code'], response_types: ['token'] }, 'response_types must only include code.'],
    [{
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    }, 'token_endpoint_auth_method must be none.'],
  ];

  for (const [metadata, expectedDescription] of cases) {
    const response = await handleClientRegistrationRequest(
      new Request('https://mcp.test/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['http://127.0.0.1:1455/oauth/callback'],
          ...metadata,
        }),
      }),
      readConfig(),
    );
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 'invalid_client_metadata');
    assert.equal(body.error_description, expectedDescription);
  }
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

test('finding tools forward triage and metadata filters to firewall-ui endpoints', async () => {
  const { client } = await connectedClient();
  const metadata = [
    { key: 'stage', value: 'prod' },
    { key: 'silmaril.request_id', value: 'req-123' },
  ];

  const totals = await client.callTool({
    name: 'get_finding_totals',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      range: '1d',
      triage: 'false_positive',
      metadata,
    },
  });
  assert.equal(totals.isError, undefined);
  assert.equal((totals.structuredContent as { totals: { blocked: number } }).totals.blocked, 3);
  let lastUrl = new URL(upstreamCalls.at(-1)?.url ?? '');
  assert.equal(lastUrl.pathname, '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/totals');
  assert.equal(lastUrl.searchParams.get('triage'), 'false_positive');
  assert.deepEqual(lastUrl.searchParams.getAll('meta'), ['stage=prod', 'silmaril.request_id=req-123']);

  const findings = await client.callTool({
    name: 'list_findings',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      triage: 'true_positive',
      metadata,
      pageSize: 25,
    },
  });
  assert.equal(findings.isError, undefined);
  lastUrl = new URL(upstreamCalls.at(-1)?.url ?? '');
  assert.equal(lastUrl.pathname, '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings');
  assert.equal(lastUrl.searchParams.get('triage'), 'true_positive');
  assert.deepEqual(lastUrl.searchParams.getAll('meta'), ['stage=prod', 'silmaril.request_id=req-123']);

  const grouped = await client.callTool({
    name: 'group_findings',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      by: 'hook',
      triage: 'false_positive',
      metadata,
    },
  });
  assert.equal(grouped.isError, undefined);
  lastUrl = new URL(upstreamCalls.at(-1)?.url ?? '');
  assert.equal(lastUrl.pathname, '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/group');
  assert.equal(lastUrl.searchParams.get('by'), 'hook');
  assert.equal(lastUrl.searchParams.get('triage'), 'false_positive');
  assert.deepEqual(lastUrl.searchParams.getAll('meta'), ['stage=prod', 'silmaril.request_id=req-123']);
});

test('list_suspicious_users forwards category filters and preserves correlation diagnostics', async () => {
  const { client } = await connectedClient();
  const metadata = [{ key: 'stage', value: 'prod' }];

  const result = await client.callTool({
    name: 'list_suspicious_users',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      range: '30d',
      categories: ['model_distillation', 'nsfw_content_abuse'],
      minFindings: 2,
      limit: 10,
      candidateLimit: 2000,
      lookbackCandidateLimit: 5000,
      metadata,
    },
  });

  assert.equal(result.isError, undefined);
  const body = result.structuredContent as {
    filters: {
      abuse_categories: string[];
      candidate_limit: number;
      lookback_candidate_limit: number;
    };
    users: Array<{
      user_id_kind: string;
      primary_abuse_category: string;
      abuse_category_counts: Record<string, number>;
      findings: { suspicious: number; true_positive?: number };
      account_farming: {
        observed_score: number;
        max_possible_score: number;
        signals: Record<string, { available: boolean; score: number | null; level: string }>;
      };
      evidence_handles: Array<{ evidence_id: string }>;
    }>;
    diagnostics: { missing_identity_counts: Record<string, number> };
    received_category: string[];
  };
  assert.deepEqual(body.filters.abuse_categories, ['model_distillation', 'nsfw_content_abuse']);
  assert.equal(body.filters.candidate_limit, 2000);
  assert.equal(body.filters.lookback_candidate_limit, 5000);
  assert.equal(body.users[0].user_id_kind, 'metadata.userId');
  assert.equal(body.users[0].primary_abuse_category, 'model_distillation');
  assert.equal(body.users[0].abuse_category_counts.nsfw_content_abuse, 1);
  assert.equal(body.users[0].findings.suspicious, 2);
  assert.equal(body.users[0].findings.true_positive, undefined);
  assert.equal(body.users[0].account_farming.signals.shared_ja4_fingerprint.available, false);
  assert.equal(body.users[0].account_farming.signals.shared_ja4_fingerprint.score, null);
  assert.equal(body.users[0].account_farming.signals.shared_ja4_fingerprint.level, 'unavailable');
  assert.ok(body.users[0].account_farming.observed_score < body.users[0].account_farming.max_possible_score);
  assert.equal(body.diagnostics.missing_identity_counts.ja4, 2);
  assert.equal(body.users[0].evidence_handles[0].evidence_id, 'yc-prod-us-west-2:qa-risk-find-001');
  assert.deepEqual(body.received_category, ['model_distillation', 'nsfw_content_abuse']);

  const lastUrl = new URL(upstreamCalls.at(-1)?.url ?? '');
  assert.equal(lastUrl.pathname, '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/users/suspicious');
  assert.deepEqual(lastUrl.searchParams.getAll('category'), ['model_distillation', 'nsfw_content_abuse']);
  assert.equal(lastUrl.searchParams.get('range'), '30d');
  assert.equal(lastUrl.searchParams.get('minFindings'), '2');
  assert.equal(lastUrl.searchParams.get('limit'), '10');
  assert.equal(lastUrl.searchParams.get('candidateLimit'), '2000');
  assert.equal(lastUrl.searchParams.get('lookbackCandidateLimit'), '5000');
  assert.deepEqual(lastUrl.searchParams.getAll('meta'), ['stage=prod']);
  assert.equal(upstreamCalls.at(-1)?.authorization, 'Bearer user-access-token');
});

test('list_suspicious_users rejects empty category arrays', async () => {
  const { client } = await connectedClient();

  const result = await client.callTool({
    name: 'list_suspicious_users',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      categories: [],
    },
  });

  assert.equal(result.isError, true);
  assert.equal(
    upstreamCalls.some((call) => new URL(call.url).pathname.endsWith('/findings/users/suspicious')),
    false,
  );
});

test('group_findings can aggregate exact counts by triage verdict', async () => {
  const { client } = await connectedClient();
  const metadata = [{ key: 'stage', value: 'prod' }];
  const result = await client.callTool({
    name: 'group_findings',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      by: 'triage',
      range: '1d',
      metadata,
    },
  });

  assert.equal(result.isError, undefined);
  const body = result.structuredContent as {
    by: string;
    exact_counts: boolean;
    triaged_count: number;
    items: Array<{ triage: string; count: number }>;
  };
  assert.equal(body.by, 'triage');
  assert.equal(body.exact_counts, true);
  assert.equal(body.triaged_count, 10);
  assert.deepEqual(
    body.items.map((item) => [item.triage, item.count]),
    [
      ['true_positive', 7],
      ['false_positive', 3],
      ['untriaged', 2],
    ],
  );

  const triageQueries = upstreamCalls
    .map((call) => new URL(call.url))
    .filter((url) => url.pathname === '/api/mcp/v1/firewalls/yc-prod-us-west-2/findings/totals')
    .map((url) => ({
      triage: url.searchParams.get('triage'),
      meta: url.searchParams.getAll('meta'),
    }));
  assert.deepEqual(triageQueries, [
    { triage: 'true_positive', meta: ['stage=prod'] },
    { triage: 'false_positive', meta: ['stage=prod'] },
    { triage: 'untriaged', meta: ['stage=prod'] },
  ]);
});

test('group_findings uses total fields when triage totals omit blocked', async () => {
  for (const envelope of ['nested-total', 'top-level-total'] as const) {
    totalsEnvelope = envelope;
    const { client } = await connectedClient();
    const result = await client.callTool({
      name: 'group_findings',
      arguments: {
        firewall_id: 'yc-prod-us-west-2',
        by: 'triage',
        range: '1d',
      },
    });

    assert.equal(result.isError, undefined);
    const body = result.structuredContent as {
      exact_counts: boolean;
      triaged_count: number;
      items: Array<{ triage: string; count: number }>;
    };
    assert.equal(body.exact_counts, true);
    assert.equal(body.triaged_count, 10);
    assert.deepEqual(
      body.items.map((item) => [item.triage, item.count]),
      [
        ['true_positive', 7],
        ['false_positive', 3],
        ['untriaged', 2],
      ],
    );
  }
});

test('group_findings reports triaged_count for explicit triaged filter', async () => {
  const { client } = await connectedClient();
  const result = await client.callTool({
    name: 'group_findings',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      by: 'triage',
      triage: 'triaged',
      range: '1d',
    },
  });

  assert.equal(result.isError, undefined);
  const body = result.structuredContent as {
    triaged_count: number;
    items: Array<{ triage: string; count: number }>;
  };
  assert.equal(body.triaged_count, 10);
  assert.deepEqual(body.items.map((item) => [item.triage, item.count]), [['triaged', 10]]);
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
        oauthStateSecret: null,
      },
    }),
    (err) =>
      err instanceof FirewallApiError &&
      err.status === 413 &&
      err.code === 'upstream_response_too_large',
  );
});
