import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test, { afterEach, beforeEach } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
} from 'jose';
import { handleMcpRequest } from '../src/http';
import { readConfig } from '../src/config';
import {
  getFirewallMcpPublicConfig,
  resetFirewallMcpPublicConfigCacheForTests,
} from '../src/firewall-ui-config';
import { firewallGetJson, FirewallApiError } from '../src/firewall-ui-client';
import { handleProtectedResourceMetadataRequest } from '../src/oauth-metadata';
import {
  handleAuthorizationRequest,
  handleAuthorizationServerMetadataRequest,
  handleClientRegistrationRequest,
  handleOAuthCallbackRequest,
  handleTokenRequest,
} from '../src/oauth-authorization-server';
import { issueMcpCredential, mcpResource } from '../src/oauth-credentials';
import { resetRateLimitsForTests } from '../src/rate-limit';

const originalFetch = globalThis.fetch;
const originalEnv = { ...process.env };
const upstreamSigningKeys = await generateKeyPair('RS256');
const upstreamPublicJwk = {
  ...await exportJWK(upstreamSigningKeys.publicKey),
  kid: 'qa-auth0-key',
  use: 'sig',
  alg: 'RS256',
};

interface UpstreamCall {
  url: string;
  authorization: string | null;
  body: string | null;
  activityKey?: string | null;
}

let upstreamCalls: UpstreamCall[] = [];
let auditCalls: UpstreamCall[] = [];
let activityCalls: UpstreamCall[] = [];
let tokenCalls: UpstreamCall[] = [];
let publicConfigOverride: Record<string, unknown> = {};
let totalsEnvelope: 'blocked' | 'nested-total' | 'top-level-total' = 'blocked';
let adminAccessAllowed = true;
let publicAccessAllowed = true;
let mcpMode: 'public' | 'admin' = 'public';
let deferredTasks: Promise<void>[] = [];
let activitySinkFails = false;
let auditSinkFails = false;
let upstreamAccessTokenOverride: string | null = null;
let omitRotatedRefreshToken = false;
let authMetadataOverride: Record<string, unknown> = {};

beforeEach(() => {
  upstreamCalls = [];
  auditCalls = [];
  activityCalls = [];
  tokenCalls = [];
  deferredTasks = [];
  publicConfigOverride = {};
  totalsEnvelope = 'blocked';
  adminAccessAllowed = true;
  publicAccessAllowed = true;
  mcpMode = 'public';
  activitySinkFails = false;
  auditSinkFails = false;
  upstreamAccessTokenOverride = null;
  omitRotatedRefreshToken = false;
  authMetadataOverride = {};
  resetFirewallMcpPublicConfigCacheForTests();
  resetRateLimitsForTests();
  process.env.FIREWALL_UI_BASE_URL = 'https://firewall.test';
  process.env.MCP_ADDITIONAL_ALLOWED_ORIGINS = 'https://codex.test';
  delete process.env.MCP_ALLOWED_ORIGINS;
  delete process.env.AUTH0_MCP_AUDIENCE;
  process.env.MCP_PUBLIC_BASE_URL = 'https://mcp.test';
  process.env.MCP_OAUTH_STATE_SECRET = 'test-oauth-state-secret-with-enough-entropy'; // pragma: allowlist secret
  delete process.env.MCP_AUTH0_ORGANIZATION;
  delete process.env.MCP_AUDIT_URL;
  delete process.env.MCP_MAX_REQUEST_BYTES;
  delete process.env.MCP_UPSTREAM_TIMEOUT_MS;
  delete process.env.MCP_PUBLIC_CONFIG_CACHE_MS;
  delete process.env.MCP_RATE_LIMIT_REQUESTS_PER_SECOND;
  delete process.env.MCP_RATE_LIMIT_BURST;
  delete process.env.MCP_AUDIT_TIMEOUT_MS;
  process.env.VERCEL_GIT_COMMIT_SHA = '321c91e-test';
  delete process.env.MCP_ACTIVITY_ENABLED;
  delete process.env.MCP_ACTIVITY_INGEST_KEY;
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

const TEST_CODE_VERIFIER = 'codex-pkce-verifier-with-at-least-forty-three-characters-001';
const TEST_CODE_CHALLENGE = s256Challenge(TEST_CODE_VERIFIER);

async function upstreamAccessToken(overrides: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({
    sub: 'auth0|user',
    iss: 'https://tenant.example.auth0.com/',
    aud: 'https://silmaril.security/firewall-ui/mcp-test',
    exp: Math.floor(Date.now() / 1000) + 3600,
    scope: 'firewalls:read metrics:read findings:read findings:detail payload:read trace:read',
    email: 'user@acme.com',
    org_id: 'org_acme',
    tenant: 'acme',
    jti: 'token-qa-001',
    ...overrides,
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'qa-auth0-key' })
    .sign(upstreamSigningKeys.privateKey);
}

function mcpAccessToken(
  mode: 'public' | 'admin' = 'public',
  grantedScopes = [
    'firewalls:read',
    'metrics:read',
    'findings:read',
    'findings:detail',
    'payload:read',
    'trace:read',
  ],
  clientId = 'dcr-test-client',
): string {
  const config = readConfig();
  return issueMcpCredential({
    kind: 'access',
    downstream_token: mode === 'admin' ? 'silmaril-admin-access-token' : 'user-access-token',
    client_id: clientId,
    resource: mcpResource(config, mode),
    scopes: grantedScopes,
    subject: 'auth0|user',
    organization: 'org_acme',
    tenant: 'acme',
    actor_email: 'user@acme.com',
    token_id: 'token-qa-001',
    expiresInSeconds: 3600,
  }, config);
}

async function registerClient(
  redirectUris = ['http://127.0.0.1:1455/oauth/callback'],
  scope = 'firewalls:read metrics:read findings:read findings:detail payload:read trace:read',
): Promise<string> {
  const response = await handleClientRegistrationRequest(
    new Request('https://mcp.test/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: redirectUris,
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        client_name: 'QA MCP Client',
        scope,
      }),
    }),
    readConfig(),
  );
  assert.equal(response.status, 201);
  return (await response.json()).client_id;
}

async function completeAuthorization(
  clientId: string,
  options: {
    redirectUri?: string;
    verifier?: string;
    organization?: string;
    resource?: string;
    state?: string;
    scope?: string;
  } = {},
): Promise<{
  authorization: Response;
  upstreamAuthorization: URL;
  callback: Response;
  bridgeCode: string;
  verifier: string;
  redirectUri: string;
}> {
  const redirectUri = options.redirectUri ?? 'http://127.0.0.1:1455/oauth/callback';
  const verifier = options.verifier ?? TEST_CODE_VERIFIER;
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    state: options.state ?? 'codex-state',
    scope: options.scope ?? 'firewalls:read metrics:read',
    resource: options.resource ?? 'https://mcp.test/mcp',
    code_challenge: s256Challenge(verifier),
    code_challenge_method: 'S256',
  });
  if (options.organization) params.set('organization', options.organization);
  const authorization = await handleAuthorizationRequest(
    new Request(`https://mcp.test/oauth/authorize?${params}`),
    readConfig(),
  );
  const upstreamAuthorization = new URL(authorization.headers.get('location') ?? '');
  const callback = await handleOAuthCallbackRequest(
    new Request('https://mcp.test/oauth/callback?' + new URLSearchParams({
      code: 'auth0-code',
      state: upstreamAuthorization.searchParams.get('state') ?? '',
    })),
    readConfig(),
  );
  const callbackLocation = new URL(callback.headers.get('location') ?? '');
  return {
    authorization,
    upstreamAuthorization,
    callback,
    bridgeCode: callbackLocation.searchParams.get('code') ?? '',
    verifier,
    redirectUri,
  };
}

function installMockFetch() {
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const req = requestFrom(input, init);
    const url = new URL(req.url);

    if (url.hostname === 'mcp.test') {
      return handleMcpRequest(req, {
        mode: mcpMode,
        defer: (task) => {
          deferredTasks.push(task());
        },
      });
    }

    if (url.hostname === 'audit.test') {
      auditCalls.push({
        url: req.url,
        authorization: req.headers.get('authorization'),
        body: await req.text(),
      });
      return auditSinkFails
        ? json({ error: 'audit unavailable' }, { status: 503 })
        : json({ ok: true });
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
          jwks_uri: 'https://tenant.example.auth0.com/.well-known/jwks.json',
          registration_endpoint: 'https://tenant.example.auth0.com/oidc/register',
          code_challenge_methods_supported: ['S256', 'plain'],
          grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
          response_types_supported: ['code', 'token'],
          ...authMetadataOverride,
        });
      }

      if (url.pathname === '/.well-known/jwks.json') {
        return json({ keys: [upstreamPublicJwk] });
      }

      if (url.pathname === '/oauth/token') {
        tokenCalls.push({
          url: req.url,
          authorization: req.headers.get('authorization'),
          body: await req.text(),
        });
        return json({
          access_token: upstreamAccessTokenOverride ?? await upstreamAccessToken(),
          refresh_token: omitRotatedRefreshToken ? undefined : 'upstream-refresh-token',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'firewalls:read metrics:read offline_access',
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
      activityKey: req.headers.get('x-silmaril-mcp-activity-key'),
    });

    if (url.pathname === '/api/mcp/v1/activity/events') {
      activityCalls.push(upstreamCalls.pop()!);
      if (activitySinkFails) throw new Error('activity sink unavailable');
      return new Response(null, { status: 204 });
    }

    if (url.pathname === '/api/mcp/v1/admin/access') {
      if (!adminAccessAllowed) {
        return json({
          error: { code: 'silmaril_admin_required', message: 'Global Silmaril admin access is required.' },
        }, { status: 403 });
      }
      return new Response(null, { status: 204 });
    }

    if (url.pathname === '/api/mcp/v1/admin/activity/summary') {
      return json({
        range: url.searchParams.get('range'),
        calls: 12,
        successes: 11,
        errors: 1,
        active_tenants: 2,
        active_users: 3,
        daily_activity: [],
        per_tenant: [],
        tool_mix: [],
        category_mix: [],
      });
    }

    if (url.pathname === '/api/mcp/v1/admin/activity/recent') {
      return json({
        range: url.searchParams.get('range'),
        items: [{
          occurred_at: '2026-07-13T00:00:00.000Z',
          tenant: 'acme',
          actor_subject: 'auth0|user',
          actor_email: 'user@acme.com',
          tool_name: 'list_findings',
          category: 'findings_search',
          outcome: 'success',
        }],
      });
    }

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
      if (!publicAccessAllowed) {
        return json({
          error: { code: 'token_revoked', message: 'Access token is no longer active.' },
        }, { status: 401 });
      }
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
          score_fields: {
            suspicious_score_percent: '0-100 user priority score.',
            top_finding_score_percent: '0-100 highest underlying firewall finding score.',
            bot_farming: {
              score_percent: '0-100 observed bot-farming correlation score.',
              max_possible_score_percent: '0-100 score ceiling with unavailable planned signals.',
              signals: {
                score_percent: '0-100 per-signal score, or null when unavailable.',
              },
            },
          },
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
          suspicious_score_percent: 84,
          findings: { suspicious: 2 },
          conversations: {
            suspicious: 2,
            observed_total_with_findings: 2,
            observed_malicious_percent: 100,
            all_ai_conversation_percent: null,
          },
          top_finding_score_percent: 91,
          bot_farming: {
            score_percent: 42,
            max_possible_score_percent: 72,
            signals: {
              new_user_burst: {
                available: true,
                score_percent: 20,
                level: 'strong',
                metrics: { first_seen_users: 3 },
                evidence: ['3 first-seen users share workspace/category/signature'],
                version: 'v1',
              },
              workspace_churn: {
                available: true,
                score_percent: 10,
                level: 'moderate',
                metrics: { distinct_suspicious_users_in_workspace_category: 3 },
                evidence: ['3 suspicious users share workspace/category'],
                version: 'v1',
              },
              limit_burn_proxy: {
                available: true,
                score_percent: 12,
                level: 'moderate',
                metrics: { suspicious_conversations: 2 },
                evidence: ['multiple suspicious conversations'],
                version: 'v1',
              },
              prompt_campaign_reuse: {
                available: true,
                score_percent: 0,
                level: 'none',
                metrics: {},
                evidence: [],
                version: 'v1',
              },
              runtime_identity_reuse: {
                available: false,
                score_percent: null,
                level: 'unavailable',
                metrics: { reason: 'runtime_identity_unavailable' },
                evidence: [],
                version: 'v1',
              },
              shared_ja4_fingerprint: {
                available: false,
                score_percent: null,
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
            finding_score_percent: 91,
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
        authorization: `Bearer ${mcpAccessToken()}`,
        origin: 'https://codex.test',
      },
    },
    fetch: globalThis.fetch,
  });
  await client.connect(transport);
  return { client, transport };
}

async function connectedAdminClient() {
  mcpMode = 'admin';
  installMockFetch();
  const client = new Client({ name: 'mcp-admin-test-client', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL('https://mcp.test/admin/mcp'), {
    requestInit: {
      headers: {
        authorization: `Bearer ${mcpAccessToken('admin')}`,
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
  const detailTool = tools.tools.find((tool) => tool.name === 'get_finding');
  assert.equal(detailTool?.annotations?.readOnlyHint, false);
  assert.equal(detailTool?._meta?.['silmaril/sensitivity'], 'restricted');

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
      score_fields: {
        suspicious_score_percent: string;
        top_finding_score_percent: string;
        bot_farming: {
          score_percent: string;
          max_possible_score_percent: string;
          signals: { score_percent: string };
        };
      };
      defaults: { candidate_limit: number; lookback_candidate_limit: number };
    };
  };
  assert.equal(body.suspicious_users.endpoint, '/api/mcp/v1/firewalls/:envKey/findings/users/suspicious');
  assert.deepEqual(body.suspicious_users.scopes, ['findings:read']);
  assert.ok(body.suspicious_users.abuse_categories.includes('nsfw_content_abuse'));
  assert.ok(body.suspicious_users.abuse_categories.includes('model_distillation'));
  assert.ok(body.suspicious_users.correlation_signals.includes('shared_ja4_fingerprint'));
  assert.match(body.suspicious_users.score_fields.suspicious_score_percent, /0-100/);
  assert.match(body.suspicious_users.score_fields.top_finding_score_percent, /0-100/);
  assert.match(body.suspicious_users.score_fields.bot_farming.score_percent, /bot-farming/);
  assert.match(body.suspicious_users.score_fields.bot_farming.max_possible_score_percent, /ceiling/);
  assert.match(body.suspicious_users.score_fields.bot_farming.signals.score_percent, /per-signal/);
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

test('rejects malformed or direct upstream bearer tokens before MCP processing', async () => {
  installMockFetch();
  for (const token of ['not-a-token', await upstreamAccessToken()]) {
    const response = await handleMcpRequest(new Request('https://mcp.test/mcp', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    }));
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error.code, 'token_invalid');
    assert.match(response.headers.get('www-authenticate') ?? '', /error="invalid_token"/);
  }
  assert.equal(upstreamCalls.length, 0);
});

test('rejects valid tokens for a different MCP resource', async () => {
  installMockFetch();
  const response = await handleMcpRequest(new Request('https://mcp.test/admin/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${mcpAccessToken('public')}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }), { mode: 'admin' });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, 'token_invalid');
  assert.equal(upstreamCalls.length, 0);
});

test('rejects a revoked downstream credential at the HTTP boundary before MCP handling', async () => {
  installMockFetch();
  publicAccessAllowed = false;
  const response = await handleMcpRequest(new Request('https://mcp.test/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${mcpAccessToken()}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }));
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, 'token_revoked');
  assert.match(response.headers.get('www-authenticate') ?? '', /error="invalid_token"/);
  assert.deepEqual(
    upstreamCalls.map((call) => new URL(call.url).pathname),
    ['/api/mcp/v1/schema'],
  );
});

test('returns HTTP 403 with deterministic scope step-up before tool execution', async () => {
  installMockFetch();
  const response = await handleMcpRequest(new Request('https://mcp.test/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${mcpAccessToken('public', ['findings:read'])}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'get_finding', arguments: {} },
    }),
  }));
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error.code, 'insufficient_scope');
  assert.match(response.headers.get('www-authenticate') ?? '', /scope="findings:detail payload:read"/);
  assert.equal(upstreamCalls.length, 0);
});

test('rejects JSON-RPC batches and oversized bodies before MCP processing', async () => {
  installMockFetch();
  const token = mcpAccessToken();
  const batch = await handleMcpRequest(new Request('https://mcp.test/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify([
      { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    ]),
  }));
  assert.equal(batch.status, 400);
  assert.equal((await batch.json()).error.code, 'batch_not_supported');

  process.env.MCP_MAX_REQUEST_BYTES = '64';
  const oversized = await handleMcpRequest(new Request('https://mcp.test/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/list',
      padding: 'x'.repeat(128),
    }),
  }));
  assert.equal(oversized.status, 413);
  assert.equal((await oversized.json()).error.code, 'request_too_large');

  resetRateLimitsForTests();
  const chunkedBody = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('x'.repeat(40)));
      controller.enqueue(new TextEncoder().encode('y'.repeat(40)));
      controller.close();
    },
  });
  const chunkedInit: RequestInit & { duplex: 'half' } = {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: chunkedBody,
    duplex: 'half',
  };
  const chunked = await handleMcpRequest(
    new Request('https://mcp.test/mcp', chunkedInit),
  );
  assert.equal(chunked.status, 413);
  assert.equal((await chunked.json()).error.code, 'request_too_large');
});

test('enforces an actor and client quota with deterministic HTTP 429', async () => {
  installMockFetch();
  process.env.MCP_RATE_LIMIT_BURST = '1';
  process.env.MCP_RATE_LIMIT_REQUESTS_PER_SECOND = '1';
  const token = mcpAccessToken();
  const makeRequest = () => handleMcpRequest(new Request('https://mcp.test/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }));

  assert.equal((await makeRequest()).status, 200);
  const limited = await makeRequest();
  assert.equal(limited.status, 429);
  assert.equal((await limited.json()).error.code, 'rate_limit_exceeded');
  assert.equal(limited.headers.get('retry-after'), '1');
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
  assert.equal(body.silmaril_oauth_client_id, undefined);
  assert.equal(body.silmaril_upstream_authorization_servers, undefined);
  assert.equal(body.silmaril_oauth_resource, undefined);
  assert.ok(body.scopes_supported.includes('firewalls:read'));
  assert.ok(body.scopes_supported.includes('trace:read'));
});

test('serves separate admin MCP protected resource metadata', async () => {
  installMockFetch();

  const response = await handleProtectedResourceMetadataRequest(
    new Request('https://mcp.test/.well-known/oauth-protected-resource/admin-mcp'),
    readConfig(),
    'admin',
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.resource, 'https://mcp.test/admin/mcp');
  assert.equal(body.resource_name, 'Silmaril Firewall Admin MCP');
  assert.deepEqual(body.scopes_supported, ['firewalls:read']);
});

test('rejects incomplete enabled activity configuration', () => {
  process.env.MCP_ACTIVITY_ENABLED = 'true';
  delete process.env.MCP_ACTIVITY_INGEST_KEY;
  assert.throws(() => readConfig(), /MCP_ACTIVITY_INGEST_KEY/);

  process.env.MCP_ACTIVITY_INGEST_KEY = 'too-short';
  assert.throws(() => readConfig(), /at least 32 characters/);

  process.env.MCP_ACTIVITY_INGEST_KEY = 'test-activity-key-with-at-least-32-characters';
  assert.equal(readConfig().activityEnabled, true);
});

test('admin MCP denies non-admin callers before constructing the tool server', async () => {
  installMockFetch();
  adminAccessAllowed = false;

  const response = await handleMcpRequest(new Request('https://mcp.test/admin/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${mcpAccessToken('admin')}`,
      origin: 'https://codex.test',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }), { mode: 'admin' });

  assert.equal(response.status, 403);
  assert.equal((await response.json()).error.code, 'silmaril_admin_required');
  assert.deepEqual(
    upstreamCalls.map((call) => new URL(call.url).pathname),
    ['/api/mcp/v1/admin/access'],
  );
});

test('admin MCP exposes only bounded adoption tools', async () => {
  const { client } = await connectedAdminClient();
  const tools = await client.listTools();
  assert.deepEqual(
    tools.tools.map((tool) => tool.name).sort(),
    ['get_mcp_adoption_summary', 'list_mcp_activity'],
  );

  const summary = await client.callTool({
    name: 'get_mcp_adoption_summary',
    arguments: { range: '7d', tenant: 'acme' },
  });
  assert.equal(summary.isError, undefined);
  assert.equal((summary.structuredContent as { calls: number }).calls, 12);

  const recent = await client.callTool({
    name: 'list_mcp_activity',
    arguments: { range: '1d', actor_email: 'user@acme.com', limit: 10 },
  });
  assert.equal(recent.isError, undefined);
  assert.equal(
    (recent.structuredContent as { items: Array<{ tool_name: string }> }).items[0].tool_name,
    'list_findings',
  );
  assert.equal(activityCalls.length, 0);
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
  assert.equal(body.scopes_supported.includes('offline_access'), false);
});

test('rejects OAuth metadata endpoints that leave the configured issuer origin', async () => {
  installMockFetch();
  authMetadataOverride = {
    token_endpoint: 'https://attacker.example/oauth/token',
  };
  const response = await handleAuthorizationServerMetadataRequest(
    new Request('https://mcp.test/.well-known/oauth-authorization-server'),
    readConfig(),
  );
  assert.equal(response.status, 503);
  assert.match((await response.json()).error.message, /configured issuer origin/);
});

test('authorization redirects directly to Auth0 consent through the fixed callback bridge', async () => {
  installMockFetch();
  const clientId = await registerClient();
  const flow = await completeAuthorization(clientId);
  const callbackLocation = new URL(flow.callback.headers.get('location') ?? '');

  assert.equal(flow.authorization.status, 302);
  assert.equal(flow.authorization.headers.get('content-type'), null);
  assert.equal(await flow.authorization.clone().text(), '');
  assert.equal(flow.upstreamAuthorization.origin, 'https://tenant.example.auth0.com');
  assert.equal(flow.upstreamAuthorization.pathname, '/authorize');
  assert.equal(flow.upstreamAuthorization.searchParams.get('client_id'), 'public-mcp-client-id');
  assert.equal(flow.upstreamAuthorization.searchParams.get('redirect_uri'), 'https://mcp.test/oauth/callback');
  assert.equal(flow.upstreamAuthorization.searchParams.get('audience'), 'https://silmaril.security/firewall-ui/mcp-test');
  assert.equal(
    flow.upstreamAuthorization.searchParams.get('scope'),
    'firewalls:read metrics:read offline_access',
  );
  assert.equal(flow.upstreamAuthorization.searchParams.get('prompt'), 'consent');
  assert.equal(flow.upstreamAuthorization.searchParams.get('ext-mcp-client-name'), 'QA MCP Client');
  assert.equal(
    flow.upstreamAuthorization.searchParams.get('ext-mcp-client-callback'),
    'http://127.0.0.1:1455/oauth/callback',
  );
  assert.equal(flow.callback.status, 302);
  assert.equal(callbackLocation.origin, 'http://127.0.0.1:1455');
  assert.ok(flow.bridgeCode.startsWith('code2.'));
  assert.equal(callbackLocation.searchParams.get('state'), 'codex-state');
});

test('authorization omits upstream offline access for authorization-code-only clients', async () => {
  installMockFetch();
  const registration = await handleClientRegistrationRequest(
    new Request('https://mcp.test/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['http://127.0.0.1:1455/oauth/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        scope: 'firewalls:read metrics:read',
      }),
    }),
    readConfig(),
  );
  const clientId = (await registration.json()).client_id;
  const flow = await completeAuthorization(clientId);

  assert.equal(registration.status, 201);
  assert.equal(
    flow.upstreamAuthorization.searchParams.get('scope'),
    'firewalls:read metrics:read',
  );
});

test('authorization endpoint does not expose a local consent POST', async () => {
  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize', { method: 'POST' }),
    readConfig(),
  );

  assert.equal(response.status, 405);
  assert.equal(response.headers.get('allow'), 'GET');
});

test('authorization sanitizes dynamic client identity for Auth0 consent display', async () => {
  installMockFetch();
  const response = await handleClientRegistrationRequest(
    new Request('https://mcp.test/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['http://127.0.0.1:1455/oauth/callback?channel=desktop'],
        client_name: '<script>alert("client")</script>',
      }),
    }),
    readConfig(),
  );
  const clientId = (await response.json()).client_id;
  const flow = await completeAuthorization(clientId, {
    redirectUri: 'http://127.0.0.1:1455/oauth/callback?channel=desktop',
  });

  assert.equal(
    flow.upstreamAuthorization.searchParams.get('ext-mcp-client-name'),
    '_script_alert__client___/script_',
  );
  assert.equal(
    flow.upstreamAuthorization.searchParams.get('ext-mcp-client-callback'),
    'http://127.0.0.1:1455/oauth/callback_channel_desktop',
  );
});

test('authorization rejects prompt=none instead of reusing shared upstream consent', async () => {
  installMockFetch();
  const clientId = await registerClient();
  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      code_challenge: TEST_CODE_CHALLENGE,
      code_challenge_method: 'S256',
      prompt: 'none',
    })),
    readConfig(),
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'interaction_required');
});

test('authorization bridge applies explicit Auth0 organization to Auth0 consent', async () => {
  installMockFetch();
  process.env.MCP_AUTH0_ORGANIZATION = 'org_silmaril';
  const clientId = await registerClient();
  const flow = await completeAuthorization(clientId);
  assert.equal(flow.upstreamAuthorization.searchParams.get('organization'), 'org_silmaril');

  const explicit = await completeAuthorization(clientId, { organization: 'org_clickup' });
  assert.equal(explicit.upstreamAuthorization.searchParams.get('organization'), 'org_clickup');
});

test('authorization bridge rejects forged callback state', async () => {
  installMockFetch();
  const forgedPayload = Buffer.from(JSON.stringify({
    v: 1,
    redirect_uri: 'http://127.0.0.1:9999/oauth/callback',
    client_id: 'public-mcp-client-id',
    code_challenge: TEST_CODE_CHALLENGE,
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

test('authorization bridge rejects non-Auth0 organization values locally', async () => {
  installMockFetch();
  const clientId = await registerClient();

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      state: 'codex-state',
      organization: 'clickup',
      code_challenge: TEST_CODE_CHALLENGE,
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
  const clientId = await registerClient();

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      state: 'codex-state',
      code_challenge: TEST_CODE_CHALLENGE,
      code_challenge_method: 'S256',
    }).toString()),
    readConfig(),
  );
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.equal(body.error, 'server_error');
  assert.match(body.error_description, /MCP_AUTH0_ORGANIZATION must be an Auth0 organization id/);
});

test('authorization bridge rejects callbacks not exactly bound to the dynamic registration', async () => {
  installMockFetch();
  const clientId = await registerClient([
    'http://127.0.0.1:1455/oauth/callback',
    'http://localhost:1455/oauth/callback',
  ]);

  const response = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'http://127.0.0.1:1456/oauth/callback',
      code_challenge: TEST_CODE_CHALLENGE,
      code_challenge_method: 'S256',
    }).toString()),
    readConfig(),
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'invalid_request');
});

test('authorization bridge requires S256 PKCE', async () => {
  installMockFetch();
  const clientId = await registerClient();

  const missingChallenge = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
    }).toString()),
    readConfig(),
  );
  const plainChallenge = await handleAuthorizationRequest(
    new Request('https://mcp.test/oauth/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      code_challenge: TEST_CODE_CHALLENGE,
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
  const clientId = await registerClient();
  const flow = await completeAuthorization(clientId);

  const response = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code: flow.bridgeCode,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier,
        resource: 'https://mcp.test/mcp',
      }).toString(),
    }),
    readConfig(),
  );
  const body = await response.json();
  const upstreamBody = new URLSearchParams(tokenCalls[0].body ?? '');

  assert.equal(response.status, 200);
  assert.match(body.access_token, /^mcp_at_v1\./);
  assert.match(body.refresh_token, /^mcp_rt_v1\./);
  assert.equal(body.scope, 'firewalls:read metrics:read');
  assert.equal(tokenCalls.length, 1);
  assert.equal(tokenCalls[0].authorization, null);
  assert.equal(upstreamBody.get('grant_type'), 'authorization_code');
  assert.equal(upstreamBody.get('client_id'), 'public-mcp-client-id');
  assert.equal(upstreamBody.get('code'), 'auth0-code');
  assert.equal(upstreamBody.get('redirect_uri'), 'https://mcp.test/oauth/callback');
  assert.equal(upstreamBody.get('code_verifier'), flow.verifier);

  const mcpResponse = await handleMcpRequest(new Request('https://mcp.test/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${body.access_token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }));
  assert.equal(mcpResponse.status, 200);
});

test('token bridge refuses wrong-issuer, wrong-audience, expired, and forged upstream JWTs', async () => {
  installMockFetch();
  const valid = await upstreamAccessToken();
  const [header, payload, signature] = valid.split('.');
  const forged = `${header}.${payload}.${signature?.startsWith('a') ? `b${signature.slice(1)}` : `a${signature?.slice(1)}`}`;
  const invalidTokens = [
    await upstreamAccessToken({ iss: 'https://attacker.example/' }),
    await upstreamAccessToken({ aud: 'https://attacker.example/api' }),
    await upstreamAccessToken({ exp: Math.floor(Date.now() / 1000) - 60 }),
    forged,
  ];

  for (const invalidToken of invalidTokens) {
    const clientId = await registerClient();
    const flow = await completeAuthorization(clientId);
    upstreamAccessTokenOverride = invalidToken;
    const response = await handleTokenRequest(
      new Request('https://mcp.test/oauth/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          code: flow.bridgeCode,
          redirect_uri: flow.redirectUri,
          code_verifier: flow.verifier,
        }),
      }),
      readConfig(),
    );
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, 'server_error');
  }
});

test('token bridge rejects authorization code exchange for a different loopback callback', async () => {
  installMockFetch();
  const clientId = await registerClient();
  const flow = await completeAuthorization(clientId);

  const response = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code: flow.bridgeCode,
        redirect_uri: 'http://127.0.0.1:1456/oauth/callback',
        code_verifier: flow.verifier,
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
  const clientId = await registerClient();

  const response = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code: 'auth0-code',
        redirect_uri: 'http://127.0.0.1:1455/oauth/callback',
      }).toString(),
    }),
    readConfig(),
  );

  assert.equal(response.status, 400);
  assert.match((await response.json()).error_description, /requires code, code_verifier, and redirect_uri/);
  assert.equal(tokenCalls.length, 0);
});

test('token bridge unwraps refresh credentials and rejects cross-client replay or scope expansion', async () => {
  installMockFetch();
  const clientId = await registerClient();
  const flow = await completeAuthorization(clientId);
  const initial = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code: flow.bridgeCode,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier,
      }),
    }),
    readConfig(),
  );
  const initialBody = await initial.json();
  tokenCalls = [];

  const response = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: initialBody.refresh_token,
      }).toString(),
    }),
    readConfig(),
  );
  const body = await response.json();
  const upstreamBody = new URLSearchParams(tokenCalls[0].body ?? '');

  assert.equal(response.status, 200);
  assert.match(body.access_token, /^mcp_at_v1\./);
  assert.equal(tokenCalls.length, 1);
  assert.equal(upstreamBody.get('grant_type'), 'refresh_token');
  assert.equal(upstreamBody.get('client_id'), 'public-mcp-client-id');
  assert.equal(upstreamBody.get('refresh_token'), 'upstream-refresh-token');

  const otherClientId = await registerClient(['http://127.0.0.1:1666/oauth/callback']);
  const mismatch = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: otherClientId,
        refresh_token: initialBody.refresh_token,
      }).toString(),
    }),
    readConfig(),
  );

  assert.equal(mismatch.status, 400);
  assert.equal((await mismatch.json()).error, 'invalid_grant');
  assert.equal(tokenCalls.length, 1);

  const expansion = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: initialBody.refresh_token,
        scope: 'firewalls:read trace:read',
      }),
    }),
    readConfig(),
  );
  assert.equal(expansion.status, 400);
  assert.equal((await expansion.json()).error, 'invalid_scope');

  omitRotatedRefreshToken = true;
  const missingRotation = await handleTokenRequest(
    new Request('https://mcp.test/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: initialBody.refresh_token,
      }),
    }),
    readConfig(),
  );
  assert.equal(missingRotation.status, 503);
  assert.match((await missingRotation.json()).error_description, /rotation is required/);
});

test('dynamic client registration returns unique signed client handles without exposing Auth0 client ID', async () => {
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
  assert.match(body.client_id, /^dcr2\./);
  assert.equal(body.client_id.includes('public-mcp-client-id'), false);
  assert.deepEqual(body.redirect_uris, ['http://127.0.0.1:1455/oauth/callback']);
  assert.deepEqual(body.grant_types, ['authorization_code']);
  assert.deepEqual(body.response_types, ['code']);
  assert.equal(body.token_endpoint_auth_method, 'none');
  assert.equal(body.scope, 'firewalls:read metrics:read');
  assert.equal(body.client_name, 'Codex');
  const secondClient = await registerClient();
  assert.notEqual(secondClient, body.client_id);
});

test('dynamic registration defaults to aggregate scopes so detail requires explicit consent', async () => {
  installMockFetch();
  const response = await handleClientRegistrationRequest(
    new Request('https://mcp.test/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['http://127.0.0.1:1455/oauth/callback'],
      }),
    }),
    readConfig(),
  );
  const body = await response.json();
  assert.equal(response.status, 201);
  assert.equal(body.scope, 'firewalls:read metrics:read findings:read');
  assert.equal(body.scope.includes('payload:read'), false);
  assert.equal(body.scope.includes('trace:read'), false);
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
  assert.equal(body.error_description, 'redirect_uris must be exact HTTP loopback callback URLs without fragments.');
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

test('caches firewall-ui public OAuth config briefly and revalidates after expiry/reset', async () => {
  installMockFetch();
  const config = readConfig();

  const first = await getFirewallMcpPublicConfig(config);
  publicConfigOverride = { enabled: false };

  assert.equal(first.audience, 'https://silmaril.security/firewall-ui/mcp-test');
  assert.equal((await getFirewallMcpPublicConfig(config)).enabled, true);
  resetFirewallMcpPublicConfigCacheForTests();
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
      suspicious_score_percent: number;
      top_finding_score_percent: number;
      account_farming?: unknown;
      suspicious_score?: unknown;
      top_score?: unknown;
      bot_farming: {
        score_percent: number;
        max_possible_score_percent: number;
        signals: Record<string, { available: boolean; score?: number | null; score_percent: number | null; level: string }>;
      };
      evidence_handles: Array<{ evidence_id: string; score?: number; finding_score_percent: number }>;
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
  assert.equal(body.users[0].suspicious_score_percent, 84);
  assert.equal(body.users[0].top_finding_score_percent, 91);
  assert.equal(body.users[0].suspicious_score, undefined);
  assert.equal(body.users[0].top_score, undefined);
  assert.equal(body.users[0].account_farming, undefined);
  assert.equal(body.users[0].findings.suspicious, 2);
  assert.equal(body.users[0].findings.true_positive, undefined);
  assert.equal(body.users[0].bot_farming.signals.shared_ja4_fingerprint.available, false);
  assert.equal(body.users[0].bot_farming.signals.shared_ja4_fingerprint.score, undefined);
  assert.equal(body.users[0].bot_farming.signals.shared_ja4_fingerprint.score_percent, null);
  assert.equal(body.users[0].bot_farming.signals.shared_ja4_fingerprint.level, 'unavailable');
  assert.ok(body.users[0].bot_farming.score_percent < body.users[0].bot_farming.max_possible_score_percent);
  assert.equal(body.diagnostics.missing_identity_counts.ja4, 2);
  assert.equal(body.users[0].evidence_handles[0].evidence_id, 'yc-prod-us-west-2:qa-risk-find-001');
  assert.equal(body.users[0].evidence_handles[0].score, undefined);
  assert.equal(body.users[0].evidence_handles[0].finding_score_percent, 91);
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

test('activity emits once per logical tool call with a minimal fail-open payload', async () => {
  process.env.MCP_ACTIVITY_ENABLED = 'true';
  process.env.MCP_ACTIVITY_INGEST_KEY = 'test-activity-key-with-at-least-32-characters';
  const { client } = await connectedClient();

  assert.equal(activityCalls.length, 0, 'initialization and tool discovery are excluded');
  const success = await client.callTool({
    name: 'group_findings',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      by: 'triage',
      range: '1d',
      metadata: [{ key: 'stage', value: 'CANARY_SECRET' }],
    },
  });
  assert.equal(success.isError, undefined);
  await Promise.all(deferredTasks);

  assert.equal(activityCalls.length, 1, 'three upstream totals reads emit one logical event');
  assert.equal(activityCalls[0].authorization, 'Bearer user-access-token');
  assert.equal(activityCalls[0].activityKey, process.env.MCP_ACTIVITY_INGEST_KEY);
  assert.deepEqual(JSON.parse(activityCalls[0].body ?? '{}'), {
    version: 1,
    tool_name: 'group_findings',
    outcome: 'success',
  });
  assert.doesNotMatch(activityCalls[0].body ?? '', /CANARY_SECRET|yc-prod|metadata|arguments/);

  deferredTasks = [];
  const failure = await client.callTool({
    name: 'get_firewall',
    arguments: { firewall_id: 'forbidden-prod-us-west-2' },
  });
  assert.equal(failure.isError, true);
  await Promise.all(deferredTasks);
  assert.deepEqual(JSON.parse(activityCalls[1].body ?? '{}'), {
    version: 1,
    tool_name: 'get_firewall',
    outcome: 'error',
  });

  deferredTasks = [];
  activitySinkFails = true;
  const failOpen = await client.callTool({ name: 'list_firewalls', arguments: {} });
  assert.equal(failOpen.isError, undefined);
  await Promise.all(deferredTasks);
});

test('activity excludes input validation failures', async () => {
  process.env.MCP_ACTIVITY_ENABLED = 'true';
  process.env.MCP_ACTIVITY_INGEST_KEY = 'test-activity-key-with-at-least-32-characters';
  const { client } = await connectedClient();

  const result = await client.callTool({
    name: 'list_suspicious_users',
    arguments: { firewall_id: 'yc-prod-us-west-2', categories: [] },
  });
  assert.equal(result.isError, true);
  await Promise.all(deferredTasks);
  assert.equal(activityCalls.length, 0);
});

test('group_findings uses total fields when triage totals omit blocked', async () => {
  for (const envelope of ['nested-total', 'top-level-total'] as const) {
    resetRateLimitsForTests();
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
    const audit = JSON.parse(auditCalls[0].body ?? '{}');
    assert.match(audit.event_id, /^[0-9a-f-]{36}$/);
    assert.equal(audit.actor_subject, 'auth0|user');
    assert.equal(audit.tenant, 'acme');
    assert.equal(audit.organization, 'org_acme');
    assert.equal(audit.oauth_client_id, 'dcr-test-client');
    assert.equal(audit.target_firewall_id, 'yc-prod-us-west-2');
    assert.equal(audit.target_finding_id, 'qa-find-001');
    assert.equal(audit.outcome, 'success');
    assert.equal(audit.deployment_version, '321c91e-test');
    assert.equal(logLines.join('\n').includes('CANARY_SECRET'), false);
  } finally {
    console.log = originalConsole.log;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
  }
});

test('failed detail reads produce an attributed error audit event', async () => {
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
  assert.equal(auditCalls.length, 1);
  const audit = JSON.parse(auditCalls[0].body ?? '{}');
  assert.equal(audit.outcome, 'error');
  assert.equal(audit.actor_subject, 'auth0|user');
  assert.equal(audit.tenant, 'acme');
  assert.equal(audit.organization, 'org_acme');
  assert.equal(audit.oauth_client_id, 'dcr-test-client');
  assert.equal(audit.target_finding_id, 'missing-finding');
  assert.equal(audit.deployment_version, '321c91e-test');
});

test('sensitive evidence is withheld when durable audit is absent or rejects the event', async () => {
  const absent = await connectedClient();
  const absentResult = await absent.client.callTool({
    name: 'get_finding',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      finding_id: 'qa-find-001',
      reason: 'Verify audit fail closed behavior.',
    },
  });
  assert.equal(absentResult.isError, true);
  assert.equal(
    (absentResult.structuredContent as { error: { code: string } }).error.code,
    'sensitive_audit_unavailable',
  );
  assert.equal(
    upstreamCalls.some((call) =>
      new URL(call.url).pathname.endsWith('/findings/qa-find-001')),
    false,
  );

  process.env.MCP_AUDIT_URL = 'https://audit.test/events';
  auditSinkFails = true;
  const rejected = await connectedClient();
  const rejectedResult = await rejected.client.callTool({
    name: 'get_finding',
    arguments: {
      firewall_id: 'yc-prod-us-west-2',
      finding_id: 'qa-find-001',
      reason: 'Verify rejected audit behavior.',
    },
  });
  assert.equal(rejectedResult.isError, true);
  assert.equal(
    (rejectedResult.structuredContent as { error: { code: string } }).error.code,
    'sensitive_audit_unavailable',
  );
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
        ...readConfig(),
        maxResponseBytes: 16,
      },
    }),
    (err) =>
      err instanceof FirewallApiError &&
      err.status === 413 &&
      err.code === 'upstream_response_too_large',
  );
});
