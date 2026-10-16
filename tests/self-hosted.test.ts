import assert from 'node:assert/strict';
import test from 'node:test';
import { auditDetailAccess } from '../src/audit';
import { readConfig } from '../src/config';
import { GET as ready } from '../app/readyz/route';
import { resetFirewallMcpPublicConfigCacheForTests } from '../src/firewall-ui-config';
import { GET as live } from '../app/healthz/route';

const event = {
  tool: 'get_conversation' as const, firewallId: 'customer-installation',
  target: { type: 'conversation' as const, id: 'opaque-handle' }, reason: 'Investigate incident',
  requestId: 'request-1', outcome: 'success' as const,
  actor: { subject: 'user', actorEmail: null, tenant: 'customer', organization: 'org_customer', isAdmin: false, clientId: 'client', tokenId: null },
};

test('audit user credentials only reach the configured evidence authority', async (t) => {
  process.env.FIREWALL_UI_BASE_URL = 'https://dashboard.example.test';
  const config = readConfig();
  const seen: string[] = [];
  t.mock.method(globalThis, 'fetch', async (_url: unknown, init?: RequestInit) => {
    seen.push(new Headers(init?.headers).get('authorization') ?? '');
    assert.equal(String(init?.body).includes('user-access-token'), false);
    return Response.json({ status: 'persisted' }, { status: 201 });
  });
  await auditDetailAccess(event, { ...config, auditUrl: 'https://dashboard.example.test/api/mcp/v1/audit' }, undefined, 'user-access-token');
  await auditDetailAccess(event, { ...config, auditUrl: 'https://external-audit.example.test/events' }, undefined, 'user-access-token');
  assert.deepEqual(seen, ['Bearer user-access-token', '']);
});

test('liveness does not depend on external identity or evidence services', async () => {
  assert.equal((await live()).status, 200);
});


test('readiness rejects absent OAuth clients and accepts the OAuth byte-length contract', async (t) => {
  const original = { ...process.env };
  t.after(() => { process.env = original; resetFirewallMcpPublicConfigCacheForTests(); });
  process.env.FIREWALL_UI_BASE_URL = 'https://dashboard.example.test';
  process.env.MCP_PUBLIC_BASE_URL = 'https://dashboard.example.test';
  process.env.MCP_AUDIT_URL = 'https://dashboard.example.test/api/mcp/v1/audit';
  process.env.MCP_OAUTH_STATE_SECRET = 'é'.repeat(16);
  let client: string | null = null;
  t.mock.method(globalThis, 'fetch', async () => Response.json({ version: 'v1', enabled: true,
    issuer: 'https://auth.example.test/', authorization_servers: ['https://auth.example.test/'],
    audience: 'https://dashboard.example.test/mcp', scopes: ['firewalls:read'],
    oauth: { client_id: client, client_id_source: 'installation' } }));
  resetFirewallMcpPublicConfigCacheForTests();
  assert.equal((await ready()).status, 503);
  client = 'public-installation-client';
  resetFirewallMcpPublicConfigCacheForTests();
  assert.equal((await ready()).status, 200);
  process.env.MCP_OAUTH_STATE_SECRET = 'short';
  assert.equal((await ready()).status, 503);
});
