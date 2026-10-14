import assert from 'node:assert/strict';
import test from 'node:test';
import { auditDetailAccess } from '../src/audit';
import { readConfig } from '../src/config';
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
