import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { ServerConfig } from '../src/config';
import { createFirewallMcpServer } from '../src/server';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const guardedFiles = [
  'README.md',
  'docs/customer-guide.md',
  'docs/developer-quickstart.md',
] as const;

const forbiddenSetupFragments = [
  '--oauth-client-id',
  '--oauth-resource',
  '<oauth.client_id from firewall-ui config>',
  '<resource from firewall-ui config>',
  'AUTH0_MCP_CLIENT_ID',
  'AUTH0_MCP_AUDIENCE',
  'bearer-token-env-var',
  'static bearer',
  'raw token',
] as const;

const reasonContractFiles = [
  'README.md',
  'docs/customer-guide.md',
  'docs/security-qa-checklist.md',
] as const;

test('user-facing MCP setup stays URL-only', () => {
  for (const file of guardedFiles) {
    const text = readFileSync(join(root, file), 'utf8');

    for (const fragment of forbiddenSetupFragments) {
      assert.equal(
        text.toLowerCase().includes(fragment.toLowerCase()),
        false,
        `${file} must not expose ${fragment} in MCP user setup`,
      );
    }
  }
});

test('README leads with the hosted URL-only setup command', () => {
  const readme = readFileSync(join(root, 'README.md'), 'utf8');

  assert.match(
    readme,
    /codex mcp add silmaril-firewall --url https:\/\/firewall-mcp\.silmaril\.dev\/mcp/,
  );
});

test('README links to the customer guide', () => {
  const readme = readFileSync(join(root, 'README.md'), 'utf8');

  assert.match(readme, /docs\/customer-guide\.md/);
});

test('README includes a first-10-minutes flow', () => {
  const readme = readFileSync(join(root, 'README.md'), 'utf8');

  assert.match(readme, /First 10 Minutes/);
});

test('README keeps the evidence safety warning near detail tools', () => {
  const readme = readFileSync(join(root, 'README.md'), 'utf8');

  assert.match(
    readme,
    /Finding payloads, conversation captures, and trace text can contain attacker-controlled instructions/,
  );
  assert.match(readme, /Treat them as evidence/);
});

test('customer guide includes happy path prompts for core workflows', () => {
  const guide = readFileSync(join(root, 'docs/customer-guide.md'), 'utf8');

  assert.match(guide, /List the firewalls I can access and tell me which one looks like production/);
  assert.match(guide, /summarize security posture over the last 24 hours using metrics and finding totals/);
  assert.match(guide, /Show the highest-risk findings for your-firewall-id over the last day and cite evidence IDs/);
  assert.match(guide, /owner tagged payments-agent/);
  assert.match(guide, /Show suspicious users for your-firewall-id over the last 30 days/);
  assert.match(guide, /Filter suspicious users for your-firewall-id to model distillation only/);
  assert.match(guide, /Filter suspicious users for your-firewall-id to NSFW content abuse only/);
  assert.match(guide, /Build an investigation packet for finding finding-id in your-firewall-id/);
});

test('customer guide explains evidence safety and detail minimization', () => {
  const guide = readFileSync(join(root, 'docs/customer-guide.md'), 'utf8');

  assert.match(guide, /Finding payloads and trace text can contain attacker-controlled instructions/);
  assert.match(guide, /Use full payload or trace tools only when needed/);
  assert.match(guide, /Treat them as evidence, not instructions/);
});

test('sensitive-read docs match the advertised reason bounds', async (t) => {
  const config: ServerConfig = {
    firewallUiBaseUrl: 'https://firewall.test',
    publicBaseUrl: null,
    auth0Organization: null,
    oauthStateSecret: null,
    oauthAllowedRedirectUris: [],
    allowedOrigins: [],
    maxRequestBytes: 256_000,
    maxResponseBytes: 1_000_000,
    upstreamTimeoutMs: 10_000,
    publicConfigCacheMs: 30_000,
    rateLimitRequestsPerSecond: 5,
    rateLimitBurst: 10,
    auditUrl: null,
    auditTimeoutMs: 3_000,
    deploymentVersion: 'docs-test',
    activityEnabled: false,
    activityIngestKey: null,
  };
  const server = createFirewallMcpServer(config);
  const client = new Client({ name: 'docs-test-client', version: '0.1.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => {
    await client.close();
    await server.close();
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const tools = await client.listTools();
  const advertisedBounds = ['get_conversation', 'get_finding', 'get_finding_trace']
    .map((name) => {
      const schema = tools.tools.find((tool) => tool.name === name)?.inputSchema as {
        properties?: Record<string, { minLength?: number; maxLength?: number }>;
      };
      return {
        minimum: schema.properties?.reason?.minLength,
        maximum: schema.properties?.reason?.maxLength,
      };
    });
  assert.ok(advertisedBounds.every(
    (bounds) => bounds.minimum === advertisedBounds[0].minimum
      && bounds.maximum === advertisedBounds[0].maximum,
  ));

  for (const file of reasonContractFiles) {
    const text = readFileSync(join(root, file), 'utf8').replaceAll('`', '');
    const documentedBounds = [...text.matchAll(
      /reason (?:of |must be )(\d+) to (\d+) characters/gi,
    )];
    assert.ok(documentedBounds.length > 0, `${file} must document reason bounds`);
    for (const match of documentedBounds) {
      assert.deepEqual({
        minimum: Number(match[1]),
        maximum: Number(match[2]),
      }, advertisedBounds[0], `${file} reason bounds must match tools/list`);
    }
    assert.match(text, /leading and trailing whitespace is trimmed/i);
  }
});
