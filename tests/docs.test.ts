import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

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
