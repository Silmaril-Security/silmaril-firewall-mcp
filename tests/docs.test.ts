import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const guardedFiles = [
  'README.md',
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
