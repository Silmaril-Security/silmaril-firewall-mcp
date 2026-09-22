import assert from 'node:assert/strict';
import test, { afterEach, beforeEach } from 'node:test';
import { readConfig } from '../src/config';
import {
  isAllowedOAuthRedirectUri,
  isSafeLoopbackOAuthRedirectUri,
  isValidConfiguredOAuthRedirectUri,
} from '../src/oauth-redirect-policy';

const originalEnv = { ...process.env };
const CLICKUP_REDIRECT = 'https://search.clickup-prod.com/connect/mcp';
const CURSOR_HOSTED_REDIRECT = 'https://www.cursor.com/agents/mcp/oauth/callback';
const CURSOR_NATIVE_REDIRECT = 'cursor://anysphere.cursor-mcp/oauth/callback';

beforeEach(() => {
  process.env.FIREWALL_UI_BASE_URL = 'https://firewall.test';
  delete process.env.MCP_OAUTH_ALLOWED_REDIRECT_URIS;
  delete process.env.MCP_ACTIVITY_ENABLED;
  delete process.env.MCP_ACTIVITY_INGEST_KEY;
});

afterEach(() => {
  process.env = { ...originalEnv };
});

test('OAuth redirect config defaults empty and trims and deduplicates exact entries', () => {
  assert.deepEqual(readConfig().oauthAllowedRedirectUris, []);

  process.env.MCP_OAUTH_ALLOWED_REDIRECT_URIS = [
    `  ${CLICKUP_REDIRECT}  `,
    CURSOR_HOSTED_REDIRECT,
    CLICKUP_REDIRECT,
    CURSOR_NATIVE_REDIRECT,
  ].join(',');

  assert.deepEqual(readConfig().oauthAllowedRedirectUris, [
    CLICKUP_REDIRECT,
    CURSOR_HOSTED_REDIRECT,
    CURSOR_NATIVE_REDIRECT,
  ]);

  process.env.MCP_OAUTH_ALLOWED_REDIRECT_URIS = ' , \t, ';
  assert.deepEqual(readConfig().oauthAllowedRedirectUris, []);
});

test('OAuth redirect config rejects ambiguous or unsafe entries without echoing them', () => {
  const invalidEntries = [
    'not-a-url',
    'http://client.example/callback',
    'https://client.example/callback#',
    'https://client.example/callback#fragment',
    'https://user:password@client.example/callback',
    'https://client.example/*',
    'https://client.example/call back',
    'https://client.example/callback\nnext',
    'HTTPS://client.example/callback',
    'https://CLIENT.example/callback',
    'https://client.example:443/callback',
    'cursor://other-client/callback',
  ];

  for (const entry of invalidEntries) {
    process.env.MCP_OAUTH_ALLOWED_REDIRECT_URIS = entry;
    assert.throws(
      () => readConfig(),
      (error: unknown) => {
        assert.match(String(error), /MCP_OAUTH_ALLOWED_REDIRECT_URIS contains an invalid redirect URI/);
        assert.equal(String(error).includes(entry), false);
        return true;
      },
    );
  }
});

test('shared redirect policy preserves loopback callbacks and requires exact hosted membership', () => {
  const loopbacks = [
    'http://localhost/callback',
    'http://localhost:8787/callback?channel=cursor',
    'http://127.0.0.1:49152/oauth/callback',
    'http://[::1]:8787/oauth/callback?channel=ipv6',
  ];
  for (const redirect of loopbacks) {
    assert.equal(isSafeLoopbackOAuthRedirectUri(redirect), true);
    assert.equal(isAllowedOAuthRedirectUri(redirect, []), true);
  }

  const allowed = [CLICKUP_REDIRECT, CURSOR_HOSTED_REDIRECT, CURSOR_NATIVE_REDIRECT];
  for (const redirect of allowed) {
    assert.equal(isValidConfiguredOAuthRedirectUri(redirect), true);
    assert.equal(isAllowedOAuthRedirectUri(redirect, allowed), true);
  }

  const denied = [
    'https://search.clickup-prod.com/connect/other',
    'https://www.cursor.com/agents/mcp/oauth/callback/',
    'https://www.cursor.com:444/agents/mcp/oauth/callback',
    'https://www.cursor.com/agents/mcp/oauth/callback?source=other',
    'https://WWW.cursor.com/agents/mcp/oauth/callback',
    'https://user@www.cursor.com/agents/mcp/oauth/callback',
    'https://unapproved.example/callback',
    'http://localhost:8787/callback#',
    'http://localhost:8787/callback#fragment',
    'http://user@localhost:8787/callback',
  ];
  for (const redirect of denied) {
    assert.equal(isAllowedOAuthRedirectUri(redirect, allowed), false);
  }
});
