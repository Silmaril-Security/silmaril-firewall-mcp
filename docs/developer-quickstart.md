# Developer Quickstart

1. Configure Auth0 API access tokens for the Firewall MCP audience in `firewall-ui`.
2. Deploy or run `firewall-ui` with `SILMARIL_MCP_API_ENABLED=true`.
3. Configure this repo with `FIREWALL_UI_BASE_URL`, `MCP_ALLOWED_ORIGINS`, and `AUTH0_MCP_AUDIENCE`.
4. Run the MCP server locally:

```sh
npm install
npm run dev
```

5. Add the server to Codex using OAuth:

```sh
codex mcp add silmaril-firewall \
  --url http://localhost:3000/mcp \
  --oauth-client-id <auth0-client-id> \
  --oauth-resource https://silmaril.security/firewall-ui/mcp
```

6. Start with aggregate tools:

```txt
list_firewalls
get_firewall
get_metrics
list_findings
get_investigation_packet
```

Use `get_finding` or `get_finding_trace` only after a compact evidence path is insufficient.

## Local Validation

```sh
npm run lint
npm run typecheck
npm test
npm run build
```

`npm test` runs an SDK client over Streamable HTTP with mocked `firewall-ui` responses and verifies bearer forwarding, Origin rejection, normalized errors, and non-logging of payload canaries.
