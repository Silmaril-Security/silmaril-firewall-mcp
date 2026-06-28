# Developer Quickstart

1. Configure the Firewall MCP audience and public OAuth client in `firewall-ui`.
2. Deploy or run `firewall-ui` with `SILMARIL_MCP_API_ENABLED=true`.
3. Configure this repo with `FIREWALL_UI_BASE_URL`, `MCP_PUBLIC_BASE_URL`, and `MCP_AUTH0_ORGANIZATION` when the Auth0 app requires organization login. `MCP_PUBLIC_BASE_URL` is the trusted public origin advertised through OAuth discovery.
4. Run the MCP server locally on a different port from `firewall-ui`:

```sh
npm install
FIREWALL_UI_BASE_URL=http://localhost:3000 MCP_PUBLIC_BASE_URL=http://localhost:3002 PORT=3002 npm run dev
```

5. Add the local server to an MCP client:

```sh
codex mcp add silmaril-firewall --url http://localhost:3002/mcp
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

## Operator Notes

`firewall-ui` exposes `GET /api/mcp/v1/config` for MCP-server diagnostics and OAuth discovery support. It returns non-secret issuer, resource, scope, enabled-state, and public-client metadata.

The MCP host advertises itself as the authorization server for MCP clients. Its local registration endpoint returns the configured public client, its authorize route redirects to Silmaril login with a fixed hosted callback and the configured default organization, and its token route forwards the authorization-code exchange with the client's PKCE verifier.

## Local Validation

```sh
npm run lint
npm run typecheck
npm test
npm run build
```

`npm test` runs an SDK client over Streamable HTTP with mocked `firewall-ui` responses and verifies bearer forwarding, Origin rejection, normalized errors, and non-logging of payload canaries.
