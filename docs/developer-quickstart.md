# Developer Quickstart

1. Configure Auth0 API access tokens for the Firewall MCP audience in `firewall-ui`.
2. Deploy or run `firewall-ui` with `SILMARIL_MCP_API_ENABLED=true`.
3. Configure this repo with `FIREWALL_UI_BASE_URL` and `MCP_PUBLIC_BASE_URL`. Set `MCP_ADDITIONAL_ALLOWED_ORIGINS` only for additional browser-hosted MCP clients.
4. Run the MCP server locally. Use a different port from `firewall-ui`:

```sh
npm install
FIREWALL_UI_BASE_URL=http://localhost:3000 MCP_PUBLIC_BASE_URL=http://localhost:3002 PORT=3002 npm run dev
```

5. Add the server to a discovery-capable MCP client using only the MCP URL:

```txt
http://localhost:3002/mcp
```

For clients that require explicit OAuth fields, read the public values from `firewall-ui`:

```sh
curl "$FIREWALL_UI_BASE_URL/api/mcp/v1/config"
```

Codex explicit setup:

```sh
codex mcp add silmaril-firewall \
  --url http://localhost:3002/mcp \
  --oauth-client-id <oauth.client_id from firewall-ui config> \
  --oauth-resource <resource from firewall-ui config>
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
