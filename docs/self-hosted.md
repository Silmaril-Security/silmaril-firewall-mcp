# Customer-hosted MCP

SilmarilTF can run this same application as an independent Fargate task behind
its dashboard HTTPS origin. It receives no AWS task role. The dashboard remains
the evidence authority and validates installation membership independently.

The signed installation supplies `FIREWALL_UI_BASE_URL`, `MCP_PUBLIC_BASE_URL`,
`MCP_AUTH0_ORGANIZATION`, and `MCP_AUDIT_URL` (the dashboard's authenticated
`/api/mcp/v1/audit` endpoint). Secrets Manager injects `MCP_OAUTH_STATE_SECRET`.
For same-origin audit endpoints, the existing verified downstream user token is
attached to the audit request. It is never sent to an external audit sink.

Build the exact source with `docker build --build-arg SILMARIL_MCP_COMMIT=$(git rev-parse HEAD) -t silmaril-firewall-mcp .`.
The image exposes `/healthz` for liveness and `/readyz` for configuration and
upstream API readiness. Bind the image by digest in the signed customer product;
local build success does not qualify a customer deployment.

Use the installation's `/mcp` URL with the existing client OAuth flow. Auth0
callbacks, discovery paths, and `/oauth/*` are served by this application;
`/api/mcp/v1/*` remains on the dashboard. The global administrator resource is
not exposed in customer installations.
