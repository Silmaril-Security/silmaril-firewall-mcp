# Customer-hosted MCP

SilmarilTF can run this same application as an independent Fargate task behind
its dashboard HTTPS origin. It receives no AWS task role. The dashboard remains
the evidence authority and validates installation membership independently.

The signed installation supplies `FIREWALL_UI_BASE_URL`, `MCP_PUBLIC_BASE_URL`,
`MCP_AUTH0_ORGANIZATION`, and `MCP_AUDIT_URL` (the dashboard's authenticated
`/api/mcp/v1/audit` endpoint). Secrets Manager injects `MCP_OAUTH_STATE_SECRET`.
For same-origin audit endpoints, the existing verified downstream user token is
attached to the audit request. It is never sent to an external audit sink.

**On a workstation, from the MCP repository:** build the exact source with `docker build --build-arg SILMARIL_MCP_COMMIT=$(git rev-parse HEAD) -t silmaril-firewall-mcp .`.
The image exposes `/healthz` for liveness and `/readyz` for configuration and
upstream API readiness. Bind the image by digest in the signed customer product;
local build success does not qualify a customer deployment.

Use the installation's `/mcp` URL with the existing client OAuth flow. Auth0
callbacks, discovery paths, and `/oauth/*` are served by this application;
`/api/mcp/v1/*` remains on the dashboard. The global administrator resource is
not exposed in customer installations.

## Immutable image publication

After the reviewed commit reaches main, run **Customer product MCP image** from
main. The workflow tests and builds linux/amd64, checks read-only non-root
startup, and publishes only the tested image. It does not sign a product or
apply customer infrastructure.

The customer-platform pipeline owns the source ECR publishing role. Configure
GitHub environment `customer-product-release` with main-only deployment branches
and these non-secret repository variables:

- `AWS_CUSTOMER_PRODUCT_MCP_PUBLISH_ROLE_ARN`: the pipeline stack's MCP publisher output.
- `AWS_CUSTOMER_PRODUCT_MCP_REPOSITORY`: the exact source application ECR repository.

The role trusts only this repository and environment. It can publish images to
the configured repository, without infrastructure, AppConfig, or secret access.
The immutable tag is `mcp-<full-source-commit>`. A retry verifies an existing
image's digest, linux/amd64 platform, source/mode labels and container startup;
it never overwrites a tag. Lookup errors other than ImageNotFound fail closed.

The `customer-mcp-image-<commit>` workflow artifact contains `mcp-image.json`:
`{uri, sha256, commit}`. Copy that exact object into a new Firewall product
definition's `mcp_image` after independently verifying the publication receipt.
Firewall then qualifies, signs, and distributes the complete customer product.
Do not manufacture a release pin from a PR build or treat publication as customer
activation.
