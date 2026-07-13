import type { ServerConfig } from './config';
import {
  DEFAULT_AUTHORIZATION_SCOPES,
  getFirewallMcpPublicConfig,
} from './firewall-ui-config';

function json(payload: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(payload), {
    ...init,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...(init?.headers ?? {}),
    },
  });
}

export function publicBaseUrl(config: ServerConfig): string {
  if (config.publicBaseUrl) return config.publicBaseUrl;
  throw new Error('MCP_PUBLIC_BASE_URL is required for OAuth discovery.');
}

export type McpResourceKind = 'public' | 'admin';

export function protectedResourceMetadataUrl(
  config: ServerConfig,
  kind: McpResourceKind = 'public',
): string {
  const path = kind === 'admin'
    ? '/.well-known/oauth-protected-resource/admin-mcp'
    : '/.well-known/oauth-protected-resource/mcp';
  return new URL(path, publicBaseUrl(config)).toString();
}

export function wwwAuthenticateHeader(
  config: ServerConfig,
  kind: McpResourceKind = 'public',
): string {
  const scopes = kind === 'admin' ? ['firewalls:read'] : DEFAULT_AUTHORIZATION_SCOPES;
  return [
    'Bearer',
    `resource_metadata="${protectedResourceMetadataUrl(config, kind)}"`,
    `scope="${scopes.join(' ')}"`,
  ].join(' ');
}

export async function handleProtectedResourceMetadataRequest(
  req: Request,
  config: ServerConfig,
  kind: McpResourceKind = 'public',
): Promise<Response> {
  try {
    const upstream = await getFirewallMcpPublicConfig(config);
    const mcpResource = new URL(kind === 'admin' ? '/admin/mcp' : '/mcp', publicBaseUrl(config)).toString();
    const issuer = publicBaseUrl(config);

    return json({
      resource: mcpResource,
      authorization_servers: [issuer],
      scopes_supported: kind === 'admin' ? ['firewalls:read'] : upstream.scopes,
      bearer_methods_supported: ['header'],
      resource_name: kind === 'admin'
        ? 'Silmaril Firewall Admin MCP'
        : 'Silmaril Firewall Evidence MCP',
      resource_documentation: 'https://github.com/Silmaril-Security/silmaril-firewall-mcp',
      silmaril_firewall_ui_config: new URL('/api/mcp/v1/config', `${config.firewallUiBaseUrl}/`).toString(),
      silmaril_oauth_resource: upstream.resource || upstream.audience,
      silmaril_oauth_client_id: upstream.oauth?.client_id ?? undefined,
      silmaril_upstream_authorization_servers: upstream.authorization_servers,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'MCP OAuth metadata is unavailable.';
    return json({
      error: {
        code: 'mcp_oauth_metadata_unavailable',
        message,
      },
    }, { status: 503 });
  }
}
