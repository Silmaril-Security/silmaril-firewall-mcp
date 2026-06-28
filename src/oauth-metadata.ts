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

export function publicBaseUrl(req: Request, config: ServerConfig): string {
  if (config.publicBaseUrl) return config.publicBaseUrl;

  const url = new URL(req.url);
  if (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]') {
    return url.origin;
  }

  throw new Error('MCP_PUBLIC_BASE_URL is required for OAuth discovery outside localhost.');
}

export function protectedResourceMetadataUrl(req: Request, config: ServerConfig): string {
  return new URL('/.well-known/oauth-protected-resource/mcp', publicBaseUrl(req, config)).toString();
}

export function wwwAuthenticateHeader(req: Request, config: ServerConfig): string {
  return [
    'Bearer',
    `resource_metadata="${protectedResourceMetadataUrl(req, config)}"`,
    `scope="${DEFAULT_AUTHORIZATION_SCOPES.join(' ')}"`,
  ].join(' ');
}

export async function handleProtectedResourceMetadataRequest(
  req: Request,
  config: ServerConfig,
): Promise<Response> {
  try {
    const upstream = await getFirewallMcpPublicConfig(config);
    const mcpResource = new URL('/mcp', publicBaseUrl(req, config)).toString();

    return json({
      resource: mcpResource,
      authorization_servers: upstream.authorization_servers,
      scopes_supported: upstream.scopes,
      bearer_methods_supported: ['header'],
      resource_name: 'Silmaril Firewall Evidence MCP',
      resource_documentation: 'https://github.com/Silmaril-Security/silmaril-firewall-mcp',
      silmaril_firewall_ui_config: new URL('/api/mcp/v1/config', `${config.firewallUiBaseUrl}/`).toString(),
      silmaril_oauth_resource: upstream.resource || upstream.audience,
      silmaril_oauth_client_id: upstream.oauth?.client_id ?? undefined,
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
