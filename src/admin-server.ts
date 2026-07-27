import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { ServerConfig } from './config';
import { FirewallApiError, firewallGetJson, pathWithQuery } from './firewall-ui-client';
import { downstreamToken } from './auth-context';

type Extra = RequestHandlerExtra<ServerRequest, ServerNotification>;

const ActivityRangeSchema = z.enum(['1d', '7d', '30d', '90d']);
const TenantSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);
const ToolSchema = z.string().min(1).max(128).regex(/^[a-z][a-z0-9_]*$/);

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

function token(extra: Extra): string {
  return downstreamToken(extra.authInfo);
}

function result(toolName: string, payload: unknown) {
  return {
    structuredContent: payload as Record<string, unknown>,
    content: [{
      type: 'text' as const,
      text: `${toolName} returned structured MCP adoption data.`,
    }],
  };
}

function errorResult(err: unknown) {
  const status = err instanceof FirewallApiError ? err.status : 500;
  const code = err instanceof FirewallApiError ? err.code : 'mcp_tool_error';
  const message = err instanceof Error ? err.message : 'MCP admin tool failed.';
  return {
    isError: true,
    structuredContent: { error: { status, code, message } },
    content: [{ type: 'text' as const, text: `firewall-ui ${status} ${code}: ${message}` }],
  };
}

async function callAdmin(
  toolName: string,
  path: string,
  extra: Extra,
  config: ServerConfig,
) {
  try {
    return result(toolName, await firewallGetJson({
      path,
      token: token(extra),
      config,
      signal: extra.signal,
    }));
  } catch (err) {
    return errorResult(err);
  }
}

export async function assertAdminAccess(
  tokenValue: string,
  config: ServerConfig,
  signal?: AbortSignal,
): Promise<void> {
  await firewallGetJson({
    path: '/api/mcp/v1/admin/access',
    token: tokenValue,
    config,
    signal,
  });
}

export function createAdminMcpServer(config: ServerConfig): McpServer {
  const server = new McpServer({
    name: 'silmaril-firewall-admin-mcp',
    version: '0.1.0',
  }, {
    instructions: 'Global Silmaril administrator interface for bounded MCP adoption analytics. Read-only.',
  });

  server.registerTool('get_mcp_adoption_summary', {
    title: 'Get MCP Adoption Summary',
    description: 'Summarize MCP calls, outcomes, active tenants/users, daily activity, and tool/category mix.',
    inputSchema: {
      range: ActivityRangeSchema.default('30d'),
      tenant: TenantSchema.optional(),
    },
    annotations: readOnlyAnnotations,
  }, async ({ range, tenant }, extra) => callAdmin(
    'get_mcp_adoption_summary',
    pathWithQuery('/api/mcp/v1/admin/activity/summary', { range, tenant }),
    extra,
    config,
  ));

  server.registerTool('list_mcp_activity', {
    title: 'List MCP Activity',
    description: 'List the newest named-actor MCP activity events with validated filters.',
    inputSchema: {
      range: ActivityRangeSchema.default('30d'),
      tenant: TenantSchema.optional(),
      actor_email: z.string().email().max(320).optional(),
      tool_name: ToolSchema.optional(),
      outcome: z.enum(['success', 'error']).optional(),
      limit: z.number().int().min(1).max(100).default(50),
    },
    annotations: readOnlyAnnotations,
  }, async ({ range, tenant, actor_email, tool_name, outcome, limit }, extra) => callAdmin(
    'list_mcp_activity',
    pathWithQuery('/api/mcp/v1/admin/activity/recent', {
      range,
      tenant,
      actor_email,
      tool_name,
      outcome,
      limit,
    }),
    extra,
    config,
  ));

  return server;
}
