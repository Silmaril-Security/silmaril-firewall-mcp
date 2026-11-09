import { McpServer, type ServerContext } from '@modelcontextprotocol/server';
import { z } from 'zod';
import type { ServerConfig } from './config';
import { FirewallApiError, firewallGetJson, pathWithQuery } from './firewall-ui-client';
import { downstreamToken } from './auth-context';

const ActivityRangeSchema = z.enum(['1d', '7d', '30d', '90d']);
const TenantSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);
const ToolSchema = z.string().min(1).max(128).regex(/^[a-z][a-z0-9_]*$/);

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

function token(ctx: ServerContext): string {
  return downstreamToken(ctx.http?.authInfo);
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
  ctx: ServerContext,
  config: ServerConfig,
) {
  try {
    return result(toolName, await firewallGetJson({
      path,
      token: token(ctx),
      config,
      signal: ctx.mcpReq.signal,
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
    maxToolInputElements: 8,
    instructions: 'Global Silmaril administrator interface for bounded MCP adoption analytics. Read-only.',
  });

  server.registerTool('get_mcp_adoption_summary', {
    title: 'Get MCP Adoption Summary',
    description: 'Summarize MCP calls, outcomes, active tenants/users, daily activity, and tool/category mix.',
    inputSchema: z.object({
      range: ActivityRangeSchema.default('30d'),
      tenant: TenantSchema.optional(),
    }),
    annotations: readOnlyAnnotations,
  }, async ({ range, tenant }, ctx) => callAdmin(
    'get_mcp_adoption_summary',
    pathWithQuery('/api/mcp/v1/admin/activity/summary', { range, tenant }),
    ctx,
    config,
  ));

  server.registerTool('list_mcp_activity', {
    title: 'List MCP Activity',
    description: 'List the newest named-actor MCP activity events with validated filters.',
    inputSchema: z.object({
      range: ActivityRangeSchema.default('30d'),
      tenant: TenantSchema.optional(),
      actor_email: z.string().email().max(320).optional(),
      tool_name: ToolSchema.optional(),
      outcome: z.enum(['success', 'error']).optional(),
      limit: z.number().int().min(1).max(100).default(50),
    }),
    annotations: readOnlyAnnotations,
  }, async ({ range, tenant, actor_email, tool_name, outcome, limit }, ctx) => callAdmin(
    'list_mcp_activity',
    pathWithQuery('/api/mcp/v1/admin/activity/recent', {
      range,
      tenant,
      actor_email,
      tool_name,
      outcome,
      limit,
    }),
    ctx,
    config,
  ));

  return server;
}
