import { readConfig } from '@/config';
import { getFirewallMcpPublicConfig } from '@/firewall-ui-config';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const config = readConfig();
    if (!config.publicBaseUrl || !config.oauthStateSecret || Buffer.byteLength(config.oauthStateSecret, 'utf8') < 32 || !config.auditUrl) {
      throw new Error('Incomplete MCP configuration');
    }
    const upstream = await getFirewallMcpPublicConfig(config);
    if (!upstream.oauth?.client_id) throw new Error('MCP OAuth client is not configured.');
    return Response.json({ status: 'ready' });
  } catch {
    return Response.json({ status: 'unavailable' }, { status: 503 });
  }
}
