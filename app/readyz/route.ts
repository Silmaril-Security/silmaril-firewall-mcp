import { readConfig } from '@/config';
import { getFirewallMcpPublicConfig } from '@/firewall-ui-config';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const config = readConfig();
    if (!config.publicBaseUrl || !config.oauthStateSecret || config.oauthStateSecret.length < 32 || !config.auditUrl) {
      throw new Error('Incomplete MCP configuration');
    }
    await getFirewallMcpPublicConfig(config);
    return Response.json({ status: 'ready' });
  } catch {
    return Response.json({ status: 'unavailable' }, { status: 503 });
  }
}
