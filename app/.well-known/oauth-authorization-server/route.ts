import { readConfig } from '@/config';
import { handleAuthorizationServerMetadataRequest } from '@/oauth-authorization-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  return handleAuthorizationServerMetadataRequest(req, readConfig());
}
