import { readConfig } from '@/config';
import { handleAuthorizationRequest } from '@/oauth-authorization-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  return handleAuthorizationRequest(req, readConfig());
}
