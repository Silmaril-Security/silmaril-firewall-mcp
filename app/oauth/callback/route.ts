import { readConfig } from '@/config';
import { handleOAuthCallbackRequest } from '@/oauth-authorization-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  return handleOAuthCallbackRequest(req, readConfig());
}
