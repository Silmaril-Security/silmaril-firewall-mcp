import { readConfig } from '@/config';
import { handleTokenRequest } from '@/oauth-authorization-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  return handleTokenRequest(req, readConfig());
}
