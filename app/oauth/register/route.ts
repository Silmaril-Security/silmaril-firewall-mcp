import { readConfig } from '@/config';
import { handleClientRegistrationRequest } from '@/oauth-authorization-server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  return handleClientRegistrationRequest(req, readConfig());
}
