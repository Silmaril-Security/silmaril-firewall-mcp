import { readConfig } from '@/config';
import { handleProtectedResourceMetadataRequest } from '@/oauth-metadata';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  return handleProtectedResourceMetadataRequest(req, readConfig());
}
