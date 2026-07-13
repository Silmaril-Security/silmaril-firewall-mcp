import { handleMcpRequest } from '@/http';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  return handleMcpRequest(req, { mode: 'admin' });
}

export async function POST(req: Request) {
  return handleMcpRequest(req, { mode: 'admin' });
}

export async function DELETE(req: Request) {
  return handleMcpRequest(req, { mode: 'admin' });
}

export async function OPTIONS(req: Request) {
  return handleMcpRequest(req, { mode: 'admin' });
}
