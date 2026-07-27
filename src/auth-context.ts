import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';

export interface McpActorContext {
  subject: string;
  organization: string | null;
  tenant: string | null;
  actorEmail: string | null;
  clientId: string;
  tokenId: string | null;
}

export function downstreamToken(authInfo: AuthInfo | undefined): string {
  const value = authInfo?.extra?.downstreamToken;
  if (typeof value !== 'string' || !value) {
    throw new Error('Missing validated downstream credential.');
  }
  return value;
}

export function actorContext(authInfo: AuthInfo | undefined): McpActorContext {
  const subject = authInfo?.extra?.subject;
  if (typeof subject !== 'string' || !subject) {
    throw new Error('Missing authenticated actor subject.');
  }
  const nullableString = (value: unknown): string | null =>
    typeof value === 'string' && value ? value : null;
  return {
    subject,
    organization: nullableString(authInfo?.extra?.organization),
    tenant: nullableString(authInfo?.extra?.tenant),
    actorEmail: nullableString(authInfo?.extra?.actorEmail),
    clientId: authInfo?.clientId ?? 'unknown',
    tokenId: nullableString(authInfo?.extra?.tokenId),
  };
}
