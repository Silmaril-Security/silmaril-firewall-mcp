import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';
import { z } from 'zod';
import type { ServerConfig } from './config';
import { publicBaseUrl, type McpResourceKind } from './oauth-metadata';

const CREDENTIAL_VERSION = 1;
const ACCESS_PREFIX = 'mcp_at_v1';
const REFRESH_PREFIX = 'mcp_rt_v1';
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const MAX_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_REFRESH_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

const CredentialSchema = z.object({
  v: z.literal(CREDENTIAL_VERSION),
  kind: z.enum(['access', 'refresh']),
  downstream_token: z.string().min(1),
  client_id: z.string().min(1),
  resource: z.string().url(),
  scopes: z.array(z.string().min(1)),
  subject: z.string().min(1),
  organization: z.string().min(1).optional(),
  tenant: z.string().min(1).optional(),
  actor_email: z.string().email().optional(),
  token_id: z.string().min(1).optional(),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
});

export type McpCredential = z.infer<typeof CredentialSchema>;

export class McpCredentialError extends Error {
  constructor(
    public readonly code: 'invalid_token' | 'invalid_resource',
    message: string,
  ) {
    super(message);
  }
}

function credentialSecret(config: ServerConfig): string {
  const secret = config.oauthStateSecret;
  if (!secret || Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('MCP_OAUTH_STATE_SECRET must contain at least 32 bytes.');
  }
  return secret;
}

function encryptionKey(config: ServerConfig): Buffer {
  return createHash('sha256')
    .update('silmaril-firewall-mcp-credential:v1\0')
    .update(credentialSecret(config))
    .digest();
}

function prefixFor(kind: McpCredential['kind']): string {
  return kind === 'access' ? ACCESS_PREFIX : REFRESH_PREFIX;
}

function seal(payload: McpCredential, config: ServerConfig): string {
  const prefix = prefixFor(payload.kind);
  const iv = randomBytes(AES_GCM_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(config), iv, {
    authTagLength: AES_GCM_TAG_BYTES,
  });
  cipher.setAAD(Buffer.from(prefix, 'utf8'));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(payload), 'utf8'),
    cipher.final(),
  ]);
  const encrypted = Buffer.concat([ciphertext, cipher.getAuthTag()]);
  return `${prefix}.${iv.toString('base64url')}.${encrypted.toString('base64url')}`;
}

function open(value: string, expectedKind: McpCredential['kind'], config: ServerConfig): McpCredential {
  try {
    const expectedPrefix = prefixFor(expectedKind);
    const [prefix, encodedIv, encodedEncrypted, extra] = value.split('.');
    if (prefix !== expectedPrefix || !encodedIv || !encodedEncrypted || extra !== undefined) {
      throw new Error('Malformed credential.');
    }
    const iv = Buffer.from(encodedIv, 'base64url');
    const encrypted = Buffer.from(encodedEncrypted, 'base64url');
    if (iv.length !== AES_GCM_IV_BYTES || encrypted.length <= AES_GCM_TAG_BYTES) {
      throw new Error('Malformed credential.');
    }
    const ciphertext = encrypted.subarray(0, encrypted.length - AES_GCM_TAG_BYTES);
    const tag = encrypted.subarray(encrypted.length - AES_GCM_TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', encryptionKey(config), iv, {
      authTagLength: AES_GCM_TAG_BYTES,
    });
    decipher.setAAD(Buffer.from(prefix, 'utf8'));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    const credential = CredentialSchema.parse(JSON.parse(plaintext));
    if (credential.kind !== expectedKind) throw new Error('Wrong credential kind.');
    return credential;
  } catch {
    throw new McpCredentialError('invalid_token', 'Bearer token is invalid.');
  }
}

export function mcpResource(config: ServerConfig, kind: McpResourceKind): string {
  return new URL(kind === 'admin' ? '/admin/mcp' : '/mcp', publicBaseUrl(config)).toString();
}

export function issueMcpCredential(
  input: Omit<McpCredential, 'v' | 'iat' | 'exp'> & {
    expiresInSeconds?: number;
    issuedAtSeconds?: number;
  },
  config: ServerConfig,
): string {
  const issuedAt = input.issuedAtSeconds ?? Math.floor(Date.now() / 1000);
  const expiresIn = input.expiresInSeconds ?? DEFAULT_REFRESH_LIFETIME_SECONDS;
  return seal({
    v: CREDENTIAL_VERSION,
    kind: input.kind,
    downstream_token: input.downstream_token,
    client_id: input.client_id,
    resource: input.resource,
    scopes: [...new Set(input.scopes)],
    subject: input.subject,
    organization: input.organization,
    tenant: input.tenant,
    actor_email: input.actor_email,
    token_id: input.token_id,
    iat: issuedAt,
    exp: issuedAt + expiresIn,
  }, config);
}

export function validateMcpAccessToken(
  value: string,
  kind: McpResourceKind,
  config: ServerConfig,
): McpCredential {
  const credential = open(value, 'access', config);
  const now = Math.floor(Date.now() / 1000);
  if (credential.iat > now + MAX_CLOCK_SKEW_SECONDS || credential.exp <= now) {
    throw new McpCredentialError('invalid_token', 'Bearer token is expired or not yet valid.');
  }
  if (credential.resource !== mcpResource(config, kind)) {
    throw new McpCredentialError('invalid_resource', 'Bearer token is not valid for this MCP resource.');
  }
  return credential;
}

export function validateMcpRefreshToken(
  value: string,
  clientId: string,
  config: ServerConfig,
): McpCredential {
  const credential = open(value, 'refresh', config);
  const now = Math.floor(Date.now() / 1000);
  if (credential.exp <= now || credential.client_id !== clientId) {
    throw new McpCredentialError('invalid_token', 'Refresh token is invalid or expired.');
  }
  return credential;
}
