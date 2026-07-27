import type { ServerConfig } from './config';

interface Bucket {
  tokens: number;
  updatedAt: number;
  lastSeen: number;
}

const buckets = new Map<string, Bucket>();
const MAX_BUCKETS = 10_000;

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

function prune(now: number): void {
  if (buckets.size < MAX_BUCKETS) return;
  const staleBefore = now - 10 * 60_000;
  for (const [key, bucket] of buckets) {
    if (bucket.lastSeen < staleBefore) buckets.delete(key);
  }
  while (buckets.size >= MAX_BUCKETS) {
    const oldest = buckets.keys().next().value as string | undefined;
    if (!oldest) break;
    buckets.delete(oldest);
  }
}

export function consumeRateLimit(
  key: string,
  config: ServerConfig,
  cost = 1,
  now = Date.now(),
): RateLimitResult {
  prune(now);
  const rate = config.rateLimitRequestsPerSecond;
  const burst = config.rateLimitBurst;
  const bucket = buckets.get(key) ?? {
    tokens: burst,
    updatedAt: now,
    lastSeen: now,
  };
  const elapsedSeconds = Math.max(0, now - bucket.updatedAt) / 1000;
  bucket.tokens = Math.min(burst, bucket.tokens + elapsedSeconds * rate);
  bucket.updatedAt = now;
  bucket.lastSeen = now;
  const boundedCost = Math.max(1, Math.min(Math.floor(cost), burst));
  if (bucket.tokens < boundedCost) {
    buckets.set(key, bucket);
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((boundedCost - bucket.tokens) / rate)),
    };
  }
  bucket.tokens -= boundedCost;
  buckets.delete(key);
  buckets.set(key, bucket);
  return { allowed: true, retryAfterSeconds: 0 };
}

export function resetRateLimitsForTests(): void {
  buckets.clear();
}
