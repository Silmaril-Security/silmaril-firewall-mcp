const CURSOR_NATIVE_REDIRECT_URI = 'cursor://anysphere.cursor-mcp/oauth/callback';
const AMBIGUOUS_CHARACTER_RE = /[\p{White_Space}\p{Cc}\p{Cf}]/u;

function hasUnsafeSyntax(value: string): boolean {
  return (
    value.length === 0 ||
    value.includes('*') ||
    value.includes('\\') ||
    value.includes('#') ||
    AMBIGUOUS_CHARACTER_RE.test(value)
  );
}

function parsedWithoutCredentials(value: string): URL | null {
  try {
    const parsed = new URL(value);
    if (parsed.username || parsed.password || !parsed.hostname) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function isValidConfiguredOAuthRedirectUri(value: string): boolean {
  if (value === CURSOR_NATIVE_REDIRECT_URI) return true;
  if (hasUnsafeSyntax(value) || !value.startsWith('https://')) return false;

  const parsed = parsedWithoutCredentials(value);
  return Boolean(parsed && parsed.protocol === 'https:' && parsed.href === value);
}

export function isSafeLoopbackOAuthRedirectUri(value: string): boolean {
  if (hasUnsafeSyntax(value)) return false;
  const parsed = parsedWithoutCredentials(value);
  if (!parsed || parsed.protocol !== 'http:') return false;
  return (
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === 'localhost' ||
    parsed.hostname === '[::1]'
  );
}

export function isAllowedOAuthRedirectUri(
  value: string,
  configuredAllowedRedirectUris: readonly string[],
): boolean {
  return (
    isSafeLoopbackOAuthRedirectUri(value) ||
    (
      isValidConfiguredOAuthRedirectUri(value) &&
      configuredAllowedRedirectUris.includes(value)
    )
  );
}
