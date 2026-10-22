const NO_STORE_HEADERS = {
  'Cache-Control': 'no-store',
  Pragma: 'no-cache',
};

export function appendQueryParameters(
  target: string,
  params: Record<string, string | undefined>,
): string {
  const url = new URL(target);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
}

export function assertAbsoluteUrl(value: string, fieldName: string): string {
  const trimmed = value.trim();
  let url: URL;

  try {
    url = new URL(trimmed);
  } catch {
    throw new Error(`${fieldName} must be a valid absolute URL`);
  }

  if (url.protocol !== 'https:') {
    throw new Error(`${fieldName} must use https`);
  }

  if (url.hash || url.search) {
    throw new Error(`${fieldName} must not contain a query string or fragment`);
  }

  return trimmed;
}

export function base64UrlEncode(input: Uint8Array): string {
  return btoa(String.fromCharCode(...input))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export function decodeBasicAuthHeader(value: string): { clientId: string; clientSecret: string } | null {
  if (!value.startsWith('Basic ')) {
    return null;
  }

  try {
    const decoded = atob(value.slice('Basic '.length));
    const separatorIndex = decoded.indexOf(':');

    if (separatorIndex < 0) {
      return null;
    }

    return {
      clientId: decoded.slice(0, separatorIndex),
      clientSecret: decoded.slice(separatorIndex + 1),
    };
  } catch {
    return null;
  }
}

export function htmlResponse(body: string, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set('Content-Type', 'text/html; charset=utf-8');
  return new Response(body, { ...init, headers });
}

export function includesOpenIdScope(scope: string): boolean {
  return new Set(normalizeScope(scope).split(' ')).has('openid');
}

export function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function jsonResponse(value: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set('Content-Type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(value, null, 2), { ...init, headers });
}

export function noStoreHeaders(headers?: HeadersInit): Headers {
  const merged = new Headers(headers);
  for (const [key, value] of Object.entries(NO_STORE_HEADERS)) {
    merged.set(key, value);
  }
  return merged;
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function normalizeScope(scope: string): string {
  return [...new Set(scope.trim().split(/\s+/).filter(Boolean))].join(' ');
}

export function parseRedirectUriList(value: string | undefined): Set<string> {
  if (!value || !value.trim()) {
    return new Set();
  }

  const trimmed = value.trim();
  const entries = trimmed.startsWith('[')
    ? (JSON.parse(trimmed) as string[])
    : trimmed.split(',').map((item) => item.trim()).filter(Boolean);

  const redirectUris = new Set<string>();

  for (const entry of entries) {
    const url = new URL(entry);
    redirectUris.add(url.toString());
  }

  return redirectUris;
}

export function randomToken(size = 32): string {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, '0')).join('');
}
