import { jwtVerify, SignJWT } from 'jose';

import type { RuntimeConfig } from './types.ts';
import { randomToken } from './utils.ts';

export const SESSION_COOKIE = '__Host-zeroauth_session';
export const BROWSER_COOKIE = '__Host-zeroauth_browser';
export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
export const TRANSACTION_TTL_SECONDS = 10 * 60;

const encoder = new TextEncoder();

// Use the existing client secret as a high-entropy HMAC key. Including the password
// invalidates sessions and pending forms on password rotation, without exposing a
// password hash or needing another secret/KV binding.
async function authenticationKey(config: RuntimeConfig): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(config.clientSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const signature = await crypto.subtle.sign(
    'HMAC', key, encoder.encode(JSON.stringify(['zeroauth-browser-v1', config.password])),
  );
  return new Uint8Array(signature);
}

export function readCookie(request: Request, name: string): string | undefined {
  return request.headers.get('Cookie')?.split(';')
    .map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
}

export function browserBinding(request: Request): string {
  const current = readCookie(request, BROWSER_COOKIE);
  return current && /^[A-Za-z0-9_-]{43}$/.test(current) ? current : randomToken();
}

export function cookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function signBrowserToken(
  config: RuntimeConfig, type: string, claims: Record<string, unknown>, ttl: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256', typ: type })
    .setIssuer(config.issuer).setAudience(config.clientId)
    .setIssuedAt(now).setExpirationTime(now + ttl)
    .sign(await authenticationKey(config));
}

async function verifyBrowserToken(token: string, config: RuntimeConfig, type: string) {
  if (token.length > 16_384) throw new Error('Browser token too large');
  return (await jwtVerify(token, await authenticationKey(config), {
    algorithms: ['HS256'], issuer: config.issuer, audience: config.clientId, typ: type,
    requiredClaims: ['iat', 'exp'],
  })).payload;
}

export async function createLoginTransaction(
  config: RuntimeConfig, parameters: URLSearchParams, binding: string,
): Promise<string> {
  return signBrowserToken(config, 'zeroauth-login+jwt', {
    parameters: parameters.toString(), binding,
  }, TRANSACTION_TTL_SECONDS);
}

export async function readLoginTransaction(
  request: Request, token: string, config: RuntimeConfig,
): Promise<URLSearchParams | null> {
  try {
    const payload = await verifyBrowserToken(token, config, 'zeroauth-login+jwt');
    const binding = readCookie(request, BROWSER_COOKIE);
    if (!binding || payload.binding !== binding || typeof payload.parameters !== 'string') return null;
    return new URLSearchParams(payload.parameters);
  } catch {
    return null;
  }
}

export async function createSession(config: RuntimeConfig, authTime: number): Promise<string> {
  return signBrowserToken(config, 'zeroauth-session+jwt', { auth_time: authTime }, SESSION_TTL_SECONDS);
}

export async function sessionAuthTime(request: Request, config: RuntimeConfig): Promise<number | null> {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;
  try {
    const payload = await verifyBrowserToken(token, config, 'zeroauth-session+jwt');
    const time = payload.auth_time;
    return typeof time === 'number' && Number.isSafeInteger(time) && time > 0 &&
      time <= Math.floor(Date.now() / 1000) ? time : null;
  } catch {
    return null;
  }
}

export async function passwordMatches(input: string, config: RuntimeConfig): Promise<boolean> {
  // Web Crypto verifies the HMAC rather than comparing password strings in JS.
  const key = await crypto.subtle.importKey(
    'raw', await authenticationKey(config), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'],
  );
  const expected = await crypto.subtle.sign('HMAC', key, encoder.encode(config.password));
  return crypto.subtle.verify('HMAC', key, expected, encoder.encode(input));
}
