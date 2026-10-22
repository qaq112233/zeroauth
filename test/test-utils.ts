import { exportJWK, generateKeyPair } from 'jose';

import type { Env } from '../src/types.ts';
import { handleRequest } from '../src/app.ts';

type StoredValue = {
  expiresAt?: number;
  value: string;
};

class MockKVNamespace {
  readonly writes: string[] = [];
  private readonly store = new Map<string, StoredValue>();

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);

    if (!entry) {
      return null;
    }

    if (entry.expiresAt !== undefined && Date.now() >= entry.expiresAt) {
      this.store.delete(key);
      return null;
    }

    return entry.value;
  }

  async put(
    key: string,
    value: string,
    options?: {
      expirationTtl?: number;
    },
  ): Promise<void> {
    this.writes.push(key);
    const expiresAt =
      options?.expirationTtl === undefined ? undefined : Date.now() + options.expirationTtl * 1000;

    this.store.set(key, { expiresAt, value });
  }
}

export async function createTestEnv(overrides: Partial<Env> = {}): Promise<Env> {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  privateJwk.alg = 'RS256';
  privateJwk.use = 'sig';

  return {
    ZEROAUTH_CODES: new MockKVNamespace() as unknown as KVNamespace,
    ZEROAUTH_PASSWORD: 'test-shared-password',
    ZEROAUTH_ALLOWED_EMAIL_DOMAINS: 'example.com, second.example',
    ZEROAUTH_ALLOWED_REDIRECT_URIS: 'https://client.example/callback',
    ZEROAUTH_AUTH_CODE_TTL_SECONDS: '60',
    ZEROAUTH_CLIENT_ID: 'test-client-id',
    ZEROAUTH_CLIENT_SECRET: 'test-client-secret',
    ZEROAUTH_ISSUER: 'https://zeroauth.example',
    ZEROAUTH_KID: 'test-kid',
    ZEROAUTH_PRIVATE_JWK: JSON.stringify(privateJwk),
    ZEROAUTH_TOKEN_TTL_SECONDS: '3600',
    ...overrides,
  };
}

export function basicAuthHeader(clientId: string, clientSecret: string): string {
  return `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
}

export function parseLocation(url: string): URL {
  return new URL(url);
}

export function mergeCookies(current: string, response: Response): string {
  const jar = new Map(current.split(';').filter(Boolean).map((part) => {
    const [name, ...value] = part.trim().split('=');
    return [name, value.join('=')];
  }));
  for (const value of response.headers.getSetCookie()) {
    const [name, ...contents] = value.split(';')[0].split('=');
    jar.set(name, contents.join('='));
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
}

export async function loginForm(response: Response): Promise<URLSearchParams> {
  const html = await response.text();
  const transaction = html.match(/name="transaction" value="([^"]+)"/)?.[1];
  if (!transaction) throw new Error('Response does not contain a login transaction');
  return new URLSearchParams({ transaction, action: 'login' });
}

export async function submitLogin(
  env: Env, form: URLSearchParams, cookies: string, origin = 'https://zeroauth.example',
): Promise<Response> {
  return handleRequest(new Request('https://zeroauth.example/authorize', {
    method: 'POST', body: form,
    headers: { Cookie: cookies, Origin: origin },
  }), env);
}

export async function completePasswordLogin(response: Response, env: Env): Promise<Response> {
  if (response.status !== 200) return response;
  const form = await loginForm(response.clone());
  form.set('password', env.ZEROAUTH_PASSWORD);
  return submitLogin(env, form, mergeCookies('', response));
}

export function codeWriteCount(env: Env): number {
  return (env.ZEROAUTH_CODES as unknown as MockKVNamespace).writes.length;
}
