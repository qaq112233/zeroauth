import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeJwt } from 'jose';

import { handleRequest } from '../src/app.ts';
import { basicAuthHeader, completePasswordLogin, createTestEnv, parseLocation } from './test-utils.ts';

async function authorize(env: Awaited<ReturnType<typeof createTestEnv>>, query: string): Promise<Response> {
  const response = await handleRequest(new Request(`https://zeroauth.example/authorize?${query}`), env);
  return completePasswordLogin(response, env);
}

async function tokenRequest(
  env: Awaited<ReturnType<typeof createTestEnv>>,
  body: URLSearchParams,
  extraHeaders?: HeadersInit,
): Promise<Response> {
  return handleRequest(
    new Request('https://zeroauth.example/token', {
      body: body.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...extraHeaders,
      },
      method: 'POST',
    }),
    env,
  );
}

test('serves an OpenID discovery document', async () => {
  const env = await createTestEnv();
  const response = await handleRequest(
    new Request('https://zeroauth.example/.well-known/openid-configuration'),
    env,
  );

  assert.equal(response.status, 200);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.issuer, 'https://zeroauth.example');
  assert.equal(payload.authorization_endpoint, 'https://zeroauth.example/authorize');
  assert.deepEqual(payload.response_types_supported, ['code']);
  assert.deepEqual(payload.token_endpoint_auth_methods_supported, [
    'client_secret_basic',
    'client_secret_post',
  ]);
});

test('preserves an explicitly configured issuer string exactly', async () => {
  const env = await createTestEnv({
    ZEROAUTH_ISSUER: 'https://zeroauth.example.workers.dev/',
  });
  const response = await handleRequest(
    new Request('https://zeroauth.example.workers.dev/.well-known/openid-configuration'),
    env,
  );

  assert.equal(response.status, 200);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.issuer, 'https://zeroauth.example.workers.dev/');
});

test('serves a JWKS document with the configured kid', async () => {
  const env = await createTestEnv();
  const response = await handleRequest(new Request('https://zeroauth.example/jwks.json'), env);

  assert.equal(response.status, 200);
  const payload = (await response.json()) as { keys: Array<Record<string, unknown>> };
  assert.equal(payload.keys.length, 1);
  assert.equal(payload.keys[0]?.kid, 'test-kid');
});

test('authorize requires login_hint', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email profile',
      state: 'state-1',
    }).toString(),
  );

  assert.equal(response.status, 302);
  const location = parseLocation(response.headers.get('location')!);
  assert.equal(location.searchParams.get('error'), 'invalid_request');
  assert.equal(location.searchParams.get('state'), 'state-1');
});

test('authorize rejects an invalid login_hint email', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'not-an-email',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  assert.equal(response.status, 302);
  const location = parseLocation(response.headers.get('location')!);
  assert.equal(location.searchParams.get('error'), 'invalid_request');
});

test('authorize rejects a redirect_uri outside the allowlist', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://evil.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  assert.equal(response.status, 400);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_request');
});

test('authorize rejects unsupported response_type', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'token',
      scope: 'openid email',
      state: 's-1',
    }).toString(),
  );

  assert.equal(response.status, 302);
  const location = parseLocation(response.headers.get('location')!);
  assert.equal(location.searchParams.get('error'), 'unsupported_response_type');
  assert.equal(location.searchParams.get('state'), 's-1');
});

test('authorize creates a code and preserves state', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'User@Example.com',
      nonce: 'nonce-1',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email profile',
      state: 'state-xyz',
    }).toString(),
  );

  assert.equal(response.status, 302);
  const location = parseLocation(response.headers.get('location')!);
  assert.ok(location.searchParams.get('code'));
  assert.equal(location.searchParams.get('state'), 'state-xyz');
});

test('token endpoint exchanges an authorization code for tokens', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'User@Example.com',
      nonce: 'nonce-123',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email profile',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const response = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(response.status, 200);
  const payload = (await response.json()) as Record<string, string | number>;
  assert.equal(payload.token_type, 'Bearer');
  assert.equal(payload.expires_in, 3600);

  const idToken = decodeJwt(payload.id_token as string);
  assert.equal(idToken.email, 'user@example.com');
  assert.equal(idToken.email_verified, true);
  assert.equal(idToken.nonce, 'nonce-123');
  assert.equal(idToken.aud, env.ZEROAUTH_CLIENT_ID);

  const accessToken = decodeJwt(payload.access_token as string);
  assert.equal(accessToken.email, 'user@example.com');
  assert.equal(accessToken.scope, 'openid email profile');
});

test('token endpoint supports client_secret_post', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const response = await tokenRequest(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      client_secret: env.ZEROAUTH_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
  );

  assert.equal(response.status, 200);
});

test('token endpoint rejects an invalid client secret', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const response = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, 'wrong-secret'),
    },
  );

  assert.equal(response.status, 401);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_client');
});

test('token endpoint rejects a reused authorization code', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const body = new URLSearchParams({
    code,
    grant_type: 'authorization_code',
    redirect_uri: 'https://client.example/callback',
  });

  const headers = {
    Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
  };

  const first = await tokenRequest(env, body, headers);
  assert.equal(first.status, 200);

  const second = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    headers,
  );

  assert.equal(second.status, 400);
  const payload = (await second.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_grant');
});

test('token endpoint rejects an expired authorization code', async () => {
  const env = await createTestEnv({
    ZEROAUTH_AUTH_CODE_TTL_SECONDS: '0',
  });
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const response = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(response.status, 400);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_grant');
});

test('token endpoint validates PKCE S256 verifiers', async () => {
  const env = await createTestEnv();
  const verifier = 'pkce-verifier-123';
  const hashedBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hashedBuffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const failure = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      code_verifier: 'wrong-verifier',
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(failure.status, 400);
  assert.equal(((await failure.json()) as Record<string, unknown>).error, 'invalid_grant');

  const authorizeAgain = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code2 = parseLocation(authorizeAgain.headers.get('location')!).searchParams.get('code');
  assert.ok(code2);

  const success = await tokenRequest(
    env,
    new URLSearchParams({
      code: code2,
      code_verifier: verifier,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(success.status, 200);
});

test('userinfo validates and returns claims from the access token', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email profile',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const tokenResponse = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  const tokenPayload = (await tokenResponse.json()) as Record<string, string>;
  const response = await handleRequest(
    new Request('https://zeroauth.example/userinfo', {
      headers: {
        Authorization: `Bearer ${tokenPayload.access_token}`,
      },
    }),
    env,
  );

  assert.equal(response.status, 200);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.email, 'user@example.com');
  assert.equal(payload.email_verified, true);
  assert.ok(typeof payload.sub === 'string');
});

test('authorize is blocked when the shared password is missing', async () => {
  const env = await createTestEnv({
    ZEROAUTH_PASSWORD: '',
  });

  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  assert.equal(response.status, 500);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'server_error');
  assert.match(String(payload.error_description), /ZEROAUTH_PASSWORD is required/);
});

test('template placeholder configuration returns a clear error', async () => {
  const env = await createTestEnv({
    ZEROAUTH_PRIVATE_JWK:
      '{"kty":"EC","crv":"P-256","x":"replace-me","y":"replace-me","d":"replace-me","alg":"ES256","use":"sig"}',
  });

  const response = await handleRequest(
    new Request('https://zeroauth.example/.well-known/openid-configuration'),
    env,
  );

  assert.equal(response.status, 500);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'server_error');
  assert.match(
    String(payload.error_description),
    /ZEROAUTH_PRIVATE_JWK is still using the template placeholder/,
  );
});
