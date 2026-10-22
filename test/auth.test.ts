import assert from 'node:assert/strict';
import test from 'node:test';
import { createLocalJWKSet, jwtVerify } from 'jose';

import { handleRequest } from '../src/app.ts';
import { BROWSER_COOKIE, SESSION_COOKIE, SESSION_TTL_SECONDS } from '../src/auth.ts';
import { hashSubject } from '../src/jwt.ts';
import type { Env } from '../src/types.ts';
import {
  basicAuthHeader, codeWriteCount, createTestEnv, loginForm, mergeCookies, submitLogin,
} from './test-utils.ts';

function query(env: Env, overrides: Record<string, string> = {}): URLSearchParams {
  return new URLSearchParams({
    client_id: env.ZEROAUTH_CLIENT_ID, redirect_uri: 'https://client.example/callback',
    response_type: 'code', scope: 'openid email profile', login_hint: 'user01@example.com',
    state: 'test-state', nonce: 'test-nonce', ...overrides,
  });
}

async function start(env: Env, cookies = '', overrides: Record<string, string> = {}) {
  return handleRequest(new Request(`https://zeroauth.example/authorize?${query(env, overrides)}`, {
    headers: { Cookie: cookies },
  }), env);
}

async function authenticate(env: Env) {
  const page = await start(env);
  const form = await loginForm(page.clone());
  form.set('password', env.ZEROAUTH_PASSWORD);
  const result = await submitLogin(env, form, mergeCookies('', page));
  assert.equal(result.status, 302);
  return { result, cookies: mergeCookies(mergeCookies('', page), result) };
}

async function exchange(env: Env, response: Response) {
  const location = new URL(response.headers.get('Location')!);
  assert.equal(location.searchParams.get('state'), 'test-state');
  const code = location.searchParams.get('code');
  assert.ok(code);
  const tokenResponse = await handleRequest(new Request('https://zeroauth.example/token', {
    method: 'POST', headers: { Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET) },
    body: new URLSearchParams({ code, grant_type: 'authorization_code', redirect_uri: 'https://client.example/callback' }),
  }), env);
  assert.equal(tokenResponse.status, 200);
  const tokens = await tokenResponse.json() as { id_token: string; access_token: string };
  const jwksResponse = await handleRequest(new Request('https://zeroauth.example/jwks.json'), env);
  const jwks = await jwksResponse.json() as Parameters<typeof createLocalJWKSet>[0];
  const { payload, protectedHeader } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), {
    issuer: env.ZEROAUTH_ISSUER, audience: env.ZEROAUTH_CLIENT_ID, algorithms: ['RS256'],
  });
  assert.equal(protectedHeader.alg, 'RS256');
  assert.equal(payload.nonce, 'test-nonce');
  return payload;
}

test('GET authorize shows an accessible password form and never issues a code', async () => {
  const env = await createTestEnv();
  const page = await start(env);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('Location'), null);
  assert.equal(page.headers.get('Cache-Control'), 'no-store');
  assert.equal(page.headers.get('Referrer-Policy'), 'same-origin');
  assert.match(page.headers.get('Content-Security-Policy')!, /frame-ancestors 'none'/);
  assert.match(page.headers.get('Content-Security-Policy')!, /form-action 'self' https:\/\/client\.example;/);
  const html = await page.text();
  assert.match(html, /ZeroAuth/);
  assert.match(html, /user01@example.com/);
  assert.match(html, /type="password" autocomplete="current-password"/);
  assert.match(html, /autocomplete="username"/);
  assert.ok(!html.includes(env.ZEROAUTH_PASSWORD));
  assert.ok(!html.includes(env.ZEROAUTH_CLIENT_SECRET));
  assert.equal(codeWriteCount(env), 0);
});

test('correct password issues a code and a protected 30-day browser cookie', async () => {
  const env = await createTestEnv();
  const { result } = await authenticate(env);
  const session = result.headers.getSetCookie().find((value) => value.startsWith(`${SESSION_COOKIE}=`));
  assert.ok(session);
  assert.match(session, /Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000/);
  assert.equal(result.headers.get('Cache-Control'), 'no-store');
  assert.ok(!session.includes(env.ZEROAUTH_PASSWORD));
  assert.equal(codeWriteCount(env), 1);
  const payload = await exchange(env, result);
  assert.equal(payload.email, 'user01@example.com');
  assert.equal(payload.sub, await hashSubject('user01@example.com'));
});

test('incorrect password shows an error, permits retry, and never creates a session or code', async () => {
  const env = await createTestEnv();
  const page = await start(env);
  const cookies = mergeCookies('', page);
  const form = await loginForm(page.clone());
  form.set('password', 'incorrect-password');
  const failure = await submitLogin(env, form, cookies);
  assert.equal(failure.status, 401);
  assert.equal(failure.headers.get('Location'), null);
  const html = await failure.clone().text();
  assert.match(html, /密码错误/);
  assert.ok(!html.includes('incorrect-password'));
  assert.ok(!failure.headers.getSetCookie().some((value) => value.startsWith(`${SESSION_COOKIE}=`)));
  assert.equal(codeWriteCount(env), 0);
  const retry = await loginForm(failure);
  retry.set('password', env.ZEROAUTH_PASSWORD);
  assert.equal((await submitLogin(env, retry, cookies)).status, 302);
});

test('GET and a crafted confirmation POST cannot skip the password, even with the old flag', async () => {
  const env = await createTestEnv();
  Object.assign(env, { ZEROAUTH_ALLOW_ANY_LOGIN_HINT: 'true' });
  const page = await start(env);
  assert.equal(page.status, 200);
  const form = await loginForm(page.clone());
  const response = await submitLogin(env, form, mergeCookies('', page));
  assert.equal(response.status, 401);
  assert.equal(codeWriteCount(env), 0);
  const direct = await submitLogin(env, new URLSearchParams({
    ...Object.fromEntries(query(env)), password: env.ZEROAUTH_PASSWORD, action: 'login',
  }), '');
  assert.equal(direct.status, 400);
  assert.equal(codeWriteCount(env), 0);
});

test('the same shared password signs in different Google emails with distinct email-derived subjects', async () => {
  const env = await createTestEnv();
  const first = await authenticate(env);
  const firstClaims = await exchange(env, first.result);
  const page = await start(env, '', { login_hint: 'User02@Second.Example' });
  const form = await loginForm(page.clone());
  form.set('password', env.ZEROAUTH_PASSWORD);
  const response = await submitLogin(env, form, mergeCookies('', page));
  const claims = await exchange(env, response);
  assert.equal(claims.email, 'user02@second.example');
  assert.equal(claims.sub, await hashSubject('user02@second.example'));
  assert.notEqual(claims.sub, firstClaims.sub);
});

test('remembered browser requires explicit confirmation and uses this request email, not the previous one', async () => {
  const env = await createTestEnv();
  const { result, cookies } = await authenticate(env);
  const initialClaims = await exchange(env, result);
  const page = await start(env, cookies, { login_hint: 'user02@second.example' });
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('Location'), null);
  const html = await page.clone().text();
  assert.match(html, /user02@second.example/);
  assert.match(html, /确认登录/);
  assert.ok(!html.includes('type="password"'));
  assert.equal(codeWriteCount(env), 1);
  const form = await loginForm(page);
  // Unsigned extra identity fields must not change the signed request.
  form.set('login_hint', 'attacker@example.com');
  form.set('redirect_uri', 'https://evil.example');
  const response = await submitLogin(env, form, cookies);
  assert.equal(response.status, 302);
  assert.ok(!response.headers.getSetCookie().some((value) => value.startsWith(`${SESSION_COOKIE}=`)));
  const claims = await exchange(env, response);
  assert.equal(claims.email, 'user02@second.example');
  assert.equal(claims.auth_time, initialClaims.auth_time);
});

test('a tampered transaction, missing browser binding, or cross-origin submission is rejected', async () => {
  const env = await createTestEnv();
  const page = await start(env);
  const original = await loginForm(page.clone());
  original.set('password', env.ZEROAUTH_PASSWORD);
  const cookies = mergeCookies('', page);
  const tampered = new URLSearchParams(original);
  const parts = tampered.get('transaction')!.split('.');
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  claims.parameters = query(env, { login_hint: 'attacker@example.com' }).toString();
  parts[1] = Buffer.from(JSON.stringify(claims)).toString('base64url');
  tampered.set('transaction', parts.join('.'));
  for (const [form, binding, origin] of [
    [tampered, cookies, 'https://zeroauth.example'],
    [original, '', 'https://zeroauth.example'],
    [original, `${BROWSER_COOKIE}=${'a'.repeat(43)}`, 'https://zeroauth.example'],
    [original, cookies, 'https://evil.example'],
    [original, cookies, 'null'],
  ] as const) {
    assert.equal((await submitLogin(env, form, binding, origin)).status, 400);
  }
  assert.equal(codeWriteCount(env), 0);
});

test('session tokens cannot be substituted for login transactions and vice versa', async () => {
  const env = await createTestEnv();
  const { cookies } = await authenticate(env);
  const page = await start(env, cookies);
  const form = await loginForm(page.clone());
  const transaction = form.get('transaction')!;
  const session = cookies.split('; ').find((value) => value.startsWith(`${SESSION_COOKIE}=`))!.slice(SESSION_COOKIE.length + 1);
  form.set('transaction', session);
  assert.equal((await submitLogin(env, form, cookies)).status, 400);
  const forgedCookie = `${SESSION_COOKIE}=${transaction}`;
  assert.match(await (await start(env, forgedCookie)).text(), /type="password"/);
});

test('tampered and expired browser sessions require the password again', async (t) => {
  const env = await createTestEnv();
  const { cookies } = await authenticate(env);
  const forged = cookies.replace(`${SESSION_COOKIE}=`, `${SESSION_COOKIE}=x`);
  assert.match(await (await start(env, forged)).text(), /type="password"/);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  t.mock.timers.tick((SESSION_TTL_SECONDS + 1) * 1000);
  assert.match(await (await start(env, cookies)).text(), /type="password"/);
});

test('expired login transactions and sessions expiring between GET and POST cannot bypass authentication', async (t) => {
  const env = await createTestEnv();
  const { cookies } = await authenticate(env);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  t.mock.timers.tick((SESSION_TTL_SECONDS - 5) * 1000);
  const confirmation = await start(env, cookies);
  const confirmationForm = await loginForm(confirmation);
  t.mock.timers.tick(6000);
  assert.equal((await submitLogin(env, confirmationForm, cookies)).status, 401);
  t.mock.timers.reset();

  const page = await start(env);
  const form = await loginForm(page.clone());
  form.set('password', env.ZEROAUTH_PASSWORD);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  t.mock.timers.tick(601_000);
  assert.equal((await submitLogin(env, form, mergeCookies('', page))).status, 400);
  assert.equal(codeWriteCount(env), 1);
});

test('password rotation invalidates old sessions and pending forms', async () => {
  const env = await createTestEnv();
  const { cookies } = await authenticate(env);
  const pending = await start(env, cookies);
  const oldForm = await loginForm(pending);
  env.ZEROAUTH_PASSWORD = 'new-shared-password';
  const page = await start(env, cookies);
  assert.match(await page.clone().text(), /type="password"/);
  assert.equal((await submitLogin(env, oldForm, cookies)).status, 400);
  const form = await loginForm(page.clone());
  form.set('password', 'test-shared-password');
  assert.equal((await submitLogin(env, form, cookies)).status, 401);
  form.set('password', env.ZEROAUTH_PASSWORD);
  assert.equal((await submitLogin(env, form, cookies)).status, 302);
});

test('domain allowlist uses exact domains and is enforced again when a form is submitted', async () => {
  const env = await createTestEnv({ ZEROAUTH_ALLOWED_EMAIL_DOMAINS: ' Example.COM , second.example ' });
  for (const email of ['user@evil.example', 'user@sub.example.com', 'user@example.com.evil.test']) {
    const response = await start(env, '', { login_hint: email });
    assert.equal(response.status, 302);
    assert.equal(new URL(response.headers.get('Location')!).searchParams.get('error'), 'access_denied');
  }
  const page = await start(env);
  const form = await loginForm(page.clone());
  form.set('password', env.ZEROAUTH_PASSWORD);
  env.ZEROAUTH_ALLOWED_EMAIL_DOMAINS = 'second.example';
  const response = await submitLogin(env, form, mergeCookies('', page));
  assert.equal(new URL(response.headers.get('Location')!).searchParams.get('error'), 'access_denied');
  assert.equal(codeWriteCount(env), 0);
});

test('missing password, missing domains and malformed domain lists fail closed', async () => {
  for (const overrides of [
    { ZEROAUTH_PASSWORD: '' }, { ZEROAUTH_ALLOWED_EMAIL_DOMAINS: '' },
    { ZEROAUTH_ALLOWED_EMAIL_DOMAINS: '*.example.com' },
    { ZEROAUTH_ALLOWED_EMAIL_DOMAINS: 'https://example.com' },
  ]) {
    const env = await createTestEnv(overrides);
    const page = await start(env);
    assert.equal(page.status, 500);
    assert.equal(codeWriteCount(env), 0);
  }
});

test('prompt=login and max_age=0 require a fresh password even with a valid session', async () => {
  const env = await createTestEnv();
  const { cookies } = await authenticate(env);
  for (const overrides of [{ prompt: 'login' }, { max_age: '0' }] as Record<string, string>[]) {
    const page = await start(env, cookies, overrides);
    assert.match(await page.clone().text(), /type="password"/);
    const form = await loginForm(page);
    assert.equal((await submitLogin(env, form, cookies)).status, 401);
    form.set('password', env.ZEROAUTH_PASSWORD);
    assert.equal((await submitLogin(env, form, cookies)).status, 302);
  }
});

test('silent authentication never skips confirmation; malformed OAuth parameters are rejected', async () => {
  const env = await createTestEnv();
  const { cookies } = await authenticate(env);
  for (const current of ['', cookies]) {
    const page = await start(env, current, { prompt: 'none' });
    const error = new URL(page.headers.get('Location')!).searchParams.get('error');
    assert.equal(error, current ? 'interaction_required' : 'login_required');
  }
  for (const overrides of [{ max_age: '-1' }, { prompt: 'none login' }, { code_challenge_method: 'S256' }] as Record<string, string>[]) {
    const page = await start(env, '', overrides);
    assert.equal(new URL(page.headers.get('Location')!).searchParams.get('error'), 'invalid_request');
  }
  const page = await handleRequest(new Request(`https://zeroauth.example/authorize?${query(env)}&login_hint=other@example.com`), env);
  assert.equal(page.status, 400);
  assert.equal(codeWriteCount(env), 1);
});

test('forget browser clears the session and returns to the password form', async () => {
  const env = await createTestEnv();
  const { cookies } = await authenticate(env);
  const page = await start(env, cookies);
  const form = await loginForm(page);
  form.set('action', 'forget');
  const response = await submitLogin(env, form, cookies);
  assert.equal(response.status, 200);
  assert.match(await response.clone().text(), /type="password"/);
  assert.ok(response.headers.getSetCookie().some((value) => value.startsWith(`${SESSION_COOKIE}=;`) && value.includes('Max-Age=0')));
  const afterForget = mergeCookies(cookies, response);
  assert.match(await (await start(env, afterForget)).text(), /type="password"/);
  assert.equal(codeWriteCount(env), 1);
});

test('login page escapes the email as text and attributes', async () => {
  const env = await createTestEnv();
  const response = await start(env, '', { login_hint: '<img/src=x/onerror=alert(1)>@example.com' });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.ok(!html.includes('<img/src='));
  assert.match(html, /&lt;img\/src=x\/onerror=alert\(1\)&gt;@example.com/);
});
