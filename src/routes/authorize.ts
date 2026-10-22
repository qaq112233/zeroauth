import { createAuthorizationCode } from '../code-store.ts';
import { OAuthError } from '../errors.ts';
import {
  browserBinding, cookie, createLoginTransaction, createSession, passwordMatches,
  readLoginTransaction, SESSION_COOKIE, SESSION_TTL_SECONDS, sessionAuthTime,
} from '../auth.ts';
import { loginPage } from '../login-page.ts';
import type { AuthorizationCodeRecord, Env, RuntimeConfig } from '../types.ts';
import {
  appendQueryParameters,
  includesOpenIdScope,
  isValidEmail,
  normalizeEmail,
  normalizeScope,
  noStoreHeaders,
} from '../utils.ts';

function redirectError(
  redirectUri: string,
  state: string | undefined,
  error: string,
  description: string,
): never {
  throw new OAuthError({
    description,
    error,
    redirectUri,
    state,
    status: 302,
  });
}

function validateAuthorizationParameters(
  parameters: URLSearchParams,
  config: RuntimeConfig,
): Omit<AuthorizationCodeRecord, 'authTime'> & { state?: string } {
  // Reject ambiguous requests before selecting either a redirect or an identity.
  for (const name of new Set(parameters.keys())) {
    if (parameters.getAll(name).length !== 1) {
      throw new OAuthError({ error: 'invalid_request', description: 'Duplicate authorization parameter', status: 400 });
    }
  }
  const clientId = parameters.get('client_id');
  const redirectUri = parameters.get('redirect_uri');
  const responseType = parameters.get('response_type');
  const scope = parameters.get('scope');
  const state = parameters.get('state') ?? undefined;
  const nonce = parameters.get('nonce') ?? undefined;
  const loginHint = parameters.get('login_hint');
  const codeChallenge = parameters.get('code_challenge') ?? undefined;
  const codeChallengeMethod = parameters.get('code_challenge_method') ?? undefined;

  if (clientId !== config.clientId) {
    throw new OAuthError({
      description: 'Unknown client_id',
      error: 'invalid_request',
      status: 400,
    });
  }

  if (!redirectUri || !config.allowedRedirectUris.has(redirectUri)) {
    throw new OAuthError({
      description: 'redirect_uri is not allowed',
      error: 'invalid_request',
      status: 400,
    });
  }

  if (responseType !== 'code') {
    redirectError(redirectUri, state, 'unsupported_response_type', 'Only response_type=code is supported');
  }

  if (!scope || !includesOpenIdScope(scope)) {
    redirectError(redirectUri, state, 'invalid_scope', 'scope must include openid');
  }

  if (!loginHint) {
    redirectError(redirectUri, state, 'invalid_request', 'login_hint is required');
  }

  const email = normalizeEmail(loginHint);

  if (!isValidEmail(email)) {
    redirectError(redirectUri, state, 'invalid_request', 'login_hint must be a valid email address');
  }

  if (!config.allowedEmailDomains.has(email.slice(email.lastIndexOf('@') + 1))) {
    redirectError(redirectUri, state, 'access_denied', 'The login_hint email domain is not allowed');
  }

  const prompt = parameters.get('prompt')?.split(/\s+/).filter(Boolean) ?? [];
  if (prompt.some((value) => !['none', 'login', 'consent', 'select_account'].includes(value)) ||
      (prompt.includes('none') && prompt.length > 1)) {
    redirectError(redirectUri, state, 'invalid_request', 'Invalid prompt parameter');
  }
  const maxAge = parameters.get('max_age');
  if (maxAge !== null && (!/^\d+$/.test(maxAge) || !Number.isSafeInteger(Number(maxAge)))) {
    redirectError(redirectUri, state, 'invalid_request', 'max_age must be a non-negative integer');
  }

  let normalizedCodeChallengeMethod: 'plain' | 'S256' | undefined;
  if (codeChallenge) {
    normalizedCodeChallengeMethod =
      codeChallengeMethod === 'S256' || codeChallengeMethod === 'plain'
        ? codeChallengeMethod
        : codeChallengeMethod === undefined
          ? 'plain'
          : undefined;

    if (!normalizedCodeChallengeMethod) {
      redirectError(
        redirectUri,
        state,
        'invalid_request',
        'code_challenge_method must be plain or S256',
      );
    }
  } else if (codeChallengeMethod) {
    redirectError(
      redirectUri,
      state,
      'invalid_request',
      'code_challenge_method requires code_challenge',
    );
  }

  return {
    clientId: config.clientId, codeChallenge, codeChallengeMethod: normalizedCodeChallengeMethod,
    email, nonce, redirectUri, scope: normalizeScope(scope), state,
  };
}

function requiresPassword(parameters: URLSearchParams, authTime: number | null): boolean {
  if (authTime === null || parameters.get('prompt')?.split(/\s+/).includes('login')) return true;
  const maxAge = parameters.get('max_age');
  return maxAge !== null && (Number(maxAge) === 0 || Math.floor(Date.now() / 1000) - authTime > Number(maxAge));
}

function invalidForm(description: string): never {
  throw new OAuthError({ description, error: 'invalid_request', status: 400 });
}

export async function handleAuthorize(
  request: Request, env: Env, config: RuntimeConfig,
): Promise<Response> {
  if (request.method === 'GET') {
    const parameters = new URL(request.url).searchParams;
    if (parameters.toString().length > 4096) invalidForm('Authorization request too large');
    const authorization = validateAuthorizationParameters(parameters, config);
    const authTime = await sessionAuthTime(request, config);
    // Confirmation is always interactive, even with a valid remembered browser.
    if (parameters.get('prompt')?.split(/\s+/).includes('none')) {
      redirectError(authorization.redirectUri, authorization.state,
        authTime === null ? 'login_required' : 'interaction_required', 'Interactive login confirmation is required');
    }
    const binding = browserBinding(request);
    return loginPage({
      email: authorization.email, binding, redirectUri: authorization.redirectUri,
      transaction: await createLoginTransaction(config, parameters, binding),
      remembered: !requiresPassword(parameters, authTime),
    });
  }

  // SameSite cookies alone are insufficient for CSRF protection. Require both
  // a same-origin form POST and a signed transaction bound to this browser.
  if (request.headers.get('Origin') !== config.origin) invalidForm('Invalid form origin');
  if (request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !==
      'application/x-www-form-urlencoded') invalidForm('Expected a URL-encoded form');
  const body = await request.text();
  if (body.length > 24_576) invalidForm('Login form too large');
  const form = new URLSearchParams(body);
  if (['transaction', 'password', 'action'].some((name) => form.getAll(name).length > 1)) {
    invalidForm('Duplicate login form field');
  }
  const transaction = form.get('transaction');
  if (!transaction) invalidForm('Missing login transaction');
  const parameters = await readLoginTransaction(request, transaction, config);
  if (!parameters) invalidForm('Login form is invalid or expired. Start again from Google.');
  // Revalidate the signed values against current client, redirect and domain policy.
  const authorization = validateAuthorizationParameters(parameters, config);
  if (parameters.get('prompt')?.split(/\s+/).includes('none')) invalidForm('Interactive login confirmation is required');
  const binding = browserBinding(request);
  const authTime = await sessionAuthTime(request, config);

  if (form.get('action') === 'forget') {
    const response = loginPage({
      email: authorization.email, redirectUri: authorization.redirectUri, binding, transaction, remembered: false,
    });
    response.headers.append('Set-Cookie', cookie(SESSION_COOKIE, '', 0));
    return response;
  }
  if (form.get('action') !== 'login') invalidForm('Invalid login action');

  let authenticatedAt = authTime;
  let session: string | undefined;
  if (requiresPassword(parameters, authTime)) {
    const password = form.get('password') ?? '';
    if (!await passwordMatches(password, config)) {
      return loginPage({
        email: authorization.email, redirectUri: authorization.redirectUri, binding, transaction, remembered: false,
        error: '密码错误，请重试。', status: 401,
      });
    }
    authenticatedAt = Math.floor(Date.now() / 1000);
    session = await createSession(config, authenticatedAt);
  }

  // This is the only authorization-code issuance path: after password validation
  // or an authenticated browser's explicit POST confirmation.
  const { state, ...record } = authorization;
  const code = await createAuthorizationCode(
    env.ZEROAUTH_CODES,
    { ...record, authTime: authenticatedAt! },
    config.authCodeTtlSeconds,
  );
  const headers = noStoreHeaders({
    Location: appendQueryParameters(authorization.redirectUri, { code, state }),
    'Referrer-Policy': 'no-referrer',
  });
  if (session) headers.append('Set-Cookie', cookie(SESSION_COOKIE, session, SESSION_TTL_SECONDS));
  return new Response(null, { headers, status: 302 });
}
