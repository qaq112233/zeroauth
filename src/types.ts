export interface Env {
  ZEROAUTH_CODES: KVNamespace;
  ZEROAUTH_CLIENT_ID: string;
  ZEROAUTH_CLIENT_SECRET: string;
  ZEROAUTH_PASSWORD: string;
  ZEROAUTH_ALLOWED_EMAIL_DOMAINS: string;
  ZEROAUTH_ALLOWED_REDIRECT_URIS?: string;
  ZEROAUTH_PRIVATE_JWK: string;
  ZEROAUTH_KID: string;
  ZEROAUTH_ISSUER?: string;
  ZEROAUTH_AUTH_CODE_TTL_SECONDS?: string;
  ZEROAUTH_TOKEN_TTL_SECONDS?: string;
}

export interface RuntimeConfig {
  clientId: string;
  clientSecret: string;
  password: string;
  allowedEmailDomains: Set<string>;
  issuer: string;
  origin: string;
  authCodeTtlSeconds: number;
  tokenTtlSeconds: number;
  allowedRedirectUris: Set<string>;
  privateJwk: Record<string, unknown>;
  kid: string;
}

export interface AuthorizationCodeRecord {
  authTime: number;
  clientId: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'plain' | 'S256';
  email: string;
  nonce?: string;
  redirectUri: string;
  scope: string;
}

export interface SigningContext {
  alg: string;
  kid: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: Record<string, unknown>;
}
