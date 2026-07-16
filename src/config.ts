import type { JSONWebKeySet } from 'jose';

export interface IdentityConfig {
  port: number;
  issuer: string;
  jwks: JSONWebKeySet;
  cookieKeys: string[];
  resourceAudiences: string[];
  secureCookies: boolean;
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function json<T>(name: string, value: string): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new Error(`${name} must be valid JSON`);
  }
}

export function getIdentityConfig(): IdentityConfig {
  const issuer = required('IDENTITY_ISSUER').replace(/\/$/, '');
  const issuerUrl = new URL(issuer);
  if (process.env.NODE_ENV === 'production' && issuerUrl.protocol !== 'https:') {
    throw new Error('IDENTITY_ISSUER must use HTTPS in production');
  }
  const jwks = json<JSONWebKeySet>('IDENTITY_JWKS_JSON', required('IDENTITY_JWKS_JSON'));
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new Error('IDENTITY_JWKS_JSON must contain at least one private signing key');
  }
  if (jwks.keys.some((key) => key.kty !== 'RSA' || key.alg !== 'PS256' || typeof key.kid !== 'string' || typeof key.d !== 'string')) {
    throw new Error('IDENTITY_JWKS_JSON keys must be private RSA PS256 signing keys with kid');
  }
  const cookieKeys = required('IDENTITY_COOKIE_KEYS').split(',').map((value) => value.trim()).filter(Boolean);
  if (cookieKeys.length < 2 || cookieKeys.some((value) => value.length < 32)) {
    throw new Error('IDENTITY_COOKIE_KEYS must contain at least two keys of 32 characters');
  }
  return {
    port: Number(process.env.PORT || 3020),
    issuer,
    jwks,
    cookieKeys,
    resourceAudiences: (process.env.IDENTITY_RESOURCE_AUDIENCES ||
      'urn:mavula:identity-access,urn:mavula:ledger-core,urn:mavula:workbench')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean),
    secureCookies: issuer.startsWith('https://'),
  };
}
