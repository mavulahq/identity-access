import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPair, exportJWK } from 'jose';
import { getIdentityConfig } from '../src/config.js';

test('identity configuration requires explicit issuer, keys and rotating cookie keys', async () => {
  const previous = { ...process.env };
  try {
    const { privateKey } = await generateKeyPair('PS256', { modulusLength: 2048, extractable: true });
    const key = await exportJWK(privateKey);
    process.env.IDENTITY_ISSUER = 'https://identity.mavula.io/';
    process.env.IDENTITY_JWKS_JSON = JSON.stringify({ keys: [{ ...key, kid: 'test', alg: 'PS256', use: 'sig' }] });
    process.env.IDENTITY_COOKIE_KEYS = `${'a'.repeat(32)},${'b'.repeat(32)}`;
    const config = getIdentityConfig();
    assert.equal(config.issuer, 'https://identity.mavula.io');
    assert.equal(config.secureCookies, true);
    assert.equal(config.jwks.keys.length, 1);
  } finally {
    process.env = previous;
  }
});

test('identity configuration rejects placeholder-equivalent missing secrets', () => {
  const previous = { ...process.env };
  try {
    delete process.env.IDENTITY_ISSUER;
    delete process.env.IDENTITY_JWKS_JSON;
    delete process.env.IDENTITY_COOKIE_KEYS;
    assert.throws(() => getIdentityConfig(), /IDENTITY_ISSUER is required/);
  } finally {
    process.env = previous;
  }
});

test('identity configuration rejects a public-only signing key', async () => {
  const previous = { ...process.env };
  try {
    const { publicKey } = await generateKeyPair('PS256', { modulusLength: 2048, extractable: true });
    const key = await exportJWK(publicKey);
    process.env.IDENTITY_ISSUER = 'https://identity.mavula.io';
    process.env.IDENTITY_JWKS_JSON = JSON.stringify({ keys: [{ ...key, kid: 'public-only', alg: 'PS256' }] });
    process.env.IDENTITY_COOKIE_KEYS = `${'a'.repeat(32)},${'b'.repeat(32)}`;
    assert.throws(() => getIdentityConfig(), /private RSA PS256/);
  } finally {
    process.env = previous;
  }
});
