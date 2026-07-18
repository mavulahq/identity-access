import assert from 'node:assert/strict';
import test from 'node:test';
import { assertClientCredentialsSecurity } from '../src/bootstrap.js';

const publicJwks = {
  keys: [{ kty: 'RSA', alg: 'PS256', use: 'sig', kid: 'service-key', n: 'modulus', e: 'AQAB' }],
};

test('client_credentials requires private_key_jwt and public JWKS', () => {
  assert.throws(() => assertClientCredentialsSecurity(
    'service-client', ['client_credentials'], 'none', publicJwks,
  ), /private_key_jwt/);
  assert.throws(() => assertClientCredentialsSecurity(
    'service-client', ['client_credentials'], 'private_key_jwt', {
      keys: [{ ...publicJwks.keys[0], d: 'private-material' }],
    },
  ), /public RSA PS256/);
  assert.doesNotThrow(() => assertClientCredentialsSecurity(
    'service-client', ['client_credentials'], 'private_key_jwt', publicJwks,
  ));
});
