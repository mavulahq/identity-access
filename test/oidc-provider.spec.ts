import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createOidcProvider } from '../src/oidc.provider.js';

test('publishes OIDC discovery and a public JWKS with PKCE and revocation', async () => {
  const reservation = createServer();
  await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
  const address = reservation.address();
  assert(address && typeof address !== 'string');
  const port = address.port;
  await new Promise<void>((resolve, reject) => reservation.close((error) => error ? reject(error) : resolve()));

  const { privateKey } = await generateKeyPair('PS256', { extractable: true });
  const jwk = await exportJWK(privateKey);
  process.env.IDENTITY_ISSUER = `http://127.0.0.1:${port}`;
  process.env.IDENTITY_JWKS_JSON = JSON.stringify({ keys: [{ ...jwk, alg: 'PS256', use: 'sig', kid: 'test-key' }] });
  process.env.IDENTITY_COOKIE_KEYS = `${'a'.repeat(32)},${'b'.repeat(32)}`;

  const identities = { providerClients: async () => [] };
  const provider = await createOidcProvider({} as never, identities as never);
  const server = createServer(provider.callback());
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  try {
    const discovery = await fetch(`${process.env.IDENTITY_ISSUER}/.well-known/openid-configuration`).then((res) => res.json());
    assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
    assert.equal(discovery.revocation_endpoint, `${process.env.IDENTITY_ISSUER}/token/revocation`);
    assert.deepEqual(discovery.response_types_supported, ['code']);
    assert(discovery.token_endpoint_auth_methods_supported.includes('private_key_jwt'));

    const jwks = await fetch(discovery.jwks_uri).then((res) => res.json());
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].kid, 'test-key');
    assert.equal(jwks.keys[0].d, undefined);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
