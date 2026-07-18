import assert from 'node:assert/strict';
import test from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { AccessGuard } from '../src/access.guard.js';

test('Identity Access resource guard rejects tokens issued only for another resource', async () => {
  const { privateKey } = await generateKeyPair('PS256', { extractable: true });
  const jwk = await exportJWK(privateKey);
  process.env.IDENTITY_ISSUER = 'https://identity.mavula.io';
  process.env.IDENTITY_JWKS_JSON = JSON.stringify({ keys: [{ ...jwk, alg: 'PS256', use: 'sig', kid: 'access-test' }] });
  process.env.IDENTITY_COOKIE_KEYS = `${'a'.repeat(32)},${'b'.repeat(32)}`;
  process.env.IDENTITY_AUDIENCE = 'urn:mavula:identity-access';
  process.env.IDENTITY_RESOURCE_AUDIENCES = 'urn:mavula:identity-access,urn:mavula:ledger-core';

  const token = await new SignJWT({
    tenant_id: 'tenant-1', institution_id: 'institution-1', roles: [], permissions: [],
  }).setProtectedHeader({ alg: 'PS256', kid: 'access-test', typ: 'at+jwt' })
    .setIssuer(process.env.IDENTITY_ISSUER)
    .setAudience('urn:mavula:ledger-core')
    .setSubject('operator-1')
    .setExpirationTime('5m')
    .sign(privateKey);
  const request: any = { headers: { authorization: `Bearer ${token}` } };
  const context = { switchToHttp: () => ({ getRequest: () => request }) } as any;

  await assert.rejects(() => new AccessGuard().canActivate(context), /Invalid access token/);
});
