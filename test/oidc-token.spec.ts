import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { exportJWK, generateKeyPair, SignJWT, decodeJwt } from 'jose';
import { createOidcProvider } from '../src/oidc.provider.js';

async function withProvider(clients: Record<string, unknown>[], identities: Record<string, unknown>, run: (issuer: string) => Promise<void>) {
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
  process.env.IDENTITY_RESOURCE_AUDIENCES = 'urn:mavula:identity-access,urn:mavula:ledger-core,urn:mavula:workbench';

  const store = new Map<string, unknown>();
  const prisma = {
    oidcArtifact: {
      upsert: async ({ where, create }: any) => {
        store.set(`${where.model_id.model}:${where.model_id.id}`, create);
        return create;
      },
      findUnique: async ({ where }: any) => store.get(`${where.model_id.model}:${where.model_id.id}`) || null,
      findFirst: async () => null,
      updateMany: async () => ({ count: 0 }),
      deleteMany: async () => ({ count: 0 }),
    },
  };

  const provider = await createOidcProvider(prisma as never, {
    providerClients: async () => clients,
    findClientIdentity: async (_clientId: string, tenantId?: string) => ({
      subject: 'client:workbench',
      accountId: 'client:workbench',
      tenantId: tenantId || 'tenant-1',
      institutionId: 'institution-1',
      roles: [],
      permissions: ['internal.worker'],
    }),
    findOperatorIdentity: async () => undefined,
    ...identities,
  } as never);
  const server = createServer(provider.callback());
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  try {
    await run(process.env.IDENTITY_ISSUER);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test('rejects unauthenticated client_credentials for a none-auth service client', async () => {
  await withProvider([{
    client_id: 'insecure-service',
    client_name: 'insecure-service',
    redirect_uris: [],
    grant_types: ['client_credentials'],
    response_types: [],
    token_endpoint_auth_method: 'none',
    id_token_signed_response_alg: 'PS256',
    resource_audiences: ['urn:mavula:ledger-core'],
  }], {}, async (issuer) => {
    const response = await fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: 'insecure-service',
        resource: 'urn:mavula:ledger-core',
        scope: 'internal.worker',
        tenant_id: 'tenant-1',
      }),
    });
    assert.equal(response.status, 400);
    const body = await response.json() as { error?: string; access_token?: string };
    assert.ok(['invalid_client', 'invalid_client_metadata'].includes(String(body.error)));
    assert.equal(body.access_token, undefined);
  });
});

test('mints a tenant-scoped service token with private_key_jwt', async () => {
  const { privateKey, publicKey } = await generateKeyPair('PS256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const clientId = 'workbench';
  await withProvider([{
    client_id: clientId,
    client_name: clientId,
    redirect_uris: [],
    grant_types: ['client_credentials'],
    response_types: [],
    token_endpoint_auth_method: 'private_key_jwt',
    id_token_signed_response_alg: 'PS256',
    jwks: { keys: [{ ...publicJwk, alg: 'PS256', use: 'sig', kid: 'workbench-key' }] },
    resource_audiences: ['urn:mavula:ledger-core'],
  }], {}, async (issuer) => {
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: 'PS256', kid: 'workbench-key', typ: 'JWT' })
      .setIssuer(clientId)
      .setSubject(clientId)
      .setAudience(`${issuer}/token`)
      .setJti('assertion-1')
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(privateKey);
    const response = await fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
        resource: 'urn:mavula:ledger-core',
        scope: 'internal.worker',
        tenant_id: 'tenant-1',
      }),
    });
    const body = await response.json() as { access_token?: string; error?: string };
    assert.equal(response.status, 200, body.error);
    assert.ok(body.access_token);
    const claims = decodeJwt(body.access_token);
    assert.equal(claims.tenant_id, 'tenant-1');
    assert.deepEqual(claims.permissions, ['internal.worker']);
    assert.equal(claims.aud, 'urn:mavula:ledger-core');
  });
});
