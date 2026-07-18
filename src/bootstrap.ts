import { hash } from 'argon2';
import { PrismaClient, type Prisma } from '../generated/prisma/index.js';
import { pathToFileURL } from 'node:url';

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main() {
  const prisma = new PrismaClient();
  try {
    const tenantId = required('IDENTITY_BOOTSTRAP_TENANT_ID');
    const institutionId = required('IDENTITY_BOOTSTRAP_INSTITUTION_ID');
    const legalName = required('IDENTITY_BOOTSTRAP_INSTITUTION_NAME');
    const email = required('IDENTITY_BOOTSTRAP_ADMIN_EMAIL').toLowerCase();
    const passwordHash = await hash(required('IDENTITY_BOOTSTRAP_ADMIN_PASSWORD'), { type: 2 });
    const institution = await prisma.institution.upsert({
      where: { id: institutionId },
      create: { id: institutionId, tenantId, legalName },
      update: { tenantId, legalName, status: 'ACTIVE' },
    });
    const operator = await prisma.operator.upsert({
      where: { email },
      create: { email, displayName: email, credential: { create: { passwordHash } } },
      update: {
        status: 'ACTIVE',
        credential: { upsert: { create: { passwordHash }, update: { passwordHash } } },
      },
    });
    let membership = await prisma.membership.findFirst({
      where: { operatorId: operator.id, institutionId: institution.id, branchId: null },
    });
    membership ||= await prisma.membership.create({
      data: { operatorId: operator.id, institutionId: institution.id },
    });
    if (membership.status !== 'ACTIVE') {
      membership = await prisma.membership.update({ where: { id: membership.id }, data: { status: 'ACTIVE' } });
    }
    await prisma.roleAssignment.upsert({
      where: { membershipId_role: { membershipId: membership.id, role: 'institution_admin' } },
      create: { membershipId: membership.id, role: 'institution_admin' },
      update: {},
    });

    const clients = JSON.parse(process.env.IDENTITY_BOOTSTRAP_CLIENTS_JSON || '[]') as Array<Record<string, unknown>>;
    for (const client of clients) {
      const id = String(client.id || '');
      if (!id) throw new Error('bootstrap client id is required');
      const grantTypes = stringArray(client.grant_types, `${id}.grant_types`);
      const tokenEndpointAuthMethod = String(client.token_endpoint_auth_method || 'none');
      const jwks = client.jwks;
      assertClientCredentialsSecurity(id, grantTypes, tokenEndpointAuthMethod, jwks);
      const data = {
        name: String(client.name || id),
        status: 'ACTIVE',
        redirectUris: (client.redirect_uris || []) as Prisma.InputJsonValue,
        grantTypes: grantTypes as Prisma.InputJsonValue,
        responseTypes: (client.response_types || []) as Prisma.InputJsonValue,
        tokenEndpointAuthMethod,
        jwks: jwks as Prisma.InputJsonValue | undefined,
        tenantBindings: (client.tenant_bindings || []) as Prisma.InputJsonValue,
        permissions: (client.permissions || []) as Prisma.InputJsonValue,
        resourceAudiences: (client.resource_audiences || []) as Prisma.InputJsonValue,
      };
      await prisma.oAuthClient.upsert({
        where: { id },
        create: { id, ...data },
        update: data,
      });
    }
  } finally {
    await prisma.$disconnect();
  }
}

function stringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`${field} must be an array of strings`);
  }
  return value;
}

export function assertClientCredentialsSecurity(
  clientId: string,
  grantTypes: string[],
  tokenEndpointAuthMethod: string,
  jwks: unknown,
): void {
  if (!grantTypes.includes('client_credentials')) return;
  if (tokenEndpointAuthMethod !== 'private_key_jwt') {
    throw new Error(`${clientId} client_credentials clients must use private_key_jwt`);
  }
  assertPublicClientJwks(jwks, clientId);
}

function assertPublicClientJwks(value: unknown, clientId: string): void {
  const keys = value && typeof value === 'object' ? (value as { keys?: unknown }).keys : undefined;
  if (!Array.isArray(keys) || keys.length === 0 || keys.some((key) => {
    if (!key || typeof key !== 'object') return true;
    const jwk = key as Record<string, unknown>;
    return jwk.kty !== 'RSA' || jwk.alg !== 'PS256' || jwk.use !== 'sig'
      || typeof jwk.kid !== 'string' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string'
      || ['d', 'p', 'q', 'dp', 'dq', 'qi'].some((member) => member in jwk);
  })) {
    throw new Error(`${clientId}.jwks must contain public RSA PS256 signing keys`);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  void main();
}
