import { hash } from 'argon2';
import { PrismaClient, type Prisma } from '../generated/prisma/index.js';
import { tokenEndpointAuthMethodForClient } from './identity.service.js';

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
      const data = {
        name: String(client.name || id),
        status: 'ACTIVE',
        redirectUris: (client.redirect_uris || []) as Prisma.InputJsonValue,
        grantTypes: (client.grant_types || []) as Prisma.InputJsonValue,
        responseTypes: (client.response_types || []) as Prisma.InputJsonValue,
        tokenEndpointAuthMethod: tokenEndpointAuthMethodForClient(
          Array.isArray(client.grant_types) ? client.grant_types.map(String) : [],
          typeof client.token_endpoint_auth_method === 'string' ? client.token_endpoint_auth_method : undefined,
        ),
        jwks: client.jwks as Prisma.InputJsonValue | undefined,
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

void main();
