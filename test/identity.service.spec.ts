import assert from 'node:assert/strict';
import test from 'node:test';
import { hash } from 'argon2';
import { IdentityService } from '../src/identity.service.js';

test('authentication derives roles from the durable membership only', async () => {
  const passwordHash = await hash('correct horse battery staple', { type: 2 });
  const prisma = {
    operator: {
      findUnique: async () => ({
        id: 'operator-1',
        status: 'ACTIVE',
        credential: { passwordHash },
        memberships: [{
          id: 'membership-1',
          institutionId: 'institution-1',
          branchId: null,
          institution: { tenantId: 'tenant-1' },
          roles: [{ role: 'auditor' }],
        }],
      }),
    },
    identityAuditEvent: { create: async () => ({}) },
  };
  const service = new IdentityService(prisma as never);
  const identity = await service.authenticate('operator@mavula.io', 'correct horse battery staple');
  assert.deepEqual(identity.roles, ['auditor']);
  assert.deepEqual(identity.permissions, ['finance.read', 'audit.read']);
});

test('service identity requires a matching active institution binding', async () => {
  const prisma = {
    oAuthClient: {
      findUnique: async () => ({
        id: 'workbench',
        status: 'ACTIVE',
        tenantBindings: [{ tenant_id: 'tenant-1', institution_id: 'institution-1' }],
        permissions: ['internal.worker'],
      }),
    },
    institution: {
      findFirst: async ({ where }: any) => where.id === 'institution-1' && where.tenantId === 'tenant-1'
        ? { id: 'institution-1' }
        : null,
    },
  };
  const service = new IdentityService(prisma as never);

  assert.equal((await service.findClientIdentity('workbench', 'tenant-1'))?.institutionId, 'institution-1');
  assert.equal(await service.findClientIdentity('workbench', 'tenant-2'), undefined);
});

test('service identity rejects a stale tenant-institution pair', async () => {
  const prisma = {
    oAuthClient: {
      findUnique: async () => ({
        id: 'workbench',
        status: 'ACTIVE',
        tenantBindings: [{ tenant_id: 'tenant-1', institution_id: 'institution-stale' }],
        permissions: ['internal.worker'],
      }),
    },
    institution: { findFirst: async () => null },
  };
  const service = new IdentityService(prisma as never);

  assert.equal(await service.findClientIdentity('workbench', 'tenant-1'), undefined);
});
