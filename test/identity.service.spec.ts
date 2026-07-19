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

test('authentication hides membership ambiguity behind Invalid credentials', async () => {
  const passwordHash = await hash('correct horse battery staple', { type: 2 });
  const audits: Array<{ action: string; result: string; metadata: Record<string, unknown> }> = [];
  const prisma = {
    operator: {
      findUnique: async () => ({
        id: 'operator-ambiguous',
        status: 'ACTIVE',
        credential: { passwordHash },
        memberships: [
          {
            id: 'membership-1',
            institutionId: 'institution-1',
            branchId: null,
            institution: { tenantId: 'tenant-1' },
            roles: [{ role: 'auditor' }],
          },
          {
            id: 'membership-2',
            institutionId: 'institution-2',
            branchId: null,
            institution: { tenantId: 'tenant-2' },
            roles: [{ role: 'auditor' }],
          },
        ],
      }),
    },
    identityAuditEvent: {
      create: async ({ data }: any) => {
        audits.push(data);
        return data;
      },
    },
  };
  const service = new IdentityService(prisma as never);
  await assert.rejects(
    () => service.authenticate('operator@mavula.io', 'correct horse battery staple'),
    (error: any) => {
      assert.equal(error.message, 'Invalid credentials');
      return true;
    },
  );
  assert.equal(audits.length, 1);
  assert.equal(audits[0].action, 'authentication.login');
  assert.equal(audits[0].result, 'FAILED');
  assert.equal(audits[0].metadata.reason, 'institution_id is required');
});

test('authentication selects an active branch membership explicitly', async () => {
  const passwordHash = await hash('correct horse battery staple', { type: 2 });
  let membershipWhere: any;
  const prisma = {
    operator: {
      findUnique: async ({ include }: any) => {
        membershipWhere = include.memberships.where;
        return {
          id: 'operator-branch', status: 'ACTIVE', credential: { passwordHash },
          memberships: [{
            id: 'membership-branch', institutionId: 'institution-1', branchId: 'branch-2',
            institution: { tenantId: 'tenant-1', status: 'ACTIVE' }, branch: { status: 'ACTIVE' },
            roles: [{ role: 'operations_maker' }],
          }],
        };
      },
    },
    identityAuditEvent: { create: async () => ({}) },
  };
  const service = new IdentityService(prisma as never);
  const identity = await service.authenticate(
    'operator@mavula.io', 'correct horse battery staple', 'institution-1', 'branch-2',
  );
  assert.equal(identity.branchId, 'branch-2');
  assert.equal(membershipWhere.branchId, 'branch-2');
  assert.deepEqual(membershipWhere.institution, { status: 'ACTIVE' });
  assert.deepEqual(membershipWhere.branch, { status: 'ACTIVE' });
});

test('operator token identity must match the OAuth client tenant binding and permissions', async () => {
  const client = {
    id: 'operator-client', status: 'ACTIVE',
    tenantBindings: [{ tenant_id: 'tenant-1', institution_id: 'institution-1' }],
    permissions: ['finance.read'],
  };
  const prisma = {
    oAuthClient: { findUnique: async () => client },
    membership: { findFirst: async () => ({
      operatorId: 'operator-1', institutionId: 'institution-1', branchId: null,
      institution: { tenantId: 'tenant-1', status: 'ACTIVE' }, branch: null,
      roles: [{ role: 'auditor' }], operator: { status: 'ACTIVE' },
    }) },
  };
  const service = new IdentityService(prisma as never);
  const resolved = await service.resolveTokenIdentity('operator-client', 'operator-1|membership-1', 'tenant-1');
  assert.deepEqual(resolved?.clientPermissions, ['finance.read']);
  client.tenantBindings = [{ tenant_id: 'tenant-2', institution_id: 'institution-2' }];
  assert.equal(await service.resolveTokenIdentity('operator-client', 'operator-1|membership-1', 'tenant-1'), undefined);
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
