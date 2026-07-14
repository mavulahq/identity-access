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
