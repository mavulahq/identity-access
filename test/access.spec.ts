import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertMakerChecker,
  effectivePermissions,
  type EffectiveIdentity,
} from '../src/access.types.js';

test('institutional roles resolve to separated permissions', () => {
  const maker = effectivePermissions(['operations_maker']);
  const checker = effectivePermissions(['operations_checker']);
  const auditor = effectivePermissions(['auditor']);
  assert(maker.includes('finance.write'));
  assert(!maker.includes('finance.approve'));
  assert(checker.includes('finance.approve'));
  assert(!checker.includes('finance.write'));
  assert(!auditor.some((permission) => permission.endsWith('write')));
});

test('maker-checker rejects self approval', () => {
  const checker: EffectiveIdentity = {
    subject: 'operator-1',
    accountId: 'operator-1|membership-1',
    tenantId: 'tenant-1',
    institutionId: 'institution-1',
    roles: ['operations_checker'],
    permissions: ['finance.read', 'finance.approve'],
  };
  assert.throws(() => assertMakerChecker('operator-1', checker), /self-approval/);
  assert.doesNotThrow(() => assertMakerChecker('operator-2', checker));
});
