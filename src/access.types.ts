export const INSTITUTIONAL_ROLES = [
  'institution_admin',
  'operations_maker',
  'operations_checker',
  'compliance_officer',
  'auditor',
] as const;

export type InstitutionalRole = (typeof INSTITUTIONAL_ROLES)[number];

export const ACCESS_PERMISSIONS = [
  'finance.read',
  'finance.write',
  'finance.approve',
  'configuration.write',
  'compliance.manage',
  'audit.read',
  'identity.admin',
  'workbench.read',
  'workbench.jobs.write',
  'observability.read',
  'internal.worker',
] as const;

export type AccessPermission = (typeof ACCESS_PERMISSIONS)[number];

const ROLE_PERMISSIONS: Record<InstitutionalRole, AccessPermission[]> = {
  institution_admin: ['finance.read', 'configuration.write', 'identity.admin'],
  operations_maker: ['finance.read', 'finance.write', 'workbench.read', 'workbench.jobs.write'],
  operations_checker: ['finance.read', 'finance.approve', 'workbench.read'],
  compliance_officer: ['finance.read', 'compliance.manage', 'audit.read'],
  auditor: ['finance.read', 'audit.read'],
};

export interface EffectiveIdentity {
  subject: string;
  accountId: string;
  tenantId: string;
  institutionId: string;
  branchId?: string;
  roles: InstitutionalRole[];
  permissions: AccessPermission[];
}

export function isInstitutionalRole(value: string): value is InstitutionalRole {
  return INSTITUTIONAL_ROLES.includes(value as InstitutionalRole);
}

export function effectivePermissions(roles: InstitutionalRole[]): AccessPermission[] {
  return [...new Set(roles.flatMap((role) => ROLE_PERMISSIONS[role]))];
}

export function assertMakerChecker(makerSubject: string, checker: EffectiveIdentity): void {
  if (!checker.permissions.includes('finance.approve')) {
    throw new Error('finance.approve permission is required');
  }
  if (makerSubject === checker.subject) {
    throw new Error('self-approval is not permitted');
  }
}
