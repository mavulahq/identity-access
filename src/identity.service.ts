import { Injectable, UnauthorizedException } from '@nestjs/common';
import { verify } from 'argon2';
import type { OAuthClient, Prisma } from '../generated/prisma/index.js';
import {
  ACCESS_PERMISSIONS,
  EffectiveIdentity,
  effectivePermissions,
  isInstitutionalRole,
  type AccessPermission,
} from './access.types.js';
import { PrismaService } from './prisma.service.js';

interface TenantBinding {
  tenant_id: string;
  institution_id: string;
  branch_id?: string;
}

@Injectable()
export class IdentityService {
  constructor(private readonly prisma: PrismaService) {}

  async authenticate(email: string, password: string, institutionId?: string, branchId?: string): Promise<EffectiveIdentity> {
    const operator = await this.prisma.operator.findUnique({
      where: { email: email.trim().toLowerCase() },
      include: {
        credential: true,
        memberships: {
          where: {
            status: 'ACTIVE',
            institution: { status: 'ACTIVE' },
            ...(institutionId ? { institutionId } : {}),
            ...(branchId ? { branchId, branch: { status: 'ACTIVE' } } : {
              OR: [{ branchId: null }, { branch: { status: 'ACTIVE' } }],
            }),
          },
          include: { institution: true, branch: true, roles: true },
        },
      },
    });
    const valid = Boolean(
      operator &&
      operator.status === 'ACTIVE' &&
      operator.credential &&
      await verify(operator.credential.passwordHash, password).catch(() => false),
    );
    if (!valid || !operator) throw new UnauthorizedException('Invalid credentials');
    if (operator.memberships.length !== 1) {
      const reason = operator.memberships.length === 0
        ? 'No active institutional membership'
        : institutionId ? 'branch_id is required' : 'institution_id is required';
      await this.audit('authentication.login', 'FAILED', { subject: operator.id }, { reason });
      throw new UnauthorizedException('Invalid credentials');
    }
    const membership = operator.memberships[0];
    const roles = membership.roles.map(({ role }) => role).filter(isInstitutionalRole);
    const identity: EffectiveIdentity = {
      subject: operator.id,
      accountId: `${operator.id}|${membership.id}`,
      tenantId: membership.institution.tenantId,
      institutionId: membership.institutionId,
      branchId: membership.branchId || undefined,
      roles,
      permissions: effectivePermissions(roles),
    };
    await this.audit('authentication.login', 'SUCCEEDED', identity, {});
    return identity;
  }

  async findOperatorIdentity(accountId: string): Promise<EffectiveIdentity | undefined> {
    const [operatorId, membershipId] = accountId.split('|');
    if (!operatorId || !membershipId) return undefined;
    const membership = await this.prisma.membership.findFirst({
      where: {
        id: membershipId,
        operatorId,
        status: 'ACTIVE',
        operator: { status: 'ACTIVE' },
        institution: { status: 'ACTIVE' },
        OR: [{ branchId: null }, { branch: { status: 'ACTIVE' } }],
      },
      include: { institution: true, branch: true, roles: true, operator: true },
    });
    if (!membership) return undefined;
    const roles = membership.roles.map(({ role }) => role).filter(isInstitutionalRole);
    return {
      subject: membership.operatorId,
      accountId,
      tenantId: membership.institution.tenantId,
      institutionId: membership.institutionId,
      branchId: membership.branchId || undefined,
      roles,
      permissions: effectivePermissions(roles),
    };
  }

  async findClientIdentity(clientId: string, requestedTenantId?: string): Promise<EffectiveIdentity | undefined> {
    const client = await this.prisma.oAuthClient.findUnique({ where: { id: clientId } });
    if (!client || client.status !== 'ACTIVE') return undefined;
    const bindings = this.array<TenantBinding>(client.tenantBindings);
    const binding = requestedTenantId
      ? bindings.find(({ tenant_id }) => tenant_id === requestedTenantId)
      : bindings.length === 1 ? bindings[0] : undefined;
    if (!binding) return undefined;
    const institution = await this.prisma.institution.findFirst({
      where: {
        id: binding.institution_id,
        tenantId: binding.tenant_id,
        status: 'ACTIVE',
        ...(binding.branch_id ? { branches: { some: { id: binding.branch_id, status: 'ACTIVE' } } } : {}),
      },
      select: { id: true },
    });
    if (!institution) return undefined;
    return {
      subject: `client:${client.id}`,
      accountId: `client:${client.id}`,
      tenantId: binding.tenant_id,
      institutionId: binding.institution_id,
      branchId: binding.branch_id,
      roles: [],
      permissions: this.array<string>(client.permissions).filter(
        (permission): permission is AccessPermission =>
          ACCESS_PERMISSIONS.includes(permission as AccessPermission),
      ),
    };
  }

  async resolveTokenIdentity(
    clientId: string,
    accountId?: string,
    requestedTenantId?: string,
  ): Promise<{ identity: EffectiveIdentity; clientPermissions: AccessPermission[] } | undefined> {
    const client = await this.prisma.oAuthClient.findUnique({ where: { id: clientId } });
    if (!client || client.status !== 'ACTIVE') return undefined;
    const clientPermissions = this.array<string>(client.permissions).filter(
      (permission): permission is AccessPermission => ACCESS_PERMISSIONS.includes(permission as AccessPermission),
    );
    if (!accountId) {
      const identity = await this.findClientIdentity(clientId, requestedTenantId);
      return identity ? { identity, clientPermissions } : undefined;
    }
    const identity = await this.findOperatorIdentity(accountId);
    if (!identity || (requestedTenantId && requestedTenantId !== identity.tenantId)) return undefined;
    const binding = this.array<TenantBinding>(client.tenantBindings).find((candidate) =>
      candidate.tenant_id === identity.tenantId
      && candidate.institution_id === identity.institutionId
      && (!candidate.branch_id || candidate.branch_id === identity.branchId));
    return binding ? { identity, clientPermissions } : undefined;
  }

  async providerClients() {
    const clients = await this.prisma.oAuthClient.findMany({ where: { status: 'ACTIVE' } });
    return clients.map((client) => this.providerClient(client));
  }

  async audit(
    action: string,
    result: string,
    identity: Partial<EffectiveIdentity> & { subject?: string },
    metadata: Record<string, unknown>,
  ) {
    await this.prisma.identityAuditEvent.create({
      data: {
        action,
        result,
        operatorId: identity.subject?.startsWith('client:') ? undefined : identity.subject,
        clientId: identity.subject?.startsWith('client:') ? identity.subject.slice(7) : undefined,
        institutionId: identity.institutionId,
        tenantId: identity.tenantId,
        metadata: metadata as Prisma.InputJsonValue,
      },
    });
  }

  private providerClient(client: OAuthClient) {
    return {
      client_id: client.id,
      client_name: client.name,
      redirect_uris: this.array<string>(client.redirectUris),
      grant_types: this.array<string>(client.grantTypes),
      response_types: this.array<string>(client.responseTypes),
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      jwks: client.jwks || undefined,
      resource_audiences: this.array<string>(client.resourceAudiences),
      permissions: this.array<string>(client.permissions),
    };
  }

  private array<T>(value: Prisma.JsonValue): T[] {
    return Array.isArray(value) ? value as T[] : [];
  }
}
