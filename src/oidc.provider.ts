import Provider, { errors, type ClientMetadata, type Configuration } from 'oidc-provider';
import { getIdentityConfig } from './config.js';
import { IdentityService } from './identity.service.js';
import { prismaAdapterFactory } from './oidc.adapter.js';
import { PrismaService } from './prisma.service.js';
import { ACCESS_PERMISSIONS } from './access.types.js';

export const OIDC_PROVIDER = Symbol('OIDC_PROVIDER');

export async function createOidcProvider(prisma: PrismaService, identities: IdentityService) {
  const config = getIdentityConfig();
  const clients = await identities.providerClients();
  const providerConfig: Configuration = {
    adapter: prismaAdapterFactory(prisma),
    clients: clients as unknown as ClientMetadata[],
    jwks: config.jwks as Configuration['jwks'],
    cookies: {
      keys: config.cookieKeys,
      long: { signed: true, httpOnly: true, sameSite: 'lax', secure: config.secureCookies },
      short: { signed: true, httpOnly: true, sameSite: 'lax', secure: config.secureCookies },
    },
    claims: {
      openid: ['sub'],
      profile: ['tenant_id', 'institution_id', 'branch_id', 'roles', 'permissions'],
    },
    scopes: ['openid', 'profile', ...ACCESS_PERMISSIONS],
    responseTypes: ['code'],
    clientDefaults: {
      id_token_signed_response_alg: 'PS256',
    },
    clientAuthMethods: ['none', 'private_key_jwt'],
    extraClientMetadata: {
      properties: ['resource_audiences'],
      validator(_ctx, key, value) {
        if (key === 'resource_audiences' && (!Array.isArray(value) || value.some((item) => typeof item !== 'string'))) {
          throw new errors.InvalidClientMetadata('resource_audiences must be an array of strings');
        }
      },
    },
    extraParams: {
      tenant_id(_ctx, value) {
        if (value !== undefined && !/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,127}$/.test(value)) {
          throw new errors.InvalidRequest('tenant_id is invalid');
        }
      },
    },
    pkce: { required: () => true },
    features: {
      clientCredentials: { enabled: true },
      devInteractions: { enabled: false },
      introspection: { enabled: false },
      registration: { enabled: false },
      revocation: { enabled: true },
      resourceIndicators: {
        enabled: true,
        defaultResource(_ctx, client) {
          return (client.resourceAudiences as string[] | undefined)?.[0] || 'urn:mavula:identity-access';
        },
        useGrantedResource: () => true,
        getResourceServerInfo(_ctx, resource, client) {
          const allowed = client.resourceAudiences as string[] | undefined;
          if (!allowed?.includes(resource) || !config.resourceAudiences.includes(resource)) {
            throw new errors.InvalidTarget('resource is not registered for this client');
          }
          return {
            scope: ACCESS_PERMISSIONS.join(' '),
            audience: resource,
            accessTokenTTL: 300,
            accessTokenFormat: 'jwt',
            jwt: { sign: { alg: 'PS256' } },
          };
        },
      },
    },
    formats: {
      customizers: {
        jwt(_ctx, _token, parts) {
          parts.header = { ...parts.header, typ: 'at+jwt' };
          return parts;
        },
      },
    },
    ttl: {
      AccessToken: 300,
      AuthorizationCode: 60,
      ClientCredentials: 300,
      IdToken: 300,
      Interaction: 600,
      RefreshToken: 28_800,
      Session: 28_800,
    },
    interactions: {
      url(_ctx, interaction) {
        return `/interaction/${interaction.uid}`;
      },
    },
    findAccount: async (_ctx, accountId) => {
      const identity = await identities.findOperatorIdentity(accountId);
      if (!identity) return undefined;
      return {
        accountId,
        claims: async () => ({
          sub: identity.subject,
          tenant_id: identity.tenantId,
          institution_id: identity.institutionId,
          branch_id: identity.branchId,
          roles: identity.roles,
          permissions: identity.permissions,
        }),
      };
    },
    extraTokenClaims: async (ctx, token) => {
      const identity = 'accountId' in token && token.accountId
        ? await identities.findOperatorIdentity(token.accountId)
        : await identities.findClientIdentity(
            token.clientId!,
            typeof ctx.oidc.params?.tenant_id === 'string' ? ctx.oidc.params.tenant_id : undefined,
          );
      if (!identity) throw new errors.InvalidGrant('identity context is unavailable');
      const requested = new Set((token.scope || '').split(' '));
      const permissions = identity.permissions.filter((permission) => requested.has(permission));
      return {
        sub: identity.subject,
        tenant_id: identity.tenantId,
        institution_id: identity.institutionId,
        branch_id: identity.branchId,
        roles: identity.roles,
        permissions,
        client_id: token.clientId,
      };
    },
    issueRefreshToken: async (ctx, client) =>
      client.grantTypeAllowed('refresh_token') && ctx.oidc.entities.AuthorizationCode !== undefined,
  };
  const provider = new Provider(config.issuer, providerConfig);
  provider.proxy = process.env.NODE_ENV === 'production';
  return provider;
}
