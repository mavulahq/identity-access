# MAVULA Identity Access

`@mavula/identity-access` is the institutional authorization server and OpenID Provider for MAVULA.

## Responsibilities

- Institutions, branches, operators, credentials and memberships.
- Institutional roles, effective permissions and maker-checker policy.
- OpenID Connect discovery, JWKS, Authorization Code with PKCE and Client Credentials.
- Short-lived signed access tokens, sessions, refresh tokens and revocation.

## Development

Create an untracked `.env` from the committed placeholders, apply the identity schema and bootstrap the first institution:

```bash
pnpm prisma:dev
pnpm bootstrap
pnpm start:dev
```

The service defaults to port `3020`. Health is exposed at `GET /health`; discovery is exposed at `GET /.well-known/openid-configuration`.

License: AGPL-3.0-only.
