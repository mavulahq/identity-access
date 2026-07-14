import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { getIdentityConfig } from './config.js';

export interface AccessTokenClaims extends JWTPayload {
  sub: string;
  tenant_id: string;
  institution_id: string;
  branch_id?: string;
  roles: string[];
  permissions: string[];
  client_id?: string;
}

@Injectable()
export class AccessGuard implements CanActivate {
  private readonly config = getIdentityConfig();
  private readonly jwks = createLocalJWKSet({
    keys: this.config.jwks.keys.map(({ d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicKey }) => publicKey),
  });

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const header = req.headers.authorization;
    if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
      throw new UnauthorizedException('Bearer access token is required');
    }
    try {
      const { payload } = await jwtVerify(header.slice(7), this.jwks, {
        issuer: this.config.issuer,
        audience: this.config.resourceAudiences,
        algorithms: ['PS256'],
        typ: 'at+jwt',
      });
      if (
        !payload.sub ||
        typeof payload.tenant_id !== 'string' ||
        typeof payload.institution_id !== 'string' ||
        !Array.isArray(payload.roles) ||
        !Array.isArray(payload.permissions)
      ) throw new Error('required claims are missing');
      req.identity = payload as AccessTokenClaims;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid access token');
    }
  }
}
