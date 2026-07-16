import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AccessGuard } from './access.guard.js';

@Controller()
export class HealthController {
  @Get('health')
  health() {
    return { status: 'ok', service: 'identity-access' };
  }
}

@Controller('v1')
@UseGuards(AccessGuard)
export class IdentityController {
  @Get('me')
  me(@Req() req: any) {
    const identity = req.identity;
    return {
      sub: identity.sub,
      tenant_id: identity.tenant_id,
      institution_id: identity.institution_id,
      branch_id: identity.branch_id,
      roles: identity.roles,
      permissions: identity.permissions,
      client_id: identity.client_id,
    };
  }
}
