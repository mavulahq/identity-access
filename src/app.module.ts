import { Module } from '@nestjs/common';
import { AccessGuard } from './access.guard.js';
import { HealthController, IdentityController } from './api.controller.js';
import { IdentityService } from './identity.service.js';
import { InteractionController } from './interaction.controller.js';
import { LoginRateLimiter } from './login-rate-limiter.js';
import { createOidcProvider, OIDC_PROVIDER } from './oidc.provider.js';
import { PrismaService } from './prisma.service.js';

@Module({
  controllers: [HealthController, IdentityController, InteractionController],
  providers: [
    PrismaService,
    IdentityService,
    LoginRateLimiter,
    AccessGuard,
    {
      provide: OIDC_PROVIDER,
      inject: [PrismaService, IdentityService],
      useFactory: createOidcProvider,
    },
  ],
})
export class AppModule {}
