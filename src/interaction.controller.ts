import {
  Body,
  Controller,
  Get,
  Inject,
  Param,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';
import type Provider from 'oidc-provider';
import { getIdentityConfig } from './config.js';
import { IdentityService } from './identity.service.js';
import { LoginRateLimiter } from './login-rate-limiter.js';
import { OIDC_PROVIDER } from './oidc.provider.js';

@Controller('interaction')
export class InteractionController {
  private readonly csrfKey = getIdentityConfig().cookieKeys[0];

  constructor(
    @Inject(OIDC_PROVIDER) private readonly provider: Provider,
    private readonly identities: IdentityService,
    private readonly loginRateLimiter: LoginRateLimiter,
  ) {}

  @Get(':uid')
  async details(@Param('uid') uid: string, @Req() req: any, @Res() res: any) {
    const details = await this.provider.interactionDetails(req, res);
    const csrf = this.csrf(uid);
    const clientName = this.escape(String(details.params.client_id || 'MAVULA'));
    if (details.prompt.name === 'login') {
      return res.type('html').send(this.page(clientName, `
        <form method="post" autocomplete="on">
          <input type="hidden" name="csrf" value="${csrf}">
          <label>Email<input name="email" type="email" autocomplete="username" required></label>
          <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
          <label>Institution ID<input name="institution_id" autocomplete="organization"></label>
          <button type="submit">Sign in</button>
        </form>`));
    }
    if (details.prompt.name === 'consent') {
      return res.type('html').send(this.page(clientName, `
        <form method="post"><input type="hidden" name="csrf" value="${csrf}">
        <button type="submit">Continue</button></form>`));
    }
    throw new UnauthorizedException('Unsupported authorization interaction');
  }

  @Post(':uid')
  async submit(@Param('uid') uid: string, @Body() body: Record<string, string>, @Req() req: any, @Res() res: any) {
    if (!this.validCsrf(uid, body.csrf)) throw new UnauthorizedException('Invalid interaction');
    const details = await this.provider.interactionDetails(req, res);
    if (details.prompt.name === 'login') {
      const remoteAddress = String(req.ip || req.socket?.remoteAddress || 'unknown');
      const email = (body.email || '').trim().toLowerCase();
      this.loginRateLimiter.assertAllowed(remoteAddress, email);
      const identity = await this.identities.authenticate(
        email,
        body.password || '',
        body.institution_id || undefined,
      ).catch((error) => {
        this.loginRateLimiter.recordFailure(remoteAddress, email);
        throw error;
      });
      this.loginRateLimiter.clear(email);
      return this.provider.interactionFinished(
        req,
        res,
        { login: { accountId: identity.accountId, acr: 'urn:mavula:operator', amr: ['pwd'] } },
        { mergeWithLastSubmission: false },
      );
    }
    if (details.prompt.name === 'consent') {
      const grant = details.grantId
        ? await this.provider.Grant.find(details.grantId)
        : new this.provider.Grant({
            accountId: details.session?.accountId!,
            clientId: details.params.client_id as string,
          });
      if (!grant) throw new UnauthorizedException('Authorization grant is unavailable');
      const missingOIDCScope = details.prompt.details.missingOIDCScope as string[] | undefined;
      if (missingOIDCScope) grant.addOIDCScope(missingOIDCScope.join(' '));
      const missingResources = details.prompt.details.missingResourceScopes as Record<string, string[]> | undefined;
      for (const [resource, scopes] of Object.entries(missingResources || {})) {
        grant.addResourceScope(resource, scopes.join(' '));
      }
      const grantId = await grant.save();
      return this.provider.interactionFinished(
        req,
        res,
        { consent: { grantId } },
        { mergeWithLastSubmission: true },
      );
    }
    throw new UnauthorizedException('Unsupported authorization interaction');
  }

  private csrf(uid: string): string {
    return createHmac('sha256', this.csrfKey).update(uid).digest('base64url');
  }

  private validCsrf(uid: string, supplied = ''): boolean {
    const expected = Buffer.from(this.csrf(uid));
    const actual = Buffer.from(supplied);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }

  private escape(value: string): string {
    const replacements: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;',
    };
    return value.replace(/[&<>'"]/g, (char) => replacements[char]);
  }

  private page(client: string, body: string): string {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
      <title>Sign in to ${client}</title><style>body{font-family:system-ui;margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f8;color:#17202a}main{width:min(92vw,28rem)}form{display:grid;gap:1rem}label{display:grid;gap:.4rem;font-weight:600}input{padding:.75rem;border:1px solid #9aa4af;border-radius:4px;font:inherit}button{padding:.8rem;border:0;border-radius:4px;background:#126b52;color:white;font:inherit;font-weight:700}</style></head>
      <body><main><h1>${client}</h1>${body}</main></body></html>`;
  }
}
