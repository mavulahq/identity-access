import 'reflect-metadata';
import { RequestMethod } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type Provider from 'oidc-provider';
import type { INestApplication } from '@nestjs/common';
import { pathToFileURL } from 'node:url';
import { AppModule } from './app.module.js';
import { getIdentityConfig } from './config.js';
import { OIDC_PROVIDER } from './oidc.provider.js';

export async function bootstrap() {
  const config = getIdentityConfig();
  const app = await NestFactory.create(AppModule);
  await configureIdentityApplication(app, config.trustProxyHops);
  await app.listen(config.port, '0.0.0.0');
}

export async function configureIdentityApplication(app: INestApplication, trustProxyHops = getIdentityConfig().trustProxyHops) {
  const express = app.getHttpAdapter().getInstance();
  express.set('trust proxy', trustProxyHops);
  app.setGlobalPrefix('api', {
    exclude: [
      { path: 'health', method: RequestMethod.GET },
      { path: 'interaction/:uid', method: RequestMethod.ALL },
    ],
  });
  const provider = app.get<Provider>(OIDC_PROVIDER);
  const oidc = provider.callback();
  express.use((req: any, res: any, next: any) => {
    if (isOidcPath(req.path)) return oidc(req, res);
    return next();
  });
  await app.init();
  return app;
}

function isOidcPath(path: string): boolean {
  return path.startsWith('/.well-known/')
    || path === '/jwks'
    || path === '/auth'
    || path === '/token'
    || path.startsWith('/token/')
    || path.startsWith('/session/');
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  void bootstrap();
}
