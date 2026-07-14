import 'reflect-metadata';
import { RequestMethod } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type Provider from 'oidc-provider';
import { AppModule } from './app.module.js';
import { getIdentityConfig } from './config.js';
import { OIDC_PROVIDER } from './oidc.provider.js';

async function bootstrap() {
  const config = getIdentityConfig();
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api', {
    exclude: [
      { path: 'health', method: RequestMethod.GET },
      { path: 'interaction/:uid', method: RequestMethod.ALL },
    ],
  });
  await app.init();
  const provider = app.get<Provider>(OIDC_PROVIDER);
  app.getHttpAdapter().getInstance().use(provider.callback());
  await app.listen(config.port, '0.0.0.0');
}

void bootstrap();
