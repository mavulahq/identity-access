import assert from 'node:assert/strict';
import test from 'node:test';
import { Test } from '@nestjs/testing';
import { HealthController } from '../src/api.controller.js';
import { configureIdentityApplication } from '../src/main.js';
import { OIDC_PROVIDER } from '../src/oidc.provider.js';

test('routes OIDC endpoints through the provider without shadowing Nest routes', async () => {
  const module = await Test.createTestingModule({
    controllers: [HealthController],
    providers: [{
      provide: OIDC_PROVIDER,
      useValue: {
        callback: () => (req: any, res: any) => res.status(200).json({ path: req.path }),
      },
    }],
  }).compile();
  const app = module.createNestApplication();
  await configureIdentityApplication(app, 0);
  await app.listen(0, '127.0.0.1');
  const server = app.getHttpServer();
  const address = server.address();
  assert(address && typeof address !== 'string');
  try {
    const oidc = await fetch(`http://127.0.0.1:${address.port}/jwks`).then((response) => response.json());
    const health = await fetch(`http://127.0.0.1:${address.port}/health`).then((response) => response.json());
    assert.equal(oidc.path, '/jwks');
    assert.equal(health.service, 'identity-access');
  } finally {
    await app.close();
  }
});
