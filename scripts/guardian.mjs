#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const failures = [];
const required = [
  '.github/CODEOWNERS',
  '.github/PULL_REQUEST_TEMPLATE.md',
  '.github/workflows/guardian.yml',
  '.env.example',
  'Dockerfile',
  'LICENSE',
  'README.md',
  'contracts/openapi/identity-access.public.v1.yaml',
  'scripts/check-openapi.mjs',
  'prisma/schema.prisma',
  'src/oidc.provider.ts',
  'src/login-rate-limiter.ts',
  'test/oidc-provider.spec.ts',
];
for (const file of required) if (!existsSync(file)) failures.push(`${file} is required`);
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
if (pkg.name !== '@mavula/identity-access') failures.push('package name must be @mavula/identity-access');
if (pkg.license !== 'AGPL-3.0-only') failures.push('identity-access must remain AGPL-3.0-only');
if (pkg.author !== 'EstandarMustaq <estandarmustaq@mavula.io>') failures.push('author must use the MAVULA address');
const tracked = spawnSync('git', ['ls-files'], { encoding: 'utf8' });
if (tracked.status !== 0) failures.push('git ls-files failed');
for (const file of tracked.stdout.split('\n').filter(Boolean)) {
  if (!existsSync(file)) continue;
  if (/(^|\/)\.env($|\.(?!example$))/.test(file)) failures.push(`${file} must not be tracked`);
  if (/\.(png|jpg|jpeg|webp|gif|ico|pdf|zip|gz|tgz)$/i.test(file) || file === 'scripts/guardian.mjs') continue;
  const content = readFileSync(file, 'utf8');
  if (/getfluxo-io|@getfluxo|\bgetfluxo\b|JWT_SECRET|change_me/.test(content)) {
    failures.push(`${file} contains a legacy identifier or insecure fallback`);
  }
  if (/BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/.test(content)) failures.push(`${file} contains private key material`);
}
const openapi = spawnSync(process.execPath, ['scripts/check-openapi.mjs'], { encoding: 'utf8' });
if (openapi.status !== 0) failures.push(`openapi check failed: ${(openapi.stderr || openapi.stdout).trim()}`);
if (failures.length) {
  console.error('MAVULA identity-access guardian failed:');
  failures.forEach((failure) => console.error(`- ${failure}`));
  process.exit(1);
}
console.log('MAVULA identity-access guardian passed.');
