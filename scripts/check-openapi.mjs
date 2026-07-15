import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = readFileSync(path.join(root, 'contracts/openapi/identity-access.public.v1.yaml'), 'utf8');
const paths = new Set([...source.matchAll(/^  (\/[^:]+):$/gm)].map((match) => match[1]));
const expected = [
  '/.well-known/openid-configuration', '/jwks', '/auth', '/token', '/token/revocation', '/api/v1/me',
];
for (const route of expected) if (!paths.has(route)) throw new Error(`OpenAPI route missing: ${route}`);
for (const route of paths) if (route.startsWith('/interaction') || route === '/health') throw new Error(`Internal route exposed: ${route}`);
console.log(`identity-access OpenAPI covers ${paths.size} public routes`);
