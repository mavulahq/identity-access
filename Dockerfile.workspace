FROM node:22.22.3-alpine AS builder
WORKDIR /usr/src/app
RUN apk add --no-cache openssl
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY packages/identity-access/package.json packages/identity-access/package.json
RUN npm i -g pnpm@10.33.0 && pnpm install --filter @mavula/identity-access... --frozen-lockfile
COPY packages/identity-access packages/identity-access
RUN pnpm --filter @mavula/identity-access build

FROM node:22.22.3-alpine AS runtime
WORKDIR /usr/src/app
RUN apk add --no-cache openssl
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY packages/identity-access/package.json packages/identity-access/package.json
RUN npm i -g pnpm@10.33.0 && pnpm install --filter @mavula/identity-access --prod --frozen-lockfile
COPY --from=builder /usr/src/app/packages/identity-access/dist ./dist
COPY --from=builder /usr/src/app/packages/identity-access/generated ./generated
ENV NODE_ENV=production
EXPOSE 3020
CMD ["node", "dist/main.js"]
