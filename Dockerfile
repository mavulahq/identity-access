FROM node:22.22.3-alpine AS builder
WORKDIR /usr/src/app
RUN apk add --no-cache openssl
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
RUN npm i -g pnpm@10.33.0 && pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM node:22.22.3-alpine AS runtime
WORKDIR /usr/src/app
RUN apk add --no-cache openssl
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
RUN npm i -g pnpm@10.33.0 && pnpm install --prod --frozen-lockfile
COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/generated ./generated
ENV NODE_ENV=production
EXPOSE 3020
CMD ["node", "dist/main.js"]
