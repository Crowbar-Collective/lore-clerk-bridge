# Custom Caddy build: the base Caddy image doesn't include DNS-provider plugins, and
# we need caddy-dns/acmedns specifically so Caddy can complete Let's Encrypt's DNS-01
# challenge via acme-dns (our DNS provider has no API, so DNS-01 must be delegated).
FROM caddy:2-builder-alpine AS caddy-build
RUN xcaddy build --with github.com/caddy-dns/acmedns

FROM node:20-alpine AS node-build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY proto ./proto
RUN npm run build
RUN npm prune --omit=dev

FROM node:20-alpine
WORKDIR /app
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy
COPY --from=node-build /app/dist ./dist
COPY --from=node-build /app/node_modules ./node_modules
COPY --from=node-build /app/proto ./proto
COPY package.json ./
COPY Caddyfile ./Caddyfile
COPY start.sh ./start.sh
RUN chmod +x start.sh

ENV NODE_ENV=production
CMD ["./start.sh"]
