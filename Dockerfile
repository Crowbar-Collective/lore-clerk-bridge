# Custom Caddy build: the base Caddy image doesn't include DNS-provider plugins, and
# we need caddy-dns/cloudflare specifically so Caddy can complete Let's Encrypt's
# DNS-01 challenge directly against our Cloudflare zone.
FROM caddy:2-builder-alpine AS caddy-build
RUN xcaddy build --with github.com/caddy-dns/cloudflare

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
# Caddy caches its ACME account and certificates under $XDG_DATA_HOME/caddy. Railway's
# container filesystem is ephemeral across deploys, so without a volume mounted here,
# every redeploy loses the cert and forces a fresh Let's Encrypt issuance — burning
# through Let's Encrypt's 5-per-week duplicate-certificate rate limit almost immediately.
ENV XDG_DATA_HOME=/data
CMD ["./start.sh"]
