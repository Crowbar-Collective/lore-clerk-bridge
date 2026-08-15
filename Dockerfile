FROM node:20-alpine AS node-build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY proto ./proto
# public/ is copied in before the build because `npm run build` vendors clerk-js's
# browser files into public/vendor/clerk.
COPY public ./public
RUN npm run build
# Drops @clerk/clerk-js and its tree, including the wallet SDKs whose advisories would
# otherwise be reported against every deployment. The files it produced are already
# vendored into public/ by this point, and nothing here imports the package at runtime.
RUN npm prune --omit=dev

FROM node:20-alpine
WORKDIR /app
# The stock Caddy binary is enough: certificates come from Let's Encrypt's HTTP-01
# challenge, which needs no DNS-provider plugin and so no custom xcaddy build. Only a
# deployment that cannot expose ports 80 and 443 needs DNS-01, and with it a rebuilt
# Caddy carrying a caddy-dns plugin; see the README.
COPY --from=caddy:2-alpine /usr/bin/caddy /usr/bin/caddy
COPY --from=node-build /app/dist ./dist
COPY --from=node-build /app/node_modules ./node_modules
COPY --from=node-build /app/proto ./proto
# From the build stage, not the context: it carries the vendored clerk-js files alongside
# the static login pages.
COPY --from=node-build /app/public ./public
COPY package.json ./
COPY Caddyfile ./Caddyfile
COPY start.sh ./start.sh
RUN chmod +x start.sh

ENV NODE_ENV=production
# Caddy caches its ACME account and certificates under $XDG_DATA_HOME/caddy. Container
# filesystems are typically ephemeral across deploys, so without a persistent volume
# mounted here, every redeploy loses the cert and forces a fresh Let's Encrypt issuance —
# burning through the 5-per-week duplicate-certificate rate limit almost immediately.
ENV XDG_DATA_HOME=/data
CMD ["./start.sh"]
