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

# Neither process needs root. Caddy still has to bind 80 and 443 - for the ACME HTTP-01
# challenge and for TLS - which a non-root process cannot do without this capability.
# File capabilities live in extended attributes and are not carried across COPY --from,
# so it is granted here rather than inherited from the caddy image. libcap is removed
# again once setcap has run: the capability is on the binary, not in the package.
RUN apk add --no-cache libcap \
    && setcap cap_net_bind_service=+ep /usr/bin/caddy \
    && apk del libcap
# Caddy's certificate cache (XDG_DATA_HOME below) has to be writable by that user, and
# the directory has to exist beforehand so a named volume mounted here inherits its
# ownership. A bind mount does not: point one here and it must already be writable by
# uid 1000, or Caddy cannot persist its certificate.
RUN mkdir -p /data && chown node:node /data
USER node

ENV NODE_ENV=production
# Caddy caches its ACME account and certificates under $XDG_DATA_HOME/caddy. Container
# filesystems are typically ephemeral across deploys, so without a persistent volume
# mounted here, every redeploy loses the cert and forces a fresh Let's Encrypt issuance —
# burning through the 5-per-week duplicate-certificate rate limit almost immediately.
ENV XDG_DATA_HOME=/data
CMD ["./start.sh"]
