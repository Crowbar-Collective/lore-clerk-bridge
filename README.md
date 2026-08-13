# lore-clerk-bridge

A bridge service developed by Crowbar Collective that lets [Lore](https://github.com/EpicGames/lore) authenticate
users through [Clerk](https://clerk.com). It implements Lore's
`UrcAuthApi` gRPC service backed by a Clerk sign-in flow, so the `lore` CLI and desktop client work exactly as they normally would:
`lore auth login` opens a browser, you sign in with Clerk, and the CLI gets back a token scoped to
whatever repositories Clerk says that user can access.

It ships as a single container and makes no assumptions about where it runs: any container host
works, as long as it can satisfy the [networking requirements](#networking-requirements) below.

## How it works

There are four flows:

1. **Browser login** (HTTP, Express): the `lore` CLI opens `/login?session=...` in a browser. That
   redirects to Clerk's Account Portal for sign-in, which redirects back to `/callback`, which runs
   Clerk's JS SDK client-side to read the newly-created session and posts the token to
   `/callback/complete`. The bridge verifies it with Clerk, looks up the user's `publicMetadata`
   for their granted resources, and mints a Lore-compatible JWT.
2. **CLI polling** (gRPC): the `lore` CLI calls `StartAuthSession` to get the `login_url` above and
   a `session_code`, opens the browser, then polls `GetAuthSession` until the token from step 1
   shows up. `LookupUserPermissions`/`CheckUserPermission` are used afterward by the Lore server
   itself (not the CLI directly) to authorize repository operations against the token's claims.
3. **Repository-scoped connections** (gRPC, `UrcAuthApi.ExchangeUserTokenForMultiresourceToken`):
   any operation that connects to a *specific* repository (`clone`, `push`, `pull`, not just
   listing) has the client exchange its broad login token for one scoped to that repository
   before it can open storage/revision/lock connections (`lore-transport/src/auth/exchange.rs`).
   Skipping this RPC doesn't break login or listing, but breaks every operation that actually
   touches repository content, with a misleading `authorization header required` error that looks
   like a missing-credential problem rather than a missing-RPC one.
4. **Repository creation** (gRPC, `ucs.auth.RebacApi`): when a user creates a new repository, the
   Lore server calls back into a *different* gRPC service (`RebacApi.CreateResource`, not
   `UrcAuthApi`) to register them as its owner. Since Clerk's `publicMetadata` is the only place
   resource grants live here, "creating a resource" means appending an entry to the creating user's
   own metadata. This is what makes newly created repositories show up in `lore repository list`
   automatically, without manually editing Clerk metadata each time; that manual step is only
   needed for granting access to repositories someone *else* created.

Grants are read from Clerk on every authorization call rather than from the caller's token, so
adding or revoking access takes effect on the next operation: no re-login, and no waiting for a
token to expire. The `resources` claim on a token is only a snapshot from the moment it was
minted; `ExchangeUserTokenForMultiresourceToken` refreshes it, which is what lets a
just-created repository be cloned in the same session.

All of it runs in one process (`src/httpServer.ts` and `src/grpcServer.ts`), but the HTTP and gRPC
sides have very different networking requirements, which is the main source of deployment
complexity; see below.

### Why there's a Caddy in front of the gRPC server

Two constraints apply to the gRPC endpoint, and most platform load balancers satisfy at most one:

- **TLS is mandatory.** The `lore` client only recognizes `https` and `ucs-auth` for this address,
  and both initiate a TLS handshake unconditionally, confirmed by testing against the real binary.
  A plaintext gRPC listener is unreachable, not merely insecure.
- **HTTP/2 must survive end to end.** Native gRPC is HTTP/2. Any hop that downgrades to HTTP/1.1
  breaks it: `@grpc/grpc-js` speaks HTTP/2 only, with no HTTP/1.1 fallback. Plenty of L7 proxies do
  exactly this downgrade when forwarding to a backend, and the resulting failure surfaces as a
  generic 502 rather than anything protocol-specific.

A raw L4/TCP passthrough preserves HTTP/2 but adds no TLS. A typical L7 HTTP proxy adds TLS but may
break HTTP/2. So by default the bundled [Caddy](https://caddyserver.com) covers both: it terminates
TLS itself and forwards to `grpc-js` over `h2c` (HTTP/2 cleartext) inside the container, preserving
native gRPC framing, and it obtains and renews its own certificate via a Let's Encrypt DNS-01
challenge: no manual certificate management, ever.

If your edge *does* support gRPC natively (e.g. an AWS ALB gRPC target group with an ACM
certificate), you can skip Caddy entirely; see [option B](#grpc-endpoint) below.

The HTTP side has neither problem: Express is HTTP/1.1-native, so any ordinary load balancer or
reverse proxy in front of it is fine.

### Why the HTTP side must live on a subdomain of Clerk's primary domain

`/callback` runs Clerk's JS SDK client-side to read the session Clerk's Account Portal just
created. That only works if the browser already has Clerk's session cookie for that origin.
Clerk's **satellite domains** feature (for sharing sessions across unrelated domains) requires a
paid plan. The workaround used here: serve the bridge's HTTP side from a **subdomain of Clerk's own
primary domain** (e.g. `lore-auth.yourcompany.com`, where `yourcompany.com` is already Clerk's
primary domain). Clerk's session cookie is scoped to the whole primary domain, so any subdomain of
it receives the cookie automatically: no satellite configuration, no paid plan required.

This rules out serving the HTTP side from a platform-assigned hostname on an unrelated domain. It
has to be a domain you control, under whatever domain Clerk's Account Portal already uses.

## Prerequisites

- A [Lore server](https://github.com/EpicGames/lore) already deployed (this bridge replaces its
  default auth, it doesn't replace the server itself).
- A [Clerk](https://clerk.com) application, with a **custom primary domain** already verified
  (Dashboard → Domains), not Clerk's default `*.accounts.dev` domain. Clerk's free Hobby plan
  covers everything here: custom domains are included, and serving the bridge from a subdomain of
  the primary domain is what avoids satellite domains, the one paid feature this would otherwise
  need.
- Somewhere to run a container, satisfying the networking requirements below.
- DNS you control for both hostnames. If you use the bundled Caddy, the gRPC hostname's zone must
  be on [Cloudflare](https://cloudflare.com), or swap the `caddy-dns` plugin in the `Dockerfile`
  for [your provider's](https://github.com/caddy-dns) and adjust the `Caddyfile` accordingly.
- The `lore` CLI, for testing.

## Networking requirements

The container exposes two independent endpoints.

### HTTP endpoint

Serves `/login`, `/callback`, and `/.well-known/jwks.json` on `PORT` (default `8080`). Plain
HTTP/1.1, so any load balancer or reverse proxy works, and TLS can be terminated anywhere upstream.

Must be reachable at a **subdomain of Clerk's primary domain** over HTTPS; see
[why](#why-the-http-side-must-live-on-a-subdomain-of-clerks-primary-domain).

### gRPC endpoint

Pick one:

**Option A: bundled Caddy terminates TLS (default).** Expose `CADDY_GRPC_PORT` (default `8443`)
through an **L4/TCP passthrough**: an AWS NLB, a plain TCP proxy, a published container port.
Anything that forwards bytes without interpreting them. Caddy handles TLS and certificates itself,
so this path needs `GRPC_DOMAIN`, `CF_API_TOKEN`, and a [persistent volume](#persistent-storage).

**Option B: your edge terminates TLS and speaks gRPC.** If your load balancer supports gRPC
natively over end-to-end HTTP/2 (e.g. an AWS ALB gRPC target group with an ACM certificate), point
it at `GRPC_PORT` (default `50051`) instead and set `GRPC_HOST=0.0.0.0` so the listener is
reachable from outside the container. Caddy, `GRPC_DOMAIN`, `CF_API_TOKEN`, and the volume are all
unnecessary in this mode.

Either way, the client must reach it over TLS at a hostname you control.

### Persistent storage

Only needed for option A. Caddy stores its ACME account and certificates under `$XDG_DATA_HOME`
(set to `/data` in the `Dockerfile`). Mount a persistent volume there. Without it, an ephemeral
container filesystem means every redeploy requests a brand-new certificate, and Let's Encrypt's
duplicate-certificate limit (5 per exact hostname set per week) is reached quickly.

## Setup

### 1. Build and run the container

The included `Dockerfile` builds the app plus a custom Caddy with the Cloudflare DNS plugin
compiled in. Deploy it however you normally deploy containers.

### 2. Set environment variables

See [Environment variables](#environment-variables) for the full reference.

```
CLERK_SECRET_KEY=sk_live_...
CLERK_PUBLISHABLE_KEY=pk_live_...
CLERK_ACCOUNT_PORTAL_URL=https://accounts.yourcompany.com
PUBLIC_HTTP_BASE_URL=https://lore-auth.yourcompany.com
LORE_SERVER_HOSTNAME=lore.yourcompany.com
LORE_SERVER_ENV=local
SIGNING_KEY_PEM=<output of: openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt>
PORT=8080
GRPC_PORT=50051
CADDY_GRPC_PORT=8443
GRPC_DOMAIN=lore-auth-grpc.yourcompany.com
CF_API_TOKEN=<see step 4>
```

### 3. Wire up DNS

- `PUBLIC_HTTP_BASE_URL`'s hostname → your HTTP endpoint. Must be a subdomain of Clerk's primary
  domain.
- `GRPC_DOMAIN` → your gRPC endpoint. Unlike the HTTP side this has no relationship to Clerk; it
  can be any domain you control DNS for.

### 4. Create a Cloudflare API token (option A only)

Cloudflare Dashboard → **My Profile → API Tokens → Create Token**, custom policy:

- `Zone`: `Read`
- `DNS`: `Edit`

Both scoped to the zone containing `GRPC_DOMAIN`. **Both permission categories are required**:
`Zone:Read` alone lets Caddy find the zone but not manage records in it, and fails with an
authentication-looking error that's actually a missing-permission error.

### 5. Point your Lore server at the bridge

On the **Lore server** (not the bridge):

```
LORE__SERVER__AUTH__JWT_ISSUER=https://lore-auth.yourcompany.com
LORE__SERVER__AUTH__JWK__ENDPOINT=https://lore-auth.yourcompany.com/.well-known/jwks.json
LORE__ENVIRONMENT__ENDPOINT__AUTH_URL=https://lore-auth-grpc.yourcompany.com:<public gRPC port>
```

Use the `https://` scheme on `AUTH_URL`, not `ucs-auth://`. The Lore server's own auth client
(`lore-server/src/authnz/auth.rs`) only enables TLS when the URL literally starts with `https://`;
with any other scheme it attempts a plaintext connection and fails immediately. The `lore` CLI
accepts both, so this bites only on the server side.

Leave `LORE__SERVER__AUTH__JWT_AUDIENCE` unset unless you have a reason to set it; if you do set
it, the bridge's `LORE_SERVER_JWT_AUDIENCE` must match one of its values.

### 6. Grant users access

In Clerk Dashboard → **Users** → a user → **public metadata**:

```json
{ "resources": [{ "partition": "<repository-id>", "permissions": ["read", "write"] }] }
```

`partition` is the 32-hex-character Lore repository ID, not its name. `"*"` grants every
repository: loreserver treats the resulting `urc-*` as a wildcard for content operations, but a
wildcard can't be enumerated, so `lore repository list` shows only explicitly-granted repositories.

Lore publishes no list of permission values; these are the ones its source actually checks
(`lore-server/src/grpc/mod.rs`): `read`/`write` are implicit once a resource is granted at all,
`owner`/`admin` gate repository administration, `obliterate` gates obliterate, and `migrate` gates
lock administration.

Repositories a user creates themselves are added here automatically (see flow 4 above).

**Size limit.** Clerk caps a user's metadata at **8KB across public, private and unsafe combined**.
Each grant is roughly 80–110 bytes depending on how many permissions it lists, so a user tops out
around **70–110 repositories**, fewer if you store anything else in their metadata. A `"*"`
wildcard grant is one entry regardless of repository count, so it's the way to give someone broad
access without consuming the budget. Past that ceiling you'd need grants in a real store (DynamoDB,
Postgres) rather than Clerk metadata. If a write does fail, `RebacApi.CreateResource` reports it as
`UNAVAILABLE` naming the cap, rather than as an authentication error.

### 7. Verify

```bash
# JWKS endpoint should return one RSA key:
curl https://lore-auth.yourcompany.com/.well-known/jwks.json

# gRPC endpoint should complete a TLS handshake presenting a real (production, not
# staging) Let's Encrypt certificate for GRPC_DOMAIN:
openssl s_client -connect lore-auth-grpc.yourcompany.com:<public gRPC port>

# End to end:
lore auth login grpcs://lore.yourcompany.com:<port>
lore repository list grpcs://lore.yourcompany.com:<port>
```

`lore auth login` should open a browser, take you through Clerk sign-in, and report success back
in the terminal.

## Environment variables

| Variable | Where | Description |
|---|---|---|
| `CLERK_SECRET_KEY` | Bridge | Clerk Dashboard → API Keys |
| `CLERK_PUBLISHABLE_KEY` | Bridge | Clerk Dashboard → API Keys |
| `CLERK_ACCOUNT_PORTAL_URL` | Bridge | Clerk Dashboard → Account Portal, no trailing slash |
| `PUBLIC_HTTP_BASE_URL` | Bridge | This service's own public URL, **with `https://` scheme**. Also used as the `iss` claim on minted tokens; must match `LORE__SERVER__AUTH__JWT_ISSUER` on the Lore server exactly |
| `LORE_SERVER_HOSTNAME` | Bridge | Bare hostname (no scheme, no port) of your Lore server. Used as the `aud` claim; must exactly match the host you pass to `lore auth login`, or the CLI rejects the token locally |
| `LORE_SERVER_ENV` | Bridge | Must match the Lore server's own `--env`/`LORE_ENV` (default `local`). Required on the JWT; loreserver's `AuthorizationToken` struct fails to decode the token at all without it. Its value doesn't appear to be checked against anything, just required to be present |
| `LORE_SERVER_JWT_AUDIENCE` | Bridge | Only matters if the Lore server has `[server.auth] jwt_audience` configured. When set, this must match one of those values (default `lore-service`); it's carried alongside `LORE_SERVER_HOSTNAME` in `aud` since the CLI and the server each require a different value there |
| `SIGNING_KEY_PEM` | Bridge | RSA private key (PKCS8 PEM) for signing tokens. Must stay stable across restarts; an ephemeral key (the fallback if unset) invalidates all outstanding tokens on every redeploy |
| `PORT` | Bridge | Express's port. Default `8080` |
| `GRPC_PORT` | Bridge | `grpc-js`'s port. Default `50051` |
| `GRPC_HOST` | Bridge | Bind address for `grpc-js`. Default `127.0.0.1`, correct when Caddy runs in the same container. Set `0.0.0.0` when Caddy runs as a separate container, or when your edge talks to `GRPC_PORT` directly (option B); otherwise connections are refused while the HTTP side keeps working, which reads as a TLS problem rather than a bind-address one |
| `CADDY_GRPC_PORT` | Bridge | Caddy's public-facing port. Default `8443`. Option A only |
| `GRPC_DOMAIN` | Bridge | Hostname Caddy serves TLS for and obtains a certificate for. Option A only |
| `CF_API_TOKEN` | Bridge | Cloudflare token, scoped to `Zone:Read` + `DNS:Edit` on `GRPC_DOMAIN`'s zone. Option A only |
| `LORE__SERVER__AUTH__JWT_ISSUER` | Lore server | Must equal `PUBLIC_HTTP_BASE_URL` |
| `LORE__SERVER__AUTH__JWK__ENDPOINT` | Lore server | `<PUBLIC_HTTP_BASE_URL>/.well-known/jwks.json` |
| `LORE__ENVIRONMENT__ENDPOINT__AUTH_URL` | Lore server | `https://<GRPC_DOMAIN>:<public gRPC port>`. Must use the `https://` scheme; see [step 5](#5-point-your-lore-server-at-the-bridge) |

## Troubleshooting

**Crash loop with `EADDRINUSE` on startup.** `PORT` and `GRPC_PORT` (or `CADDY_GRPC_PORT`) resolved
to the same value. Some platforms inject their own `PORT`, which can collide with a manually-set
port. Pin all of them explicitly to distinct values.

**Login completes in the browser but the CLI never sees it / `window.Clerk.session` is empty on
`/callback`.** The bridge's HTTP side isn't on a subdomain of Clerk's primary domain; see
[why](#why-the-http-side-must-live-on-a-subdomain-of-clerks-primary-domain).

**`openssl s_client` against the gRPC endpoint: `wrong version number`.** Nothing in that path is
speaking TLS. On option A, check the passthrough targets `CADDY_GRPC_PORT` and not `GRPC_PORT`.

**`openssl s_client` connects but hangs with `unexpected eof`.** The connection reaches something,
but nothing is listening on the target port inside the container. Usually the passthrough points at
a port nothing serves, or `GRPC_HOST` is loopback while the listener needs to be reachable from
outside the container.

**gRPC calls fail with 502, or your proxy's logs show the gRPC method path (e.g.
`/epic_urc.UrcAuthApi/StartAuthSession`) returning 502/404.** The gRPC endpoint is behind an L7
proxy that downgrades to HTTP/1.1 before the container. Native gRPC needs end-to-end HTTP/2; use an
L4/TCP passthrough to Caddy (option A) or a load balancer with real gRPC support (option B).

**Caddy logs show `no memory of presenting a DNS record` / Cloudflare `HTTP 403` or `401`.** The
Cloudflare token is invalid or missing a permission. Verify it directly:
`curl -H "Authorization: Bearer $CF_API_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify`.
If that's fine, check the token has **both** `Zone:Read` and `DNS:Edit`; one without the other
fails with an authentication-looking error even though the real problem is scope.

**Caddy's logs mention `acme-staging-v02.api.letsencrypt.org`.** Not itself the bug: Caddy falls
back to Let's Encrypt's staging CA automatically after repeated failures, to avoid burning your
production rate limit while you fix the real problem. Fix whatever's actually failing (see above)
and it'll go back to issuing a production certificate.

**Caddy's certificate cache resets on every deploy / Let's Encrypt rate limit
(`too many certificates ... already issued for this exact set of identifiers`).** No persistent
volume is mounted at `/data`; see [persistent storage](#persistent-storage). If you're already
rate-limited, either wait out the 7-day window or point `GRPC_DOMAIN` at a fresh hostname; the
limit is keyed to the exact set of names in the certificate.

**Lore server logs `transport error` / `broken pipe` when calling the auth service.**
`LORE__ENVIRONMENT__ENDPOINT__AUTH_URL` isn't using the `https://` scheme. The Lore server only
enables TLS for that literal prefix; see [step 5](#5-point-your-lore-server-at-the-bridge).

**`lore auth login` opens a browser but the OS says it can't find the URL / the CLI errors
`ExitStatus(1)` while opening it.** `PUBLIC_HTTP_BASE_URL` is missing its `https://` scheme: the
login URL is built directly from it, and without a scheme the OS treats it as a filename.

**`JWT 'aud' does not specify remote domain '...'`.** `LORE_SERVER_HOSTNAME` doesn't exactly match
the host you passed to `lore auth login`. It needs to be the bare hostname: no scheme, no port.

**Lore server logs `Unexpected error decoding JWT AuthN token ... Error(InvalidAudience)`.**
The Lore server has `[server.auth] jwt_audience` configured and the token's `aud` doesn't contain
any of those values. Set `LORE_SERVER_JWT_AUDIENCE` on the bridge to match. This is independent of
`LORE_SERVER_HOSTNAME`; both end up in `aud` together, since the CLI's own local check and the
server's `jwt_audience` check each require a different value there.

**A change to token claims doesn't take effect: old behavior persists even after
`lore auth login`.** The client caches tokens on disk in `tokens.toml` (under the per-user local
config dir, e.g. `%LOCALAPPDATA%\Epic Games\lore\config\` on Windows, or wherever `LORE_AUTH_PATH`
points). Crucially, **repository-scoped authz tokens are keyed `{auth_url}/{repository_id}`**, so
`lore auth logout` against the *server* URL doesn't clear them, and `login` only refreshes the
authn token. A still-valid cached authz token is reused without ever calling the auth service
(`lore-transport/src/auth/exchange.rs` returns early on a cache hit), so the bridge sees no request
at all. To force a clean exchange, delete `tokens.toml` or point the store somewhere fresh:

```
LORE_AUTH_PATH=/some/empty/dir
```

This only matters when token *contents* change; a normal deployment never hits it.

## Callback pages

The browser-facing pages are plain static files under `public/`, with no server-side templating:

```
public/callback.html         served by GET /callback (behind the session guard)
public/session-error.html    served by /login and /callback on an unknown/expired session
public/assets/callback.js    the sign-in logic
public/assets/styles.css     shared styling
```

Neither dynamic value needs to be interpolated into the markup: the session code is already in the
query string, and the Clerk publishable key (public by design) comes from `GET /callback/config`.
That keeps the HTML and JS editable as real files, and leaves no hand-rolled HTML escaping in the
request path.

`clerk-js` is **self-hosted** rather than loaded from a public CDN: this page reads the user's
Clerk session, so it shouldn't depend on a third-party origin for the script that does it. It's
served from the installed `@clerk/clerk-js` package under `/vendor/clerk`. The whole `dist`
directory is exposed rather than the single entry file because `clerk.browser.js` is code-split and
resolves its lazily-loaded chunks relative to its own script URL.

Note that `tsc` only emits compiled TypeScript, so `public/` is copied into the image separately by
the `Dockerfile`, the same way `proto/` is.

## Local development

```bash
npm install
cp .env.example .env   # fill in real values; SIGNING_KEY_PEM and the Caddy/Cloudflare
                        # vars can be left unset for local dev; TLS/Caddy only matter
                        # in production, plaintext gRPC works fine on localhost
npm run dev
```

`scripts/grpc-client-test.mjs` exercises the gRPC API directly against a locally running instance;
`scripts/mint-test-token.mjs` mints a token without going through Clerk, useful for testing
`LookupUserPermissions` in isolation.

The login pages can be exercised without Clerk credentials: any `PUBLIC_HTTP_BASE_URL` and
`CLERK_*` placeholder values are enough to serve `/callback` and the error pages, since the flow
only reaches Clerk once the page's JavaScript runs.
