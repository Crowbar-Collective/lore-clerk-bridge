# lore-clerk-bridge

A bridge service developed by Crowbar Collective that lets [Lore](https://github.com/EpicGames/lore) authenticate
users through [Clerk](https://clerk.com). It implements Lore's
`UrcAuthApi` gRPC service backed by a Clerk sign-in flow, so the `lore` CLI and desktop client work exactly as they normally would —
`lore auth login` opens a browser, you sign in with Clerk, and the CLI gets back a token scoped to
whatever repositories Clerk says that user can access.

## How it works

There are two independent flows:

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
   any operation that connects to a *specific* repository — `clone`, `push`, `pull`, not just
   listing — has the client exchange its broad login token for one scoped to that repository
   before it can open storage/revision/lock connections (`lore-transport/src/auth/exchange.rs`).
   Skipping this RPC doesn't break login or listing, but breaks every operation that actually
   touches repository content, with a misleading `authorization header required` error that looks
   like a missing-credential problem rather than a missing-RPC one.
4. **Repository creation** (gRPC, `ucs.auth.RebacApi`): when a user creates a new repository, the
   Lore server calls back into a *different* gRPC service — `RebacApi.CreateResource`, not
   `UrcAuthApi` — to register them as its owner. Since Clerk's `publicMetadata` is the only place
   resource grants live here, "creating a resource" means appending an entry to the creating user's
   own metadata. This is what makes newly created repositories show up in `lore repository list`
   automatically going forward, without manually editing Clerk metadata each time — that manual
   step is only needed for granting access to repositories someone *else* created.

Both flows are implemented in one service (`src/httpServer.ts` and `src/grpcServer.ts`), but they
have very different networking requirements, which is the main source of complexity here — see
below.

### Why there's a Caddy in front of the gRPC server

Lore's discovered auth endpoint requires TLS (confirmed by testing against the real `lore` CLI —
it only recognizes `https` and `ucs-auth` schemes for this address, and both initiate a TLS
handshake unconditionally). That's a problem on Railway specifically:

- Railway's **TCP Proxy** is a raw byte passthrough — no TLS at all, but it *does* preserve native
  HTTP/2 framing, which raw gRPC needs.
- Railway's **HTTP-domain** feature (custom domains, `*.up.railway.app`) terminates TLS
  automatically, but proxies to the container over HTTP/1.1 internally — which breaks a native
  gRPC server (`@grpc/grpc-js` only speaks HTTP/2, no HTTP/1.1 fallback).

Neither option alone works, so the gRPC server sits behind [Caddy](https://caddyserver.com),
reachable via a raw TCP Proxy. Caddy terminates TLS itself and forwards decrypted traffic to
`grpc-js` over local `h2c` (HTTP/2 cleartext), preserving native gRPC framing end-to-end. Caddy
also handles certificate issuance and renewal automatically via a Let's Encrypt DNS-01 challenge
against Cloudflare — no manual certificate management, ever.

The HTTP side (`/login`, `/callback`, `/.well-known/jwks.json`) doesn't have this problem — Express
is HTTP/1.1-native, so it works fine behind Railway's normal HTTP-domain routing.

### Why the HTTP side must live on a subdomain of Clerk's primary domain

`/callback` runs Clerk's JS SDK client-side to read the session Clerk's Account Portal just
created. That only works if the browser already has Clerk's session cookie for that origin.
Clerk's **satellite domains** feature (for sharing sessions across unrelated domains) requires a
paid plan. The workaround used here: deploy the bridge's HTTP side on a **subdomain of Clerk's own
primary domain** (e.g. `lore-auth.yourcompany.com`, where `yourcompany.com` is already Clerk's
primary domain). Clerk's session cookie is scoped to the whole primary domain, so any subdomain of
it receives the cookie automatically — no satellite configuration, no paid plan required.

This means the bridge **cannot** be deployed on Railway's own `*.up.railway.app` domain for the
HTTP side — it has to be a custom domain under whatever domain Clerk's Account Portal is already
using.

## Prerequisites

- A [Lore server](https://github.com/snowfall-games/lore-railway) already deployed (this bridge
  replaces its default auth, it doesn't replace the server itself).
- A [Clerk](https://clerk.com) application, with a **custom primary domain** already verified
  (Dashboard → Domains) — not Clerk's default `*.accounts.dev` domain.
- A [Railway](https://railway.com) account.
- DNS for your domain hosted on [Cloudflare](https://cloudflare.com) (used for automatic TLS
  certificate issuance — see below for why).
- The `lore` CLI, for testing.

## Setup

### 1. Deploy this repo to Railway

Fork this repo, then in Railway: **New → GitHub Repo** → select your fork. Railway auto-detects
the included `Dockerfile` (needed because this service runs both Node and a custom Caddy build —
Nixpacks alone can't do that).

### 2. Set environment variables

On the service, set (see [Environment variables](#environment-variables) below for details on
each):

```
CLERK_SECRET_KEY=sk_live_...
CLERK_PUBLISHABLE_KEY=pk_live_...
CLERK_ACCOUNT_PORTAL_URL=https://accounts.yourcompany.com
PUBLIC_HTTP_BASE_URL=https://lore-auth.yourcompany.com
LORE_SERVER_HOSTNAME=your-lore-server.up.railway.app
LORE_SERVER_ENV=local
SIGNING_KEY_PEM=<output of: openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt>
PORT=8080
GRPC_PORT=50051
CADDY_GRPC_PORT=8443
GRPC_DOMAIN=lore-auth-grpc.yourcompany.com
CF_API_TOKEN=<see step 5>
```

### 3. Set up HTTP networking (Clerk side)

**Settings → Networking → Custom Domain** → add a subdomain of Clerk's primary domain, e.g.
`lore-auth.yourcompany.com`, targeting port `8080`. Add the CNAME Railway gives you at your DNS
provider. This **must** be a subdomain of Clerk's primary domain — see
[why](#why-the-http-side-must-live-on-a-subdomain-of-clerks-primary-domain) above.

### 4. Set up gRPC networking

**Settings → Networking → TCP Proxy** → target port `8443` (Caddy, not the raw gRPC port). Railway
assigns a `host:port` — note it, you'll need it in step 6.

Add a CNAME at your DNS provider: `GRPC_DOMAIN` (e.g. `lore-auth-grpc.yourcompany.com`) → the TCP
Proxy host from Railway. Unlike the HTTP side, this domain has no relationship to Clerk — it can
be any domain you control DNS for.

### 5. Create a Cloudflare API token

Cloudflare Dashboard → **My Profile → API Tokens → Create Token**, custom policy:

- `Zone` — `Read`
- `DNS` — `Edit`

Both scoped to the zone containing `GRPC_DOMAIN`. **Both permission categories are required** —
`Zone:Read` alone lets Caddy find the zone but not manage records in it, and will fail silently
with an authentication-looking error that's actually a missing-permission error.

Set the token as `CF_API_TOKEN` on the bridge service (step 2).

### 6. Point your Lore server at the bridge

On the **Lore server** (not the bridge), set:

```
LORE__SERVER__AUTH__JWT_ISSUER=https://lore-auth.yourcompany.com
LORE__SERVER__AUTH__JWK__ENDPOINT=https://lore-auth.yourcompany.com/.well-known/jwks.json
LORE__ENVIRONMENT__ENDPOINT__AUTH_URL=ucs-auth://lore-auth-grpc.yourcompany.com:<TCP proxy port from step 4>
```

Leave `LORE__SERVER__AUTH__JWT_AUDIENCE` unset — the bridge sets `aud` on minted tokens itself
(from `LORE_SERVER_HOSTNAME`), and the Lore server doesn't need to separately validate it.

### 7. Grant users access

In Clerk Dashboard → **Users** → a user → **public metadata**:

```json
{ "resources": [{ "partition": "<repo-partition-id>", "permissions": ["read", "write"] }] }
```

### 8. Verify

```bash
# JWKS endpoint should return one RSA key:
curl https://lore-auth.yourcompany.com/.well-known/jwks.json

# gRPC endpoint should complete a TLS handshake showing a real (production, not
# staging) Let's Encrypt cert for GRPC_DOMAIN:
openssl s_client -connect lore-auth-grpc.yourcompany.com:<TCP proxy port>

# End to end:
lore auth login grpc://your-lore-server.up.railway.app:<port>
```

`lore auth login` should open a browser, take you through Clerk sign-in, and report success back
in the terminal.

## Environment variables

| Variable | Where | Description |
|---|---|---|
| `CLERK_SECRET_KEY` | Bridge | Clerk Dashboard → API Keys |
| `CLERK_PUBLISHABLE_KEY` | Bridge | Clerk Dashboard → API Keys |
| `CLERK_ACCOUNT_PORTAL_URL` | Bridge | Clerk Dashboard → Account Portal, no trailing slash |
| `PUBLIC_HTTP_BASE_URL` | Bridge | This service's own public URL, **with `https://` scheme**. Also used as the `iss` claim on minted tokens — must match `LORE__SERVER__AUTH__JWT_ISSUER` on the Lore server exactly |
| `LORE_SERVER_HOSTNAME` | Bridge | Bare hostname (no scheme, no port) of your Lore server. Used as the `aud` claim — must exactly match the host you pass to `lore auth login`, or the CLI rejects the token locally |
| `LORE_SERVER_ENV` | Bridge | Must match the Lore server's own `--env`/`LORE_ENV` (default `local`). Required on the JWT — loreserver's `AuthorizationToken` struct fails to decode the token at all without it. Its value doesn't appear to be checked against anything, just required to be present |
| `LORE_SERVER_JWT_AUDIENCE` | Bridge | Only matters if the Lore server has `[server.auth] jwt_audience` configured — check its config for `LORE__SERVER__AUTH__JWT_AUDIENCE`. When set, this must match one of those values (default `lore-service`); it's carried alongside `LORE_SERVER_HOSTNAME` in `aud` since the CLI and the server each require a different value there |
| `SIGNING_KEY_PEM` | Bridge | RSA private key (PKCS8 PEM) for signing tokens. Must stay stable across restarts — an ephemeral key (the fallback if unset) invalidates all outstanding tokens on every redeploy |
| `PORT` | Bridge | Express's port, routed to by Railway's HTTP-domain feature. Default `8080` |
| `GRPC_PORT` | Bridge | `grpc-js`'s port, loopback-only — only Caddy talks to it. Default `50051` |
| `CADDY_GRPC_PORT` | Bridge | Caddy's public-facing port, targeted by the Railway TCP Proxy. Default `8443` |
| `GRPC_DOMAIN` | Bridge | Domain Caddy serves TLS for and gets a cert for. Must have a CNAME to the TCP Proxy host |
| `CF_API_TOKEN` | Bridge | Cloudflare token, scoped to `Zone:Read` + `DNS:Edit` on `GRPC_DOMAIN`'s zone |
| `LORE__SERVER__AUTH__JWT_ISSUER` | Lore server | Must equal `PUBLIC_HTTP_BASE_URL` |
| `LORE__SERVER__AUTH__JWK__ENDPOINT` | Lore server | `<PUBLIC_HTTP_BASE_URL>/.well-known/jwks.json` |
| `LORE__ENVIRONMENT__ENDPOINT__AUTH_URL` | Lore server | `ucs-auth://<GRPC_DOMAIN>:<TCP proxy port>` |

## Troubleshooting

**Deploy crash-loops with `EADDRINUSE` on startup.** `PORT` and `GRPC_PORT` (or `CADDY_GRPC_PORT`)
resolved to the same value — usually because Railway auto-assigns its own `PORT` and it happened
to collide with a manually-set `GRPC_PORT`. Pin both explicitly to distinct values.

**Login completes in the browser but the CLI never sees it / `window.Clerk.session` is empty on
`/callback`.** The bridge's HTTP side isn't on a subdomain of Clerk's primary domain — see
[why](#why-the-http-side-must-live-on-a-subdomain-of-clerks-primary-domain) above. It cannot be on
Railway's own domain.

**`openssl s_client` against the gRPC domain: `wrong version number`.** Something in front of the
gRPC server isn't speaking TLS — check the Railway TCP Proxy is targeting Caddy's port
(`CADDY_GRPC_PORT`), not `GRPC_PORT` directly.

**`lore auth login` fails with a 502-flavored error, or Railway's network log shows the gRPC method
path (e.g. `/epic_urc.UrcAuthApi/StartAuthSession`) returning 502/404.** The gRPC domain is routed
through Railway's HTTP-domain feature instead of a TCP Proxy. Native gRPC needs the raw TCP Proxy
+ Caddy setup described above — Railway's HTTP-domain routing can't carry it.

**Caddy logs show `no memory of presenting a DNS record` / Cloudflare `HTTP 403` or `401`.** The
Cloudflare token is invalid or missing a permission. Verify it directly:
`curl -H "Authorization: Bearer $CF_API_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify`.
If that's fine, check the token has **both** `Zone:Read` and `DNS:Edit` — one without the other
fails with an authentication-looking error even though the real problem is scope.

**Caddy's logs mention `acme-staging-v02.api.letsencrypt.org`.** Not itself the bug — Caddy falls
back to Let's Encrypt's staging CA automatically after repeated failures, to avoid burning your
production rate limit while you fix the real problem. Fix whatever's actually failing (see the
Cloudflare item above) and it'll go back to issuing a real production cert.

**`lore auth login` opens a browser but Windows says it can't find the URL / the CLI errors
`ExitStatus(1)` while opening the URL.** `PUBLIC_HTTP_BASE_URL` is missing its `https://` scheme —
the login URL gets built directly from it, and without a scheme Windows tries to treat it as a
filename instead of a URL to open.

**`JWT 'aud' does not specify remote domain '...'`.** `LORE_SERVER_HOSTNAME` doesn't exactly match
the host you passed to `lore auth login`. It needs to be the bare hostname — no scheme, no port.

**A change to token claims doesn't take effect — old behavior persists even after
`lore auth login`.** The client caches tokens on disk in `tokens.toml` (under the per-user local
config dir — e.g. `%LOCALAPPDATA%\Epic Games\lore\config\` on Windows — or wherever `LORE_AUTH_PATH`
points). Crucially, **repository-scoped authz tokens are keyed `{auth_url}/{repository_id}`**, so
`lore auth logout` against the *server* URL doesn't clear them, and `login` only refreshes the
authn token. A still-valid cached authz token is reused without ever calling the auth service
(`lore-transport/src/auth/exchange.rs` returns early on a cache hit), so the bridge sees no request
at all. To force a clean exchange, either delete `tokens.toml` or point the store somewhere fresh:

```
$env:LORE_AUTH_PATH = "C:\some\empty\dir"
```

This only matters when token *contents* change — a normal deployment never hits it.

**Everything authenticates, but repository content operations fail with `Unauthorized` /
`The caller does not have permission to execute the specified operation`, with nothing useful in
the Lore server logs.** The JWT's `resources` claim must use loreserver's own field names —
`{"resource_id": "urc-<id>", "permission": [...]}` — not the `{partition, permissions}` shape
Clerk metadata stores. The bridge converts between them (`toWireResources`/`fromWireResources` in
[src/signing.ts](src/signing.ts)). This one fails *silently*: loreserver's `verify_token_internal`
wraps the `AuthorizationToken` decode in `if let Ok(..)`, so a malformed `resources` claim just
falls through to the `JWTUserInfo` fallback, which has no `resources` field and yields
`resources: None` — after which every authorization check denies with a bare "Unauthorized" and no
decode error is ever logged. Note that `repository list`/`create` keep working in this state,
because they consult the bridge's `LookupUserPermissions` over gRPC rather than reading the claim.

**`lore repository list`/`create` work, but `clone` (or push/pull) fails repeatedly with
`authorization header required` / `Get request failed` / `channel closed`, eventually giving up
with `Repository not found`.** Listing and creating don't need a repository-scoped connection;
clone/push/pull do, via `ExchangeUserTokenForMultiresourceToken` (see
[architecture](#how-it-works) above). If this RPC isn't implemented, the client's token exchange
fails silently enough that it still attempts the storage connections, just with no valid
credential attached — the repeated failures and eventual disconnect are a symptom of that, not of
a literally missing header on your end.

**`lore repository create` fails with `The server does not implement the method
/ucs.auth.RebacApi/CreateResource`.** The Lore server calls a second gRPC service (`ucs.auth.RebacApi`,
vendored as `proto/rebac_api.proto`) on repository creation/deletion, separate from `UrcAuthApi`. The
bridge implements both `CreateResource` and `DeleteResource` on the same server/port — if you see
this, the deployed build predates that, or the proto didn't get copied into the Docker image.

**Lore server logs `Unexpected error decoding JWT AuthN token ... Error(InvalidAudience)`.**
The Lore server has `[server.auth] jwt_audience` configured (check its `bucket.toml`/`local.toml`/
`LORE__SERVER__AUTH__JWT_AUDIENCE`) and the token's `aud` doesn't contain any of those values. Set
`LORE_SERVER_JWT_AUDIENCE` on the bridge to match. This is independent of `LORE_SERVER_HOSTNAME` —
both end up in `aud` together, since the CLI's own local check and the server's `jwt_audience`
check each require a different value there.

**Lore server logs `Unexpected error decoding JWT AuthN token ... missing field '<name>'`, and
`lore repository list` (or similar) fails with a permission-denied-flavored error even though
`lore auth login` succeeded.** The Lore server's own `AuthorizationToken` struct requires several
claims beyond the JWT standard ones: `env`, `preferred_username`, and `idp`. `LORE_SERVER_ENV`
covers `env`; the bridge sets `preferred_username` and `idp` itself. If this shows up again after
a Lore server upgrade, check `lore-server/src/auth/jwt.rs`'s `AuthorizationToken` struct for a new
required field — this fails token decoding entirely, before repository authorization is ever
reached, so it can look identical to a permissions problem even though it's unrelated.

**Caddy's certificate cache resets on every deploy / Let's Encrypt rate limit
(`too many certificates ... already issued for this exact set of identifiers`).** Railway's
container filesystem is ephemeral across deploys. Attach a Railway Volume to the bridge service at
mount path `/data` (via the Command Palette or right-click on the project canvas — not under
Settings) so Caddy's cert cache (`XDG_DATA_HOME=/data`, set in the Dockerfile) survives redeploys.
If you're already rate-limited, either wait out the 7-day window or temporarily point `GRPC_DOMAIN`
at a fresh subdomain — Let's Encrypt's limit is keyed to the exact set of domain names in the cert.

## Local development

```bash
npm install
cp .env.example .env   # fill in real values; SIGNING_KEY_PEM and the Caddy/Cloudflare
                        # vars can be left unset for local dev — TLS/Caddy only matter
                        # in production, plaintext gRPC works fine on localhost
npm run dev
```

`scripts/grpc-client-test.mjs` exercises the gRPC API directly against a locally running instance;
`scripts/mint-test-token.mjs` mints a token without going through Clerk, useful for testing
`LookupUserPermissions` in isolation.
