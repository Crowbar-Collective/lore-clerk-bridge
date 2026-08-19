import { generateKeyPairSync } from "node:crypto";
import {
  SignJWT,
  jwtVerify,
  exportJWK,
  importJWK,
  calculateJwkThumbprint,
  importPKCS8,
  type KeyLike,
  type JWK,
} from "jose";

export interface ResourceGrant {
  partition: string;
  permissions: string[];
}

// Two independent readers, two different required values: the CLI's local check
// (lore-credential/src/jwt.rs) needs the Lore server's bare hostname present, and
// loreserver's own [server.auth] jwt_audience check (when configured — confirmed
// against a real server set to jwt_audience = ["lore-service"]) needs its configured
// value present. Both go in since aud accepts an array. Shared by every place that
// mints a token (initial login, and the ExchangeUserTokenForMultiresourceToken re-mint).
export function loreServerAudience(): string[] {
  const hostname = process.env.LORE_SERVER_HOSTNAME;
  if (!hostname) throw new Error("LORE_SERVER_HOSTNAME is required");
  return [hostname, process.env.LORE_SERVER_JWT_AUDIENCE ?? "lore-service"];
}

// Must match the Lore server's own --env / LORE_ENV (default "local") — required on the
// JWT independently of anything this bridge validates.
export function loreServerEnv(): string {
  const env = process.env.LORE_SERVER_ENV;
  if (!env) throw new Error("LORE_SERVER_ENV is required");
  return env;
}

// The `resources` JWT claim is read directly by loreserver's own interceptor, so it has
// to use loreserver's field names (lore-server/src/auth/jwt.rs ResourcePermission), not
// the {partition, permissions} shape Clerk metadata stores. Getting this wrong fails
// silently and confusingly: the AuthorizationToken decode errors, `if let Ok(..)` in
// verify_token_internal swallows it, the JWTUserInfo fallback (which has no `resources`
// field) succeeds instead, and every request is then denied with a bare "Unauthorized"
// and no decode error in the logs.
//
// A "*" partition maps to the literal "urc-*", which loreserver treats natively as a
// wildcard (ResourcePermission::is_wildcard_resource) — so wildcard grants are enforced
// server-side here, unlike the LookupUserPermissions path where we expand them ourselves.
interface WireResourcePermission {
  resource_id: string;
  permission: string[];
}

function toWireResources(resources: ResourceGrant[]): WireResourcePermission[] {
  return resources.map((r) => ({ resource_id: `urc-${r.partition}`, permission: r.permissions }));
}

function fromWireResources(claim: unknown): ResourceGrant[] {
  if (!Array.isArray(claim)) return [];
  return (claim as WireResourcePermission[]).map((r) => ({
    partition: (r.resource_id ?? "").replace(/^urc-/, ""),
    permissions: r.permission ?? [],
  }));
}

interface SigningKeys {
  privateKey: KeyLike;
  publicJwk: JWK;
  kid: string;
}

/**
 * Turns the single-line, backslash-n form the deployment supplies back into a real PEM.
 * Left alone when it already contains real newlines, so a locally supplied key still works.
 */
function normalisePem(pem: string): string {
  const ESCAPED_NEWLINE = String.fromCharCode(92) + "n";
  return pem.includes(ESCAPED_NEWLINE) ? pem.split(ESCAPED_NEWLINE).join("\n") : pem;
}

/** Private JWK members, which must never appear in a published key set. */
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/** Returns a copy carrying only public key material. */
function stripPrivateJwkFields(jwk: JWK): JWK {
  const safe: JWK = { ...jwk };
  for (const field of PRIVATE_JWK_FIELDS) {
    delete (safe as unknown as Record<string, unknown>)[field];
  }
  return safe;
}

let cached: SigningKeys | null = null;

// Lore server fetches/caches signing keys from our JWKS endpoint at startup and
// re-fetches on an unknown key ID, so a stable key across restarts matters —
// generating a fresh one every boot would strand already-issued tokens.
async function loadSigningKeys(): Promise<SigningKeys> {
  if (cached) return cached;

  let pem = process.env.SIGNING_KEY_PEM;
  if (!pem) {
    console.warn(
      "SIGNING_KEY_PEM not set — generating an ephemeral RSA keypair. " +
        "Tokens will stop verifying on the next restart. Set SIGNING_KEY_PEM in production " +
        "(generate with: openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt)."
    );
    const generated = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    pem = generated.privateKey;
  }

  // The deployed .env carries this PEM on a single line with literal backslash-n, because
  // docker compose env files cannot hold embedded newlines (see scripts/start.sh in the
  // lore-aws repo). Nothing accepts that form: jose's importPKCS8 fails it with
  // ERR_OSSL_ASN1_HEADER_TOO_LONG, so it has to be turned back into a real PEM first.
  //
  // Only jose parses it after that. An earlier attempt to derive the public key with Node's
  // createPublicKey failed too, because passing a PKCS8 *private* key as a string makes it
  // decode as SPKI (ERR_OSSL_UNSUPPORTED). Both mistakes took the bridge down; there is
  // deliberately one parser here, and it is the one already used to sign.
  const privateKey = await importPKCS8(normalisePem(pem), "RS256");

  // exportJWK() on a private key returns the *private* JWK, and this value is published at
  // /.well-known/jwks.json - which is how the signing key came to be served publicly. The
  // private members are removed here, and again in getJwks(), because the cost of getting
  // this wrong is the entire signing key.
  const publicJwk = stripPrivateJwkFields(await exportJWK(privateKey));
  const kid = await calculateJwkThumbprint(publicJwk);
  publicJwk.kid = kid;
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";

  cached = { privateKey, publicJwk, kid };
  return cached;
}

export async function signLoreToken(params: {
  userId: string;
  userName: string;
  issuer: string;
  audience?: string | string[];
  resources: ResourceGrant[];
  ttlSeconds?: number;
  env: string;
  idp?: string;
}): Promise<{ token: string; expiresAt: number }> {
  const { privateKey, kid } = await loadSigningKeys();
  const ttlSeconds = params.ttlSeconds ?? 3600;
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + ttlSeconds;

  // aud has two independent, unrelated readers that each need their own value present:
  // the `lore` CLI's local check (lore-credential/src/jwt.rs) requires it to include the
  // bare hostname of the Lore server being connected to, while loreserver itself checks
  // it against its own configured [server.auth] jwt_audience (e.g. "lore-service") when
  // that's set. `aud` accepts an array, and both sides check for membership rather than
  // an exact single value, so both are included rather than picking one.
  //
  // env, preferred_username, and idp are required (non-Option) fields on loreserver's
  // own AuthorizationToken struct (lore-server/src/auth/jwt.rs) — omitting any of them
  // fails JWT decoding server-side with "missing field '<name>'" before repository
  // authorization is ever reached. Confirmed against the real loreserver's auth logs.
  const token = await new SignJWT({
    resources: toWireResources(params.resources),
    name: params.userName,
    preferred_username: params.userName,
    env: params.env,
    idp: params.idp ?? "clerk",
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(params.issuer)
    .setAudience(params.audience ?? "lore-service")
    .setSubject(params.userId)
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .sign(privateKey);

  return { token, expiresAt };
}

export async function getJwks(): Promise<{ keys: JWK[] }> {
  const { publicJwk } = await loadSigningKeys();
  // Stripped again rather than trusted: this endpoint is public and unauthenticated.
  return { keys: [stripPrivateJwkFields(publicJwk)] };
}

// Used by LookupUserPermissions to authenticate the caller: the CLI presents the
// very token this bridge minted, so verifying against our own public key is enough —
// no round trip back to Clerk needed.
export async function verifyLoreToken(
  token: string
): Promise<{ sub: string; name: string; resources: ResourceGrant[] }> {
  const { publicJwk } = await loadSigningKeys();
  const publicKey = await importJWK(publicJwk, "RS256");
  const { payload } = await jwtVerify(token, publicKey);
  return {
    sub: payload.sub ?? "",
    name: (payload.name as string | undefined) ?? "",
    // Back to the internal {partition, permissions} shape the rest of the bridge uses.
    resources: fromWireResources(payload.resources),
  };
}
