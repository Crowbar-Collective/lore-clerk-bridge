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

interface SigningKeys {
  privateKey: KeyLike;
  publicJwk: JWK;
  kid: string;
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

  const privateKey = await importPKCS8(pem, "RS256");
  const publicJwk = await exportJWK(privateKey);
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
  audience?: string;
  resources: ResourceGrant[];
  ttlSeconds?: number;
  env: string;
  idp?: string;
}): Promise<{ token: string; expiresAt: number }> {
  const { privateKey, kid } = await loadSigningKeys();
  const ttlSeconds = params.ttlSeconds ?? 3600;
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + ttlSeconds;

  // The `lore` CLI's local token decode (lore-revision/src/auth/login.rs) requires
  // `aud` to be structurally present, even though loreserver itself only validates it
  // when jwt_audience is configured server-side (which we're deliberately leaving unset).
  //
  // env, preferred_username, and idp are required (non-Option) fields on loreserver's
  // own AuthorizationToken struct (lore-server/src/auth/jwt.rs) — omitting any of them
  // fails JWT decoding server-side with "missing field '<name>'" before repository
  // authorization is ever reached. Confirmed against the real loreserver's auth logs.
  const token = await new SignJWT({
    resources: params.resources,
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
  return { keys: [publicJwk] };
}

// Used by LookupUserPermissions to authenticate the caller: the CLI presents the
// very token this bridge minted, so verifying against our own public key is enough —
// no round trip back to Clerk needed.
export async function verifyLoreToken(
  token: string
): Promise<{ sub: string; resources: ResourceGrant[] }> {
  const { publicJwk } = await loadSigningKeys();
  const publicKey = await importJWK(publicJwk, "RS256");
  const { payload } = await jwtVerify(token, publicKey);
  return {
    sub: payload.sub ?? "",
    resources: (payload.resources as ResourceGrant[] | undefined) ?? [],
  };
}
