import path from "node:path";
import { createHash, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { createSession, deleteSession, getSession } from "./sessionStore.js";
import {
  signLoreToken,
  verifyLoreToken,
  loreServerAudience,
  loreServerEnv,
  loreTokenIssuer,
  type ResourceGrant,
} from "./signing.js";
import {
  ClerkUserNotFound,
  getUserDisplayNames,
  getUserForApiKey,
  getUserGrants,
  grantResource,
  revokeResource,
} from "./clerk.js";
import { apiKeyMatches, apiKeyUserId } from "./apiKeys.js";
import {
  createRateLimiter,
  isTrustedPeer,
  peerAddress,
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW_MS,
} from "./rateLimit.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.join(__dirname, "..", "proto", "auth_api.proto");
const REBAC_PROTO_PATH = path.join(__dirname, "..", "proto", "rebac_api.proto");

const packageDefinition = protoLoader.loadSync([PROTO_PATH, REBAC_PROTO_PATH], {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const proto = grpc.loadPackageDefinition(packageDefinition) as any;
const urcAuthApiService = proto.epic_urc.UrcAuthApi.service;
const rebacApiService = proto.ucs.auth.RebacApi.service;

function requirePublicBaseUrl(): string {
  const url = process.env.PUBLIC_HTTP_BASE_URL;
  if (!url) throw new Error("PUBLIC_HTTP_BASE_URL is required");
  return url.replace(/\/$/, "");
}

function extractBearerToken(metadata: grpc.Metadata): string | undefined {
  const [raw] = metadata.get("authorization");
  if (!raw) return undefined;
  const value = typeof raw === "string" ? raw : raw.toString("utf8");
  return /^Bearer\s+(.+)$/i.exec(value)?.[1];
}

// lore-server's repository_list/repository_authorizer (lore-server/src/authnz/
// repository_authorizer.rs, lore-server/src/grpc/handlers/repository_list.rs) expect
// resource_id values formatted "urc-<repository id>" — Clerk metadata only stores the
// bare partition, so the prefix is added here rather than asking every admin to know it.
function toResourceId(partition: string): string {
  return `urc-${partition}`;
}

// loreserver's own authorization checks (repository_authorizer.rs) do a plain exact
// string match on whatever resource_id we hand back — it has no wildcard logic itself.
// A partition of "*" is our own convention for "every repository"; resolving it to the
// specific resource_id being asked about happens here, not on loreserver's side.
function matchesResource(partition: string, resourceId: string): boolean {
  return partition === "*" || toResourceId(partition) === resourceId;
}

class RpcError extends Error {
  constructor(
    readonly code: grpc.status,
    message: string
  ) {
    super(message);
  }
}

// Compared as digests so the check is constant-time whatever the inputs: comparing the
// strings directly would leak how much of a guessed client_state was right, and comparing
// raw buffers would throw on a length mismatch, which leaks the length by itself.
function secretEquals(a: string, b: string): boolean {
  const left = createHash("sha256").update(a, "utf8").digest();
  const right = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(left, right);
}

// A partition is a Lore repository ID - 32 hex characters, in every version we have seen.
// This check exists for one specific value. A partition of "*" is our own convention for
// "every repository" (see matchesResource), meant to be typed into the Clerk dashboard by
// an administrator and never written by an RPC. Without this guard a single CreateResource
// naming "*" turns the RebacApi escalation described above createRebacServer from "owner
// on the one repository you can name" into "owner on all of them", which is a materially
// worse outcome for the same mistake in network configuration.
//
// The accepted set is deliberately wider than 32 hex characters, so a Lore server using
// some other ID format still works; what it cannot contain is anything matchesResource
// treats as special, or the empty string.
const PARTITION_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

function partitionFromResourceId(resourceId: unknown): string {
  if (typeof resourceId !== "string") {
    throw new RpcError(grpc.status.INVALID_ARGUMENT, "resource_id is required");
  }
  const partition = resourceId.replace(/^urc-/, "");
  if (!PARTITION_PATTERN.test(partition)) {
    // The offending value is not echoed back: it reaches this service from the network and
    // failRpc puts the message straight into the log.
    throw new RpcError(
      grpc.status.INVALID_ARGUMENT,
      "resource_id must be a repository id, optionally prefixed \"urc-\""
    );
  }
  return partition;
}

// Authenticates the caller from its bearer token, then loads that user's *current* grants
// from Clerk. Deliberately not `verifyLoreToken(token).resources`: the token's claim is a
// snapshot from login, so a repository created afterwards (or a grant added or revoked in
// the Clerk dashboard) would not take effect until the user logged in again.
//
// The two failures are reported distinctly on purpose. A Clerk outage surfacing as an
// empty grant list would read as "you have access to nothing" — a silent, plausible-looking
// denial — so it returns UNAVAILABLE instead.
async function callerIdentity(
  metadata: grpc.Metadata
): Promise<{ userId: string; userName: string }> {
  const token = extractBearerToken(metadata);
  if (!token) {
    throw new RpcError(grpc.status.UNAUTHENTICATED, "Missing bearer token");
  }

  try {
    const claims = await verifyLoreToken(token);
    return { userId: claims.sub, userName: claims.name };
  } catch (err) {
    throw new RpcError(grpc.status.UNAUTHENTICATED, `Invalid token: ${(err as Error).message}`);
  }
}

async function callerGrants(
  metadata: grpc.Metadata
): Promise<{ userId: string; userName: string; resources: ResourceGrant[] }> {
  const identity = await callerIdentity(metadata);
  try {
    return { ...identity, resources: await getUserGrants(identity.userId) };
  } catch (err) {
    throw new RpcError(
      grpc.status.UNAVAILABLE,
      `Could not load permissions from Clerk: ${(err as Error).message}`
    );
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function failRpc(label: string, callback: grpc.sendUnaryData<any>, err: unknown): void {
  if (err instanceof RpcError) {
    console.warn(`${label}: ${err.message}`);
    callback({ code: err.code, message: err.message });
    return;
  }
  console.error(`${label}: unexpected failure:`, err);
  callback({ code: grpc.status.INTERNAL, message: (err as Error).message });
}

function healthCheck(
  _call: grpc.ServerUnaryCall<Record<string, never>, { status: string }>,
  callback: grpc.sendUnaryData<{ status: string }>
): void {
  callback(null, { status: "SERVING" });
}

// StartAuthSession has to be unauthenticated, since it runs before the user has logged
// in. MAX_SESSIONS bounds the memory that lets an anonymous caller consume; this bounds
// the rate at which they can churn it, so a flood cannot keep evicting real users'
// pending logins.
const sessionLimiter = createRateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);

// Its own bucket rather than sharing sessionLimiter: this one guards a secret that can be
// guessed, so it must not be possible to exhaust the budget for API key attempts by
// spending it on harmless StartAuthSession calls, nor the reverse.
const apiKeyLimiter = createRateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);

// Its own bucket again: this one spends Clerk API quota per uncached id, and a caller
// looping over ids should not be able to exhaust the login path for everyone else.
const userInfoLimiter = createRateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);

// A single request asking for thousands of ids would turn one RPC into thousands of Clerk
// calls. Lore asks about the authors on a page of history, which is nowhere near this.
const MAX_USER_INFO_IDS = 100;

// gRPC metadata is just HTTP/2 headers, so a proxy's X-Forwarded-For arrives here the
// same way it does on the HTTP side. Trust it only from a private peer, for the reason
// given in rateLimit.ts; otherwise every request behind the proxy shares one bucket and
// a single abuser locks out everyone.
function callerAddress(call: grpc.ServerUnaryCall<unknown, unknown>): string {
  const peer = peerAddress(call.getPeer());
  if (!isTrustedPeer(peer)) return peer;
  const [forwarded] = call.metadata.get("x-forwarded-for");
  if (!forwarded) return peer;
  const value = typeof forwarded === "string" ? forwarded : forwarded.toString("utf8");
  return value.split(",")[0]?.trim() || peer;
}

function startAuthSession(
  call: grpc.ServerUnaryCall<{ client_state: string }, unknown>,
  callback: grpc.sendUnaryData<{ session_code: string; login_url: string }>
): void {
  const address = callerAddress(call);
  if (!sessionLimiter.check(address)) {
    console.warn(`StartAuthSession: rate limited ${address}`);
    callback({ code: grpc.status.RESOURCE_EXHAUSTED, message: "Too many requests" });
    return;
  }

  const clientState = call.request.client_state ?? "";
  const sessionCode = createSession(clientState);
  const baseUrl = requirePublicBaseUrl();
  callback(null, {
    session_code: sessionCode,
    login_url: `${baseUrl}/login?session=${encodeURIComponent(sessionCode)}`,
  });
}

function getAuthSession(
  call: grpc.ServerUnaryCall<{ session_code: string; client_state: string }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): void {
  const { session_code: sessionCode, client_state: clientState } = call.request;
  const record = getSession(sessionCode);

  if (!record) {
    callback({ code: grpc.status.NOT_FOUND, message: "Unknown or expired session_code" });
    return;
  }
  if (!secretEquals(record.clientState, clientState ?? "")) {
    callback({ code: grpc.status.PERMISSION_DENIED, message: "client_state does not match session" });
    return;
  }
  if (record.status === "pending" || !record.userToken) {
    callback(null, {});
    return;
  }

  // Read out before the session is dropped, and dropped before the reply goes out: the
  // token is delivered exactly once, so a code that leaks afterwards is worth nothing.
  // See deleteSession for the trade this makes.
  const issued = record.userToken;
  deleteSession(sessionCode);

  callback(null, {
    user_token: {
      user_token: issued.userToken,
      expires_at: issued.expiresAt,
      user_id: issued.userId,
      user_name: issued.userName,
    },
  });
}

async function lookupUserPermissions(
  call: grpc.ServerUnaryCall<
    { resource_filter: string; context_filter?: string; page_size?: number; page_token?: string },
    unknown
  >,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  try {
    const { resources } = await callerGrants(call.metadata);
    // repository_list.rs calls this with resource_filter: "urc" — a category, not a
    // specific resource — asking for every repository the token grants. Only treat the
    // filter as a single-resource lookup when it's an actual "urc-..." resource_id.
    const filter = call.request.resource_filter;
    const filtered = filter && filter !== "urc" ? resources.filter((r) => matchesResource(r.partition, filter)) : resources;
    console.log(
      `LookupUserPermissions: filter=${JSON.stringify(filter)} granted=${JSON.stringify(resources)} matched=${filtered.length}`
    );

    callback(null, {
      // A wildcard match must echo back the specific resource_id that was asked about,
      // not the literal "urc-*" — the caller is checking for an exact match on its own ask.
      resource_permission: filtered.map((r) => ({
        resource_id: r.partition === "*" && filter && filter !== "urc" ? filter : toResourceId(r.partition),
        permission: r.permissions,
      })),
    });
  } catch (err) {
    failRpc("LookupUserPermissions", callback, err);
  }
}

async function checkUserPermission(
  call: grpc.ServerUnaryCall<{ resource_id: string[] }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  try {
    const { resources } = await callerGrants(call.metadata);

    const allowed: { resource_id: string; permission: string[] }[] = [];
    const denied: { resource_id: string; permission: string[] }[] = [];
    for (const resourceId of call.request.resource_id ?? []) {
      const match = resources.find((r) => matchesResource(r.partition, resourceId));
      (match ? allowed : denied).push({ resource_id: resourceId, permission: match?.permissions ?? [] });
    }
    console.log(
      `CheckUserPermission: requested=${JSON.stringify(call.request.resource_id)} allowed=${allowed.length} denied=${denied.length}`
    );

    callback(null, { allowed_resource_permission: allowed, denied_resource_permission: denied });
  } catch (err) {
    failRpc("CheckUserPermission", callback, err);
  }
}

// Called by the `lore` client (lore-transport/src/auth/exchange.rs) whenever it connects
// for a specific repository — clone, push, pull all need this, not just the simpler
// listing/creation calls we implemented first. It exchanges the broad AuthN token from
// login for one scoped to the requested resource(s), used for the storage/revision/lock
// connections that operation opens. It mints a fresh token after confirming every
// requested resource is authorized, which is what the client's own
// verify_jwt_usage_for_remote check on the result expects.
//
// The new token carries the caller's *current* grants rather than copying the ones on the
// presented token, which is what lets a just-created repository be cloned without logging
// in again: loreserver authorizes storage reads against the token's own `resources` claim
// (its JWT interceptor never calls this service), so this exchange is the only point where
// a stale claim can be refreshed.
async function exchangeUserTokenForMultiresourceToken(
  call: grpc.ServerUnaryCall<{ resource_id: string[] }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  try {
    const { userId, userName, resources } = await callerGrants(call.metadata);
    const requested = call.request.resource_id ?? [];
    const denied = requested.filter((id) => !resources.some((r) => matchesResource(r.partition, id)));
    console.log(
      `ExchangeUserTokenForMultiresourceToken: user=${userId} requested=${JSON.stringify(requested)} denied=${JSON.stringify(denied)}`
    );

    if (denied.length > 0) {
      callback({ code: grpc.status.PERMISSION_DENIED, message: `Not authorized for: ${denied.join(", ")}` });
      return;
    }

    const { token: loreToken, expiresAt } = await signLoreToken({
      userId,
      userName,
      issuer: loreTokenIssuer(),
      audience: loreServerAudience(),
      env: loreServerEnv(),
      resources,
    });

    callback(null, {
      token: { user_token: loreToken, expires_at: expiresAt, user_id: userId, user_name: userName },
    });
  } catch (err) {
    failRpc("ExchangeUserTokenForMultiresourceToken", callback, err);
  }
}

// Long-lived API keys exist for clients that cannot complete a browser sign-in — CI agents
// above all. A key names the Clerk user it belongs to and carries a secret half whose
// SHA-256 is stored on that user in Clerk; see apiKeys.ts for the format and why the
// digests live there rather than in this service's configuration.
//
// The key is only an identifier. Grants on the resulting token are read from the same
// Clerk user, exactly as they are for an interactive login, so nothing in the request can
// influence them. That is what keeps this from being the escalation described above
// RebacApi: a caller cannot name the resources it wants, only prove which identity it is.
//
// The minted token keeps the ordinary short lifetime. The long-lived secret is the key,
// revoked by removing its digest in Clerk — no restart and no redeploy.
async function mintTokenForApiKey(
  apiKey: string,
  address: string
): Promise<{ user_token: string; expires_at: number; user_id: string; user_name: string }> {
  if (!apiKeyLimiter.check(address)) {
    throw new RpcError(grpc.status.RESOURCE_EXHAUSTED, "Too many requests");
  }

  // Every rejection below is the same message. Distinguishing "no such user" from "wrong
  // secret" would turn this into an oracle for which CI identities exist.
  const invalid = new RpcError(grpc.status.UNAUTHENTICATED, "Invalid API key");

  const claimedUserId = apiKeyUserId(apiKey);
  if (!claimedUserId) {
    console.warn(`API key exchange: malformed key from ${address}`);
    throw invalid;
  }

  let identity;
  try {
    identity = await getUserForApiKey(claimedUserId);
  } catch (err) {
    if (err instanceof ClerkUserNotFound) {
      console.warn(`API key exchange: key names unknown user ${claimedUserId}, from ${address}`);
      throw invalid;
    }
    // Same reasoning as callerGrants: a Clerk outage must not read as "authorized for
    // nothing", which would look like a legitimate denial.
    throw new RpcError(
      grpc.status.UNAVAILABLE,
      `Could not load user from Clerk: ${(err as Error).message}`
    );
  }

  if (!apiKeyMatches(apiKey, identity.apiKeyDigests)) {
    console.warn(`API key exchange: no matching digest for ${claimedUserId}, from ${address}`);
    throw invalid;
  }

  console.log(
    `API key exchange: user=${identity.userId} resources=${identity.resources.length} from=${address}`
  );

  const { token: loreToken, expiresAt } = await signLoreToken({
    userId: identity.userId,
    userName: identity.userName,
    issuer: loreTokenIssuer(),
    audience: loreServerAudience(),
    env: loreServerEnv(),
    resources: identity.resources,
  });

  return {
    user_token: loreToken,
    expires_at: expiresAt,
    user_id: identity.userId,
    user_name: identity.userName,
  };
}

// What `lore login --token-type api-key --token <key>` actually calls. Despite the name in
// the proto, the CLI routes both "api-key" and "eg1" here rather than to
// ExchangeAPIKeyForUserToken, so token_type is what distinguishes them.
async function exchangeExternalTokenForUserToken(
  call: grpc.ServerUnaryCall<{ external_token: string; token_type: string }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  try {
    const tokenType = (call.request.token_type ?? "").trim().toLowerCase();
    if (tokenType && tokenType !== "api-key") {
      // "eg1" would be an Epic Games account token, which this bridge has no way to
      // validate — Clerk is the only identity provider here.
      throw new RpcError(
        grpc.status.UNIMPLEMENTED,
        `Unsupported token type "${tokenType}"; this bridge accepts "api-key"`
      );
    }
    const token = await mintTokenForApiKey(call.request.external_token ?? "", callerAddress(call));
    callback(null, { user_token: token });
  } catch (err) {
    failRpc("ExchangeExternalTokenForUserToken", callback, err);
  }
}

// The proto's dedicated API key entry point. The current CLI does not use it, but other
// clients may, and it costs one delegation to answer correctly rather than UNIMPLEMENTED.
async function exchangeApiKeyForUserToken(
  call: grpc.ServerUnaryCall<{ api_key: string }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  try {
    const token = await mintTokenForApiKey(call.request.api_key ?? "", callerAddress(call));
    callback(null, { user_token: token });
  } catch (err) {
    failRpc("ExchangeAPIKeyForUserToken", callback, err);
  }
}

// Called by loreserver when a user creates a new repository (lore-server/src/grpc/
// handlers/repository_create.rs), to register them as its owner. Clerk's publicMetadata
// is the only place resource grants live, so "creating" a resource here means appending
// to the calling user's own metadata — there's no separate authorization database.
async function createResource(
  call: grpc.ServerUnaryCall<{ resource_id: string; resource_name: string }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  try {
    const { userId } = await callerIdentity(call.metadata);
    const partition = partitionFromResourceId(call.request.resource_id);

    let created: boolean;
    try {
      ({ created } = await grantResource(userId, partition, ["owner"]));
    } catch (err) {
      // Clerk caps a user's metadata at 8KB across public/private/unsafe combined, which
      // is on the order of 70-110 grants. Reporting a write failure as an auth error
      // would send whoever hits it looking at tokens rather than at a full bucket.
      throw new RpcError(
        grpc.status.UNAVAILABLE,
        `Could not record the grant in Clerk (metadata is capped at 8KB per user): ${(err as Error).message}`
      );
    }

    console.log(`CreateResource: user=${userId} partition=${partition} created=${created}`);
    if (!created) {
      // repository_create.rs explicitly treats AlreadyExists as success, not an error.
      callback({ code: grpc.status.ALREADY_EXISTS, message: "Resource already exists" });
      return;
    }
    callback(null, {});
  } catch (err) {
    failRpc("CreateResource", callback, err);
  }
}

// Only revokes the grant from the calling (deleting) user — not from every user who
// might have been granted this resource, which would need iterating Clerk's whole user
// base. Acceptable gap for now: stale grants for a deleted repository just point at
// nothing rather than posing an access risk.
async function deleteResource(
  call: grpc.ServerUnaryCall<{ resource_id: string }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  try {
    const { userId } = await callerIdentity(call.metadata);
    // Validated on the same terms as CreateResource, so the two agree on what a
    // resource_id is rather than each having its own idea.
    const partition = partitionFromResourceId(call.request.resource_id);

    try {
      await revokeResource(userId, partition);
    } catch (err) {
      throw new RpcError(
        grpc.status.UNAVAILABLE,
        `Could not revoke the grant in Clerk: ${(err as Error).message}`
      );
    }

    console.log(`DeleteResource: user=${userId} partition=${partition}`);
    callback(null, {});
  } catch (err) {
    failRpc("DeleteResource", callback, err);
  }
}

// Public: the `lore` CLI has to reach this, so it is exposed through Caddy.
export function createGrpcServer(): grpc.Server {
  const server = new grpc.Server();
// Resolves user ids to display names, for `lore auth info` and anything built on it.
// Without this, Lore falls back to showing the raw id: revision metadata records the
// identity subject (user_...) rather than a name, deliberately, because a name captured
// at commit time would be permanently wrong the moment someone changed it.
//
// Lore resolves its OWN user locally from the token's preferred_username claim and never
// reaches this RPC, which is why a client logged in as the person it is asking about sees
// a name whether or not this exists. Every other lookup - anyone reading someone else's
// commits - lands here.
//
// Authorization: the caller must be authenticated, and when the request names a
// resource_id it must be one the caller holds a grant for. That mirrors
// CheckUserPermission rather than inventing a second rule. A request with no resource_id
// is allowed on authentication alone: there is nothing to check it against, and the reply
// discloses only display names for ids the caller could already read out of a repository
// it has access to.
async function getUserInfo(
  call: grpc.ServerUnaryCall<{ resource_id?: string; user_id?: string[] }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  try {
    const address = callerAddress(call);
    if (!userInfoLimiter.check(address)) {
      console.warn(`GetUserInfo: rate limited ${address}`);
      callback({ code: grpc.status.RESOURCE_EXHAUSTED, message: "Too many requests" });
      return;
    }

    const requested = call.request.user_id ?? [];
    if (requested.length > MAX_USER_INFO_IDS) {
      callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: `At most ${MAX_USER_INFO_IDS} user ids per request, got ${requested.length}`,
      });
      return;
    }

    const { resources } = await callerGrants(call.metadata);
    const resourceId = call.request.resource_id;

    if (resourceId && !resources.some((r) => matchesResource(r.partition, resourceId))) {
      console.warn(`GetUserInfo: caller not authorized for ${resourceId}`);
      callback({ code: grpc.status.PERMISSION_DENIED, message: `Not authorized for: ${resourceId}` });
      return;
    }

    if (requested.length === 0) {
      callback(null, { user_info: [] });
      return;
    }

    let names: Map<string, string>;
    try {
      names = await getUserDisplayNames(requested);
    } catch (err) {
      throw new RpcError(
        grpc.status.UNAVAILABLE,
        `Could not load user information from Clerk: ${(err as Error).message}`
      );
    }

    console.log(
      `GetUserInfo: resource=${JSON.stringify(resourceId)} requested=${requested.length} resolved=${names.size}`
    );

    // Unknown ids are simply absent from the reply. The client echoes back the id it
    // asked with when it has no name for it, which is the behaviour we want anyway.
    callback(null, {
      user_info: [...names].map(([userId, displayName]) => ({
        user_id: userId,
        display_name: displayName,
      })),
    });
  } catch (err) {
    failRpc("GetUserInfo", callback, err);
  }
}

  server.addService(urcAuthApiService, {
    HealthCheck: healthCheck,
    StartAuthSession: startAuthSession,
    GetAuthSession: getAuthSession,
    LookupUserPermissions: lookupUserPermissions,
    CheckUserPermission: checkUserPermission,
    ExchangeUserTokenForMultiresourceToken: exchangeUserTokenForMultiresourceToken,
    ExchangeExternalTokenForUserToken: exchangeExternalTokenForUserToken,
    ExchangeAPIKeyForUserToken: exchangeApiKeyForUserToken,
    GetUserInfo: getUserInfo,
  });
  return server;
}

// Internal: RebacApi is served on its own listener because CreateResource grants the
// CALLER ownership of whatever resource_id the request names. Reached from loreserver
// that is exactly right, since loreserver only calls it after it has itself created the
// repository. Reached directly by a user it is privilege escalation: present a valid
// login token, name someone else's repository ID, and the grant lands in your own Clerk
// metadata, after which LookupUserPermissions, CheckUserPermission and the token
// exchange all authorize you for it.
//
// It cannot be told apart by credentials: loreserver forwards the end user's own bearer
// token on this call (lore-server/src/authnz/rebac.rs), so a legitimate call and a
// hand-crafted one are byte-identical. Only loreserver ever calls RebacApi, so the
// separation that does work is network reachability, hence a second listener that stays
// off the public edge.
export function createRebacServer(): grpc.Server {
  const server = new grpc.Server();
  server.addService(rebacApiService, {
    CreateResource: createResource,
    DeleteResource: deleteResource,
  });
  return server;
}

export function startGrpcServer(port: number): grpc.Server {
  const server = createGrpcServer();
  // By default Caddy (see Caddyfile) is the actual public listener, terminating TLS and
  // forwarding here over h2c. That split exists because the endpoint has to satisfy two
  // constraints at once: the `lore` client always connects over TLS, and native gRPC
  // needs HTTP/2 end to end — an L4 passthrough gives the second but not the first,
  // while an L7 proxy that downgrades to HTTP/1.1 gives the first but breaks the second
  // (grpc-js speaks HTTP/2 only, with no fallback).
  //
  // The default stays loopback for the bundled-Caddy layout, where Caddy runs INSIDE
  // this container: loopback works and keeps the raw port off any public listener.
  //
  // That assumption does not survive other layouts. If Caddy runs as a separate
  // container, 127.0.0.1 is this container's own loopback and Caddy's
  // `reverse_proxy h2c://bridge:50051` gets connection refused; the same applies when an
  // edge that speaks gRPC natively targets this port directly. Either way the HTTP side
  // keeps working (Express's app.listen defaults to 0.0.0.0), so it reads as a gRPC/TLS
  // problem rather than a bind-address one. Set GRPC_HOST=0.0.0.0 for those. Safe as
  // long as the port is not published beyond the network you intend, in which case
  // 0.0.0.0 means "reachable on the container network", not "reachable from the internet".
  const host = process.env.GRPC_HOST ?? "127.0.0.1";
  server.bindAsync(`${host}:${port}`, grpc.ServerCredentials.createInsecure(), (err, boundPort) => {
    if (err) {
      console.error("Failed to bind gRPC server:", err);
      process.exit(1);
    }
    console.log(`UrcAuthApi gRPC server listening on ${host}:${boundPort}`);
  });
  return server;
}

// Defaults to loopback and stays there unless deliberately opened. Where loreserver runs
// in a separate container, set REBAC_HOST to the address reachable on that private
// network only, and never publish this port at the edge: unlike GRPC_PORT, nothing
// outside loreserver has any reason to reach it.
export function startRebacServer(port: number): grpc.Server {
  const server = createRebacServer();
  const host = process.env.REBAC_HOST ?? "127.0.0.1";
  server.bindAsync(`${host}:${port}`, grpc.ServerCredentials.createInsecure(), (err, boundPort) => {
    if (err) {
      console.error("Failed to bind RebacApi server:", err);
      process.exit(1);
    }
    console.log(`RebacApi gRPC server listening on ${host}:${boundPort} (internal only)`);
  });
  return server;
}
