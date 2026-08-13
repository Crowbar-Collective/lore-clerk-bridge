import path from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { createSession, getSession } from "./sessionStore.js";
import {
  signLoreToken,
  verifyLoreToken,
  loreServerAudience,
  loreServerEnv,
  type ResourceGrant,
} from "./signing.js";
import { getUserGrants, grantResource, revokeResource } from "./clerk.js";

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

function startAuthSession(
  call: grpc.ServerUnaryCall<{ client_state: string }, unknown>,
  callback: grpc.sendUnaryData<{ session_code: string; login_url: string }>
): void {
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
  if (record.clientState !== clientState) {
    callback({ code: grpc.status.PERMISSION_DENIED, message: "client_state does not match session" });
    return;
  }
  if (record.status === "pending" || !record.userToken) {
    callback(null, {});
    return;
  }

  callback(null, {
    user_token: {
      user_token: record.userToken.userToken,
      expires_at: record.userToken.expiresAt,
      user_id: record.userToken.userId,
      user_name: record.userToken.userName,
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
      issuer: requirePublicBaseUrl(),
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
    const partition = call.request.resource_id.replace(/^urc-/, "");

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
    const partition = call.request.resource_id.replace(/^urc-/, "");

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

export function createGrpcServer(): grpc.Server {
  const server = new grpc.Server();
  server.addService(urcAuthApiService, {
    HealthCheck: healthCheck,
    StartAuthSession: startAuthSession,
    GetAuthSession: getAuthSession,
    LookupUserPermissions: lookupUserPermissions,
    CheckUserPermission: checkUserPermission,
    ExchangeUserTokenForMultiresourceToken: exchangeUserTokenForMultiresourceToken,
  });
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
