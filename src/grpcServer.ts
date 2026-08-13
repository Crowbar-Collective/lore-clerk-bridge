import path from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { createSession, getSession } from "./sessionStore.js";
import { signLoreToken, verifyLoreToken, loreServerAudience, loreServerEnv } from "./signing.js";
import { grantResource, revokeResource } from "./clerk.js";

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
  const token = extractBearerToken(call.metadata);
  if (!token) {
    console.warn("LookupUserPermissions: no bearer token on request");
    callback({ code: grpc.status.UNAUTHENTICATED, message: "Missing bearer token" });
    return;
  }

  try {
    const { resources } = await verifyLoreToken(token);
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
    console.warn("LookupUserPermissions: token verification failed:", err);
    callback({ code: grpc.status.UNAUTHENTICATED, message: `Invalid token: ${(err as Error).message}` });
  }
}

async function checkUserPermission(
  call: grpc.ServerUnaryCall<{ resource_id: string[] }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  const token = extractBearerToken(call.metadata);
  if (!token) {
    console.warn("CheckUserPermission: no bearer token on request");
    callback({ code: grpc.status.UNAUTHENTICATED, message: "Missing bearer token" });
    return;
  }

  try {
    const { resources } = await verifyLoreToken(token);

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
    console.warn("CheckUserPermission: token verification failed:", err);
    callback({ code: grpc.status.UNAUTHENTICATED, message: `Invalid token: ${(err as Error).message}` });
  }
}

// Called by the `lore` client (lore-transport/src/auth/exchange.rs) whenever it connects
// for a specific repository — clone, push, pull all need this, not just the simpler
// listing/creation calls we implemented first. It exchanges the broad AuthN token from
// login for one scoped to the requested resource(s), used for the storage/revision/lock
// connections that operation opens. Our token model doesn't narrow scope on exchange (the
// original token already carries the full granted resource list) — this mints a fresh
// token with the same claims after confirming every requested resource is authorized,
// which is what the client's own verify_jwt_usage_for_remote check on the result expects.
async function exchangeUserTokenForMultiresourceToken(
  call: grpc.ServerUnaryCall<{ resource_id: string[] }, unknown>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  const token = extractBearerToken(call.metadata);
  if (!token) {
    console.warn("ExchangeUserTokenForMultiresourceToken: no bearer token on request");
    callback({ code: grpc.status.UNAUTHENTICATED, message: "Missing bearer token" });
    return;
  }

  try {
    const { sub: userId, name: userName, resources } = await verifyLoreToken(token);
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
    console.warn("ExchangeUserTokenForMultiresourceToken: failed:", err);
    callback({ code: grpc.status.UNAUTHENTICATED, message: `Invalid token: ${(err as Error).message}` });
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
  const token = extractBearerToken(call.metadata);
  if (!token) {
    console.warn("CreateResource: no bearer token on request");
    callback({ code: grpc.status.UNAUTHENTICATED, message: "Missing bearer token" });
    return;
  }

  try {
    const { sub: userId } = await verifyLoreToken(token);
    const partition = call.request.resource_id.replace(/^urc-/, "");
    const { created } = await grantResource(userId, partition, ["owner"]);
    console.log(`CreateResource: user=${userId} partition=${partition} created=${created}`);
    if (!created) {
      // repository_create.rs explicitly treats AlreadyExists as success, not an error.
      callback({ code: grpc.status.ALREADY_EXISTS, message: "Resource already exists" });
      return;
    }
    callback(null, {});
  } catch (err) {
    console.warn("CreateResource: failed:", err);
    callback({ code: grpc.status.UNAUTHENTICATED, message: `Invalid token: ${(err as Error).message}` });
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
  const token = extractBearerToken(call.metadata);
  if (!token) {
    console.warn("DeleteResource: no bearer token on request");
    callback({ code: grpc.status.UNAUTHENTICATED, message: "Missing bearer token" });
    return;
  }

  try {
    const { sub: userId } = await verifyLoreToken(token);
    const partition = call.request.resource_id.replace(/^urc-/, "");
    await revokeResource(userId, partition);
    console.log(`DeleteResource: user=${userId} partition=${partition}`);
    callback(null, {});
  } catch (err) {
    console.warn("DeleteResource: failed:", err);
    callback({ code: grpc.status.UNAUTHENTICATED, message: `Invalid token: ${(err as Error).message}` });
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
  // Caddy (see Caddyfile) is the actual public listener, terminating TLS and
  // forwarding over h2c. Railway's TCP Proxy has no TLS of its own, and its
  // HTTP-domain edge downgrades to HTTP/1.1 before the container, which a native
  // HTTP/2-only gRPC server can't speak — so nothing but Caddy should reach this port.
  //
  // The default stays loopback because on Railway Caddy runs INSIDE this container,
  // where loopback both works and keeps the raw port off the public TCP proxy.
  //
  // That assumption does not survive a deployment where Caddy is a separate
  // container: 127.0.0.1 is then this container's own loopback, and Caddy's
  // `reverse_proxy h2c://bridge:50051` gets connection refused while the HTTP side
  // keeps working (Express's app.listen defaults to 0.0.0.0) — which reads as a
  // gRPC/TLS problem rather than a bind-address one. Set GRPC_HOST=0.0.0.0 there.
  // Safe as long as the port is not published to the host, in which case 0.0.0.0
  // means "reachable on the container network" and not "reachable from the internet".
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
