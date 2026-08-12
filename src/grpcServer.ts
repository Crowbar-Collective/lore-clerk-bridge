import path from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { createSession, getSession } from "./sessionStore.js";
import { verifyLoreToken } from "./signing.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.join(__dirname, "..", "proto", "auth_api.proto");

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const proto = grpc.loadPackageDefinition(packageDefinition) as any;
const urcAuthApiService = proto.epic_urc.UrcAuthApi.service;

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
    callback({ code: grpc.status.UNAUTHENTICATED, message: "Missing bearer token" });
    return;
  }

  try {
    const { resources } = await verifyLoreToken(token);
    const filter = call.request.resource_filter;
    const filtered = filter ? resources.filter((r) => r.partition === filter) : resources;

    callback(null, {
      resource_permission: filtered.map((r) => ({
        resource_id: r.partition,
        permission: r.permissions,
      })),
    });
  } catch (err) {
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
  });
  return server;
}

export function startGrpcServer(port: number): grpc.Server {
  const server = createGrpcServer();
  // Loopback-only: Caddy (see Caddyfile) is the actual public listener, terminating
  // TLS and forwarding over local h2c. Railway's TCP Proxy has no TLS of its own, and
  // its HTTP-domain edge downgrades to HTTP/1.1 before the container, which a native
  // HTTP/2-only gRPC server can't speak — so nothing but Caddy should reach this port.
  server.bindAsync(`127.0.0.1:${port}`, grpc.ServerCredentials.createInsecure(), (err, boundPort) => {
    if (err) {
      console.error("Failed to bind gRPC server:", err);
      process.exit(1);
    }
    console.log(`UrcAuthApi gRPC server listening on 127.0.0.1:${boundPort}`);
  });
  return server;
}
