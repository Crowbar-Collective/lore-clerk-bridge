import path from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.join(__dirname, "..", "proto", "auth_api.proto");

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});
const proto = grpc.loadPackageDefinition(packageDefinition);
const client = new proto.epic_urc.UrcAuthApi("localhost:50051", grpc.credentials.createInsecure());

function call(method, request, metadata) {
  return new Promise((resolve, reject) => {
    client[method](request, metadata ?? new grpc.Metadata(), (err, res) => {
      if (err) reject(err);
      else resolve(res);
    });
  });
}

const health = await call("HealthCheck", {});
console.log("HealthCheck:", health);

const started = await call("StartAuthSession", { client_state: "test-client-state" });
console.log("StartAuthSession:", started);

const pending = await call("GetAuthSession", {
  session_code: started.session_code,
  client_state: "test-client-state",
});
console.log("GetAuthSession (pending):", pending);

const mismatched = await call("GetAuthSession", {
  session_code: started.session_code,
  client_state: "wrong-state",
}).catch((err) => ({ error: err.details, code: err.code }));
console.log("GetAuthSession (wrong client_state):", mismatched);

const unknown = await call("GetAuthSession", {
  session_code: "does-not-exist",
  client_state: "test-client-state",
}).catch((err) => ({ error: err.details, code: err.code }));
console.log("GetAuthSession (unknown session):", unknown);

const testToken = process.env.TEST_TOKEN;
if (testToken) {
  const md = new grpc.Metadata();
  md.set("authorization", `Bearer ${testToken}`);
  const perms = await call("LookupUserPermissions", { resource_filter: "" }, md);
  console.log("LookupUserPermissions:", JSON.stringify(perms, null, 2));

  const filtered = await call(
    "LookupUserPermissions",
    { resource_filter: "test-partition-id" },
    md
  );
  console.log("LookupUserPermissions (filtered):", JSON.stringify(filtered, null, 2));

  const noAuth = await call("LookupUserPermissions", { resource_filter: "" }).catch((err) => ({
    error: err.details,
    code: err.code,
  }));
  console.log("LookupUserPermissions (no bearer token):", noAuth);
}

client.close();
