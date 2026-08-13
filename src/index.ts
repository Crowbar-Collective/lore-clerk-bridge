import { startGrpcServer, startRebacServer } from "./grpcServer.js";
import { startHttpServer } from "./httpServer.js";

const requiredEnvVars = [
  "CLERK_SECRET_KEY",
  "CLERK_PUBLISHABLE_KEY",
  "CLERK_ACCOUNT_PORTAL_URL",
  "PUBLIC_HTTP_BASE_URL",
  "LORE_SERVER_HOSTNAME",
];

const missing = requiredEnvVars.filter((name) => !process.env[name]);
if (missing.length > 0) {
  console.error(`Missing required environment variables: ${missing.join(", ")}`);
  process.exit(1);
}

const grpcPort = Number(process.env.GRPC_PORT ?? 50051);
const rebacPort = Number(process.env.REBAC_PORT ?? 50052);
const httpPort = Number(process.env.PORT ?? process.env.HTTP_PORT ?? 8080);

const ports = { PORT: httpPort, GRPC_PORT: grpcPort, REBAC_PORT: rebacPort };
const collisions = Object.entries(ports).filter(
  ([name, port]) => Object.entries(ports).some(([other, p]) => other !== name && p === port)
);
if (collisions.length > 0) {
  console.error(
    `Ports must be distinct, got ${collisions.map(([n, p]) => `${n}=${p}`).join(", ")}`
  );
  process.exit(1);
}

startGrpcServer(grpcPort);
startRebacServer(rebacPort);
startHttpServer(httpPort);
