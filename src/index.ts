import { startGrpcServer } from "./grpcServer.js";
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
const httpPort = Number(process.env.PORT ?? process.env.HTTP_PORT ?? 8080);

startGrpcServer(grpcPort);
startHttpServer(httpPort);
