process.env.PUBLIC_HTTP_BASE_URL = "http://localhost:8080";
const { signLoreToken } = await import("../src/signing.ts");
const { token, expiresAt } = await signLoreToken({
  userId: "user_test123",
  userName: "Test User",
  issuer: "http://localhost:8080",
  audience: process.env.TEST_AUD ?? "lore-service",
  resources: [{ partition: "test-partition-id", permissions: ["read", "write"] }],
  ttlSeconds: 3600,
  env: process.env.TEST_ENV ?? "local",
});
console.log(token);
console.error("expiresAt", expiresAt);
