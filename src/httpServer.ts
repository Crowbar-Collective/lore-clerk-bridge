import path from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import express, { type Express, type Response } from "express";
import { getSession, completeSession } from "./sessionStore.js";
import { verifyClerkSessionAndGetGrants } from "./clerk.js";
import { signLoreToken, getJwks, loreServerAudience, loreServerEnv } from "./signing.js";
import { createRateLimiter, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS } from "./rateLimit.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "..", "public");

// Self-hosted rather than loaded from a public CDN, because this page reads the user's
// Clerk session and should not depend on a third party for the script that does it.
// clerk.browser.js is code-split and resolves its chunks relative to its own script URL
// (document.currentScript.src), so the whole set has to sit behind one prefix.
//
// `npm run build` vendors those files into public/ (see scripts/vendor-clerk.mjs), which
// is what lets @clerk/clerk-js stay a devDependency and be pruned from the deployed
// image. The node_modules fallback is for local development, where `npm run dev` runs
// without a build; in a built image that directory is gone, so a missing vendor step
// surfaces as a 404 on the script rather than silently working.
const VENDORED_CLERK_DIR = path.join(PUBLIC_DIR, "vendor", "clerk");
const CLERK_DIST_DIR = existsSync(VENDORED_CLERK_DIR)
  ? VENDORED_CLERK_DIR
  : path.join(__dirname, "..", "node_modules", "@clerk", "clerk-js", "dist");
const CLERK_SCRIPT_URL = "/vendor/clerk/clerk.browser.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value.replace(/\/$/, "");
}

function sendPage(res: Response, file: string, status = 200): void {
  res.status(status).sendFile(path.join(PUBLIC_DIR, file));
}

// Every call here spends a Clerk verifyToken plus a getUser, so an unauthenticated flood
// burns the deployment's Clerk quota rather than just its own CPU.
const completeLimiter = createRateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);

export function createHttpApp(): Express {
  const app = express();

  // Only believe X-Forwarded-For from a private peer. This service is designed to sit
  // behind a proxy, so a request from a private address arrived through one and its
  // forwarded address is meaningful; a request straight off the internet can claim any
  // address it likes and is rate-limited by the address it actually came from.
  app.set("trust proxy", ["loopback", "linklocal", "uniquelocal"]);

  app.use("/assets", express.static(path.join(PUBLIC_DIR, "assets")));
  app.use("/vendor/clerk", express.static(CLERK_DIST_DIR));

  app.get("/healthz", (_req, res) => {
    res.send("ok");
  });

  app.get("/login", (req, res) => {
    const sessionCode = typeof req.query.session === "string" ? req.query.session : undefined;
    if (!sessionCode || !getSession(sessionCode)) {
      sendPage(res, "session-error.html", 400);
      return;
    }

    const accountPortalUrl = requireEnv("CLERK_ACCOUNT_PORTAL_URL");
    const baseUrl = requireEnv("PUBLIC_HTTP_BASE_URL");
    const redirectUrl = `${baseUrl}/callback?session=${encodeURIComponent(sessionCode)}`;
    res.redirect(`${accountPortalUrl}/sign-in?redirect_url=${encodeURIComponent(redirectUrl)}`);
  });

  app.get("/callback", (req, res) => {
    const sessionCode = typeof req.query.session === "string" ? req.query.session : "";
    if (!sessionCode || !getSession(sessionCode)) {
      sendPage(res, "session-error.html", 400);
      return;
    }
    // The page itself is static; it reads the session code back out of the query string.
    // Guarding here (rather than serving it via express.static) keeps today's behavior of
    // rejecting an unknown session up front instead of failing later at /callback/complete.
    sendPage(res, "callback.html");
  });

  // The publishable key is public by design — it ships in every Clerk frontend. Serving
  // it here instead of templating it into the HTML is what keeps the page fully static.
  app.get("/callback/config", (_req, res) => {
    res.json({
      publishableKey: requireEnv("CLERK_PUBLISHABLE_KEY"),
      clerkScriptUrl: CLERK_SCRIPT_URL,
    });
  });

  app.post("/callback/complete", express.json(), async (req, res) => {
    const clientIp = req.ip ?? "unknown";
    if (!completeLimiter.check(clientIp)) {
      console.warn(`/callback/complete: rate limited ${clientIp}`);
      res.set("Retry-After", String(completeLimiter.retryAfter(clientIp)));
      res.status(429).json({ error: "Too many requests" });
      return;
    }

    const { session: sessionCode, token } = req.body ?? {};
    if (typeof sessionCode !== "string" || typeof token !== "string") {
      res.status(400).json({ error: "session and token are required" });
      return;
    }
    if (!getSession(sessionCode)) {
      res.status(404).json({ error: "Unknown or expired session" });
      return;
    }

    try {
      const { userId, userName, resources } = await verifyClerkSessionAndGetGrants(token);
      const { token: loreToken, expiresAt } = await signLoreToken({
        userId,
        userName,
        issuer: requireEnv("PUBLIC_HTTP_BASE_URL"),
        audience: loreServerAudience(),
        env: loreServerEnv(),
        resources,
      });
      completeSession(sessionCode, { userToken: loreToken, expiresAt, userId, userName });
      res.json({ ok: true });
    } catch (err) {
      res.status(401).json({ error: `Clerk verification failed: ${(err as Error).message}` });
    }
  });

  app.get("/.well-known/jwks.json", async (_req, res) => {
    res.json(await getJwks());
  });

  return app;
}

export function startHttpServer(port: number): void {
  const app = createHttpApp();
  app.listen(port, () => {
    console.log(`HTTP server (login/callback/jwks) listening on 0.0.0.0:${port}`);
  });
}
