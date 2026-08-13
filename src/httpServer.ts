import path from "node:path";
import { fileURLToPath } from "node:url";
import express, { type Express, type Response } from "express";
import { getSession, completeSession } from "./sessionStore.js";
import { verifyClerkSessionAndGetGrants } from "./clerk.js";
import { signLoreToken, getJwks, loreServerAudience, loreServerEnv } from "./signing.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "..", "public");

// Served straight out of node_modules rather than copied into public/: clerk.browser.js
// is code-split across ~130 sibling chunks that it resolves relative to its own script
// URL (document.currentScript.src), so the whole dist directory has to be reachable
// under one prefix. Self-hosted rather than loaded from a public CDN because this page
// reads the user's Clerk session.
const CLERK_DIST_DIR = path.join(__dirname, "..", "node_modules", "@clerk", "clerk-js", "dist");
const CLERK_SCRIPT_URL = "/vendor/clerk/clerk.browser.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value.replace(/\/$/, "");
}

function sendPage(res: Response, file: string, status = 200): void {
  res.status(status).sendFile(path.join(PUBLIC_DIR, file));
}

export function createHttpApp(): Express {
  const app = express();

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
