import express, { type Express } from "express";
import { getSession, completeSession } from "./sessionStore.js";
import { verifyClerkSessionAndGetGrants } from "./clerk.js";
import { signLoreToken, getJwks } from "./signing.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value.replace(/\/$/, "");
}

function renderCallbackPage(sessionCode: string, publishableKey: string): string {
  const safeSessionCode = JSON.stringify(sessionCode);
  const safeKey = publishableKey.replace(/"/g, "");
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Lore sign-in</title></head>
<body>
<p id="status">Completing sign-in&hellip;</p>
<script async crossorigin="anonymous" data-clerk-publishable-key="${safeKey}"
  src="https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js"></script>
<script>
  const sessionCode = ${safeSessionCode};
  const statusEl = document.getElementById("status");
  window.addEventListener("load", async () => {
    try {
      // No satellite config needed: this page must be served from a subdomain of
      // Clerk's primary domain (devops.crowbargames.com), so the browser already
      // hands Clerk's session cookie to this origin automatically.
      await window.Clerk.load();
      if (!window.Clerk.session) {
        statusEl.textContent = "No active session detected — please retry lore auth login.";
        return;
      }
      const token = await window.Clerk.session.getToken();
      const res = await fetch("/callback/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session: sessionCode, token }),
      });
      if (res.ok) {
        statusEl.textContent = "Signed in — you can close this window and return to the CLI.";
      } else {
        statusEl.textContent = "Sign-in failed: " + (await res.text());
      }
    } catch (err) {
      statusEl.textContent = "Sign-in failed: " + err;
    }
  });
</script>
</body>
</html>`;
}

export function createHttpApp(): Express {
  const app = express();

  app.get("/healthz", (_req, res) => {
    res.send("ok");
  });

  app.get("/login", (req, res) => {
    const sessionCode = typeof req.query.session === "string" ? req.query.session : undefined;
    if (!sessionCode || !getSession(sessionCode)) {
      res.status(400).send("Unknown or expired login session. Please retry `lore auth login`.");
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
      res.status(400).send("Unknown or expired login session. Please retry `lore auth login`.");
      return;
    }
    res.type("html").send(renderCallbackPage(sessionCode, requireEnv("CLERK_PUBLISHABLE_KEY")));
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
        // Two independent readers, two different required values: the CLI's local check
        // (lore-credential/src/jwt.rs) needs the Lore server's bare hostname present, and
        // loreserver's own [server.auth] jwt_audience check (when configured — confirmed
        // against a real server set to jwt_audience = ["lore-service"]) needs its
        // configured value present. Both go in since aud accepts an array.
        audience: [requireEnv("LORE_SERVER_HOSTNAME"), process.env.LORE_SERVER_JWT_AUDIENCE ?? "lore-service"],
        // Must match the Lore server's own --env / LORE_ENV (default "local") — it's a
        // required claim on the JWT that loreserver decodes independently of anything
        // this bridge checks, and a mismatch there isn't something this bridge can see.
        env: requireEnv("LORE_SERVER_ENV"),
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
