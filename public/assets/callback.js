"use strict";

const statusEl = document.getElementById("status");

function setStatus(message) {
  statusEl.textContent = message;
  delete statusEl.dataset.state;
}

function fail(message) {
  statusEl.textContent = message;
  statusEl.dataset.state = "error";
}

// clerk-js reads its publishable key off the `data-clerk-publishable-key` attribute of
// the script tag that loads it (via document.currentScript), so the element has to
// carry the attribute before it is appended. It also resolves its lazily-loaded chunks
// relative to its own src, which is why the whole dist directory is served under
// /vendor/clerk rather than just this one file.
function loadClerkScript(src, publishableKey) {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.crossOrigin = "anonymous";
    script.dataset.clerkPublishableKey = publishableKey;
    script.addEventListener("load", () => resolve());
    script.addEventListener("error", () => reject(new Error(`Failed to load ${src}`)));
    document.head.appendChild(script);
  });
}

async function main() {
  const sessionCode = new URLSearchParams(window.location.search).get("session");
  if (!sessionCode) {
    fail("Missing login session. Please retry `lore auth login`.");
    return;
  }

  setStatus("Loading Clerk…");
  const configResponse = await fetch("/callback/config");
  if (!configResponse.ok) {
    fail("Could not load sign-in configuration. Please retry `lore auth login`.");
    return;
  }
  const { publishableKey, clerkScriptUrl } = await configResponse.json();

  await loadClerkScript(clerkScriptUrl, publishableKey);

  // No satellite config needed: this page is served from a subdomain of Clerk's primary
  // domain, so the browser already hands Clerk's session cookie to this origin.
  await window.Clerk.load();
  if (!window.Clerk.session) {
    fail("No active session detected. Please retry `lore auth login`.");
    return;
  }

  setStatus("Finishing sign-in…");
  const token = await window.Clerk.session.getToken();
  const response = await fetch("/callback/complete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session: sessionCode, token }),
  });

  if (response.ok) {
    setStatus("Signed in — you can close this window and return to the CLI.");
  } else {
    fail(`Sign-in failed: ${await response.text()}`);
  }
}

main().catch((err) => {
  fail(`Sign-in failed: ${err && err.message ? err.message : err}`);
});
