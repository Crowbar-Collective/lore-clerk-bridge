import { createHash, timingSafeEqual } from "node:crypto";

// Long-lived API keys for non-interactive clients: CI agents, build machines, anything
// that cannot complete a browser sign-in. A key is only ever an *identifier* — it maps to
// a Clerk user, and every grant still comes from that user's Clerk metadata at the moment
// of exchange. Nothing about a key confers access on its own.
//
// Keys are configured as their SHA-256 digests rather than in the clear, so a leaked
// environment (a container inspect, a crash dump, a log of process env) does not hand over
// working credentials. The bridge never needs the original value, only to recognise it.
//
// Format of LORE_API_KEYS, one entry per line or comma-separated:
//
//   user_2abcDEF...:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
//
// Generate with scripts/generate-api-key.mjs.

const ENV_VAR = "LORE_API_KEYS";
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

interface ApiKeyEntry {
  userId: string;
  digest: Buffer;
}

let cachedSource: string | undefined;
let cachedEntries: ApiKeyEntry[] = [];

function parse(source: string): ApiKeyEntry[] {
  const entries: ApiKeyEntry[] = [];

  // Split by line first so a "# ..." comment covers the rest of its line rather than only
  // its first word, then by comma within a line for the single-line form.
  const fields = source
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, ""))
    .flatMap((line) => line.split(","));

  for (const raw of fields) {
    const line = raw.trim();
    if (!line) continue;

    // rsplit on ":" so a userId containing a colon would not break parsing; the digest is
    // always the final field.
    const separator = line.lastIndexOf(":");
    if (separator <= 0) {
      console.warn(`${ENV_VAR}: ignoring malformed entry (expected <userId>:<sha256>)`);
      continue;
    }
    const userId = line.slice(0, separator).trim();
    const digest = line.slice(separator + 1).trim().toLowerCase();
    if (!userId || !DIGEST_PATTERN.test(digest)) {
      console.warn(`${ENV_VAR}: ignoring entry for "${userId}" (digest is not a sha256 hex string)`);
      continue;
    }
    entries.push({ userId, digest: Buffer.from(digest, "hex") });
  }
  return entries;
}

function entries(): ApiKeyEntry[] {
  const source = process.env[ENV_VAR] ?? "";
  if (source !== cachedSource) {
    cachedSource = source;
    cachedEntries = parse(source);
  }
  return cachedEntries;
}

/** Whether any API keys are configured at all. */
export function apiKeysConfigured(): boolean {
  return entries().length > 0;
}

/**
 * The Clerk user ID an API key maps to, or {@code null} if it matches none.
 *
 * <p>Every configured entry is compared, without returning early on a match, and each
 * comparison is constant-time. Bailing out at the first hit would make response time
 * depend on a key's position in the list, and a plain === on the digest would leak how
 * many leading bytes a guess got right.
 */
export function resolveApiKey(presented: string): string | null {
  if (!presented) return null;

  const candidate = createHash("sha256").update(presented, "utf8").digest();
  let matched: string | null = null;

  for (const entry of entries()) {
    // Digests are fixed-width SHA-256, so lengths always agree and timingSafeEqual cannot
    // throw here.
    if (timingSafeEqual(candidate, entry.digest)) {
      matched = entry.userId;
    }
  }
  return matched;
}
