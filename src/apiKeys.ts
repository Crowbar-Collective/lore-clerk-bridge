import { createHash, timingSafeEqual } from "node:crypto";

// Long-lived API keys for clients that cannot complete a browser sign-in — CI agents above
// all. A key carries the Clerk user it belongs to, so verifying one is a direct lookup
// rather than a search:
//
//   lore_ci_user_2abcDEF.mzJ8kQ...
//   ^^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^
//   prefix   Clerk user  secret
//
// The SHA-256 of the *whole* key is stored on that user's Clerk privateMetadata, under
// `loreApiKeyDigests`. Three things follow from that choice:
//
//   - There is no deployment configuration at all. No environment variable, no Terraform
//     input, no SSM parameter, nothing to redeploy. Issuing and revoking a key is an edit
//     in the Clerk dashboard, beside the repository grants it is paired with.
//   - Verification is free. The exchange already fetches the Clerk user to read its
//     grants, and the digests arrive in that same response.
//   - Because the user ID is inside the hashed material, a key issued for one user cannot
//     be replayed as another.
//
// privateMetadata, not publicMetadata: the latter is readable by the frontend, and these
// digests have no business leaving the server.

const KEY_PATTERN = /^lore_ci_(user_[A-Za-z0-9]+)\.([A-Za-z0-9_-]{16,})$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

/** Metadata field holding a user's API key digests. */
export const DIGEST_FIELD = "loreApiKeyDigests";

/**
 * The Clerk user a key claims to belong to, or {@code null} if it is not a well-formed key.
 *
 * <p>This is only a claim. It says which user's digests to check against, and is worthless
 * until {@link apiKeyMatches} confirms the secret half.
 */
export function apiKeyUserId(presented: string): string | null {
  return KEY_PATTERN.exec(presented ?? "")?.[1] ?? null;
}

/**
 * Whether a presented key matches any digest stored for its user.
 *
 * <p>Every digest is compared, without returning early, and each comparison is
 * constant-time. Bailing out on the first hit would make response time depend on a key's
 * position in the list, and a plain string comparison would leak how many leading bytes a
 * guess got right.
 *
 * <p>Multiple digests per user are supported so a key can be rotated without downtime: add
 * the new one, move CI over, then drop the old.
 */
export function apiKeyMatches(presented: string, storedDigests: unknown): boolean {
  if (!presented) return false;

  const digests = normaliseDigests(storedDigests);
  if (digests.length === 0) return false;

  const candidate = createHash("sha256").update(presented, "utf8").digest();
  let matched = false;
  for (const digest of digests) {
    // Both are fixed-width SHA-256, so lengths always agree and timingSafeEqual cannot throw.
    if (timingSafeEqual(candidate, digest)) {
      matched = true;
    }
  }
  return matched;
}

/**
 * Reads the digest list out of Clerk metadata, which is untyped JSON that an administrator
 * edits by hand. A single string is accepted as well as an array, since that is the obvious
 * thing to type when there is only one key.
 */
function normaliseDigests(stored: unknown): Buffer[] {
  const raw = typeof stored === "string" ? [stored] : Array.isArray(stored) ? stored : [];
  const digests: Buffer[] = [];
  for (const value of raw) {
    if (typeof value !== "string") continue;
    const normalised = value.trim().toLowerCase();
    if (!DIGEST_PATTERN.test(normalised)) {
      // A malformed entry is far more likely to be a typo than an attack, and silently
      // ignoring it would present as a key that simply stops working.
      console.warn(`${DIGEST_FIELD}: ignoring entry that is not a sha256 hex digest`);
      continue;
    }
    digests.push(Buffer.from(normalised, "hex"));
  }
  return digests;
}
