import { createClerkClient, verifyToken } from "@clerk/backend";
import type { ResourceGrant } from "./signing.js";
import { DIGEST_FIELD } from "./apiKeys.js";

const secretKey = process.env.CLERK_SECRET_KEY;
if (!secretKey) {
  throw new Error("CLERK_SECRET_KEY is required");
}

const clerkClient = createClerkClient({ secretKey });

export interface ClerkUserGrant {
  userId: string;
  userName: string;
  resources: ResourceGrant[];
  /**
   * Raw `privateMetadata.loreApiKeyDigests`, for the API key exchange to verify against.
   * Untyped because it is hand-edited JSON; apiKeys.ts is what makes sense of it.
   */
  apiKeyDigests: unknown;
}

/** Raised when Clerk says the user does not exist, as opposed to being unreachable. */
export class ClerkUserNotFound extends Error {}

// The bridge is deployed on a subdomain of Clerk's primary domain (not on Clerk's
// satellite-domain feature, which needs a paid plan), so its session cookie arrives
// here automatically. This check itself is unaffected either way: it's a direct
// secretKey verification, independent of which domain issued the token.
export async function verifyClerkSessionAndGetGrants(sessionToken: string): Promise<ClerkUserGrant> {
  // authorizedParties pins the token to this origin. A Clerk instance can serve several
  // applications, and without it a session token minted for any of the others would be
  // accepted here on the strength of its signature alone.
  const authorizedParties = process.env.PUBLIC_HTTP_BASE_URL
    ? [process.env.PUBLIC_HTTP_BASE_URL.replace(/\/$/, "")]
    : undefined;
  const claims = await verifyToken(sessionToken, { secretKey, authorizedParties });
  const userId = claims.sub;
  if (!userId) {
    throw new Error("Clerk token has no subject claim");
  }

  return toUserGrant(await clerkClient.users.getUser(userId));
}

// The name a person is shown as, most recognisable first. Falling through to the raw id
// is the last resort: it always identifies someone, it just reads badly.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function displayNameOf(user: any): string {
  return (
    user.username ||
    [user.firstName, user.lastName].filter(Boolean).join(" ") ||
    user.primaryEmailAddress?.emailAddress ||
    user.id
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toUserGrant(user: any): ClerkUserGrant {
  return {
    userId: user.id,
    userName: displayNameOf(user),
    resources: (user.publicMetadata?.resources as ResourceGrant[] | undefined) ?? [],
    apiKeyDigests: user.privateMetadata?.[DIGEST_FIELD],
  };
}

/** How long a resolved display name is reused before Clerk is asked again. */
export const USER_INFO_TTL_MS = Number(process.env.USER_INFO_TTL_SECONDS ?? 300) * 1000;

/** Ceiling on cached names, so the cache cannot become a leak. */
const USER_INFO_CACHE_MAX = 5_000;

const displayNames = new Map<string, { name: string; expiresAt: number }>();

function pruneDisplayNames(now: number): void {
  if (displayNames.size < USER_INFO_CACHE_MAX) return;
  for (const [id, entry] of displayNames) {
    if (entry.expiresAt <= now) displayNames.delete(id);
  }
  while (displayNames.size >= USER_INFO_CACHE_MAX) {
    const oldest = displayNames.keys().next();
    if (oldest.done) break;
    displayNames.delete(oldest.value);
  }
}

// Display names for user ids, cached because Lore resolves the same handful of authors
// over and over - every commit announcement, every lock - and each miss spends Clerk API
// quota. Names change rarely, so a few minutes of staleness costs nothing.
//
// A user Clerk does not know is omitted rather than reported: the caller asked about ids
// it read out of revision metadata, and one belonging to a deleted account should not
// fail the lookup for everyone else in the same batch. Any other Clerk failure throws, so
// an outage surfaces as an outage instead of as "these people have no names" - the same
// distinction getUserForApiKey draws.
export async function getUserDisplayNames(userIds: string[]): Promise<Map<string, string>> {
  const now = Date.now();
  const resolved = new Map<string, string>();
  const misses: string[] = [];

  for (const userId of new Set(userIds)) {
    const cached = displayNames.get(userId);
    if (cached && cached.expiresAt > now) {
      resolved.set(userId, cached.name);
    } else {
      misses.push(userId);
    }
  }

  await Promise.all(
    misses.map(async (userId) => {
      try {
        const name = displayNameOf(await clerkClient.users.getUser(userId));
        pruneDisplayNames(now);
        displayNames.set(userId, { name, expiresAt: now + USER_INFO_TTL_MS });
        resolved.set(userId, name);
      } catch (err) {
        if ((err as { status?: number })?.status === 404) return;
        throw err;
      }
    })
  );

  return resolved;
}

// Current grants for a user, straight from Clerk. The authorization RPCs use this rather
// than the `resources` claim carried on the caller's token: that claim is a snapshot from
// login, so a repository created (or a grant added or revoked) afterwards would not be
// visible until the user logged in again.
export async function getUserGrants(userId: string): Promise<ResourceGrant[]> {
  const user = await clerkClient.users.getUser(userId);
  return (user.publicMetadata?.resources as ResourceGrant[] | undefined) ?? [];
}

// Identity, grants and API key digests for a user known by ID rather than by a presented
// session. Used by the API key exchange, where there is no Clerk session to verify.
//
// A missing user is reported distinctly from an unreachable Clerk: the first is an
// authentication failure (a key naming a user that no longer exists), the second is an
// outage. Collapsing them would either return UNAVAILABLE for a revoked key, or report a
// Clerk outage as a credential problem and send someone hunting the wrong fault.
export async function getUserForApiKey(userId: string): Promise<ClerkUserGrant> {
  try {
    return toUserGrant(await clerkClient.users.getUser(userId));
  } catch (err) {
    if ((err as { status?: number })?.status === 404) {
      throw new ClerkUserNotFound(`No Clerk user ${userId}`);
    }
    throw err;
  }
}


// Backs RebacApi.CreateResource: when a user creates a new repository, loreserver
// calls back here to register them as its owner (lore-server/src/grpc/handlers/
// repository_create.rs). This is a read-modify-write against Clerk's metadata, not an
// atomic operation — acceptable for how infrequently repositories get created, but two
// concurrent creates for the same user could race. Returns created: false (rather than
// throwing) when the grant already exists, since the caller treats that as success too.
export async function grantResource(
  userId: string,
  partition: string,
  permissions: string[]
): Promise<{ created: boolean }> {
  const user = await clerkClient.users.getUser(userId);
  const resources = (user.publicMetadata?.resources as ResourceGrant[] | undefined) ?? [];

  if (resources.some((r) => r.partition === partition)) {
    return { created: false };
  }

  await clerkClient.users.updateUserMetadata(userId, {
    publicMetadata: { ...user.publicMetadata, resources: [...resources, { partition, permissions }] },
  });
  return { created: true };
}

// Backs RebacApi.DeleteResource, called when a repository is deleted. Idempotent: a
// partition that isn't present is treated as already-deleted, not an error.
export async function revokeResource(userId: string, partition: string): Promise<void> {
  const user = await clerkClient.users.getUser(userId);
  const resources = (user.publicMetadata?.resources as ResourceGrant[] | undefined) ?? [];
  const updated = resources.filter((r) => r.partition !== partition);
  if (updated.length === resources.length) return;

  await clerkClient.users.updateUserMetadata(userId, {
    publicMetadata: { ...user.publicMetadata, resources: updated },
  });
}
