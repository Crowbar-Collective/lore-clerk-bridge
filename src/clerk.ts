import { createClerkClient, verifyToken } from "@clerk/backend";
import type { ResourceGrant } from "./signing.js";

const secretKey = process.env.CLERK_SECRET_KEY;
if (!secretKey) {
  throw new Error("CLERK_SECRET_KEY is required");
}

const clerkClient = createClerkClient({ secretKey });

export interface ClerkUserGrant {
  userId: string;
  userName: string;
  resources: ResourceGrant[];
}

// The bridge is deployed on a subdomain of Clerk's primary domain (not on Clerk's
// satellite-domain feature, which needs a paid plan), so its session cookie arrives
// here automatically. This check itself is unaffected either way: it's a direct
// secretKey verification, independent of which domain issued the token.
export async function verifyClerkSessionAndGetGrants(sessionToken: string): Promise<ClerkUserGrant> {
  const claims = await verifyToken(sessionToken, { secretKey });
  const userId = claims.sub;
  if (!userId) {
    throw new Error("Clerk token has no subject claim");
  }

  const user = await clerkClient.users.getUser(userId);
  const resources = (user.publicMetadata?.resources as ResourceGrant[] | undefined) ?? [];

  const userName =
    user.username ||
    [user.firstName, user.lastName].filter(Boolean).join(" ") ||
    user.primaryEmailAddress?.emailAddress ||
    userId;

  return { userId, userName, resources };
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
