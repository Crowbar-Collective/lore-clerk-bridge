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
