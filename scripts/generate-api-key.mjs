#!/usr/bin/env node
// Generates an API key for a non-interactive client (a CI agent, typically) and prints the
// digest to store on that user in Clerk.
//
//   node scripts/generate-api-key.mjs user_2abcDEF...
//
// The raw key is shown once and never stored anywhere: the bridge only ever holds its
// SHA-256 digest, so a lost key is reissued rather than recovered.

import { createHash, randomBytes } from "node:crypto";

const userId = process.argv[2];

if (!userId || userId.startsWith("-")) {
  console.error(`Usage: node scripts/generate-api-key.mjs <clerk-user-id>

The Clerk user ID is the identity the key authenticates as, and whose publicMetadata
grants decide which repositories it can reach. Create a dedicated Clerk user for CI
rather than reusing a person's account, so builds are attributed correctly and access
can be revoked without touching anyone's login.`);
  process.exit(1);
}

if (!/^user_[A-Za-z0-9]+$/.test(userId)) {
  console.error(`"${userId}" does not look like a Clerk user ID (expected user_...).`);
  process.exit(1);
}

// The user ID travels inside the key so verification is a direct Clerk lookup rather than a
// search, and so a key issued for one user cannot be replayed as another - the ID is part of
// the hashed material. 32 bytes of randomness, base64url so the key survives env files,
// shell quoting and credential fields without escaping.
const key = `lore_ci_${userId}.${randomBytes(32).toString("base64url")}`;
const digest = createHash("sha256").update(key, "utf8").digest("hex");

console.log(`
API key (store this in your CI credential store now - it is not recoverable):

  ${key}

Clerk Dashboard -> Users -> ${userId} -> Metadata -> Private:

  {
    "loreApiKeyDigests": ["${digest}"]
  }

Add to the array rather than replacing it to rotate without downtime: issue the new key,
move CI over, then remove the old digest.

Then, on the CI side:

  lore login lore://your-server:41337 --token-type api-key --token <key>

Make sure the same user has its repositories in publicMetadata.resources - the key proves
who the agent is, the grants decide what it can reach.
`);
