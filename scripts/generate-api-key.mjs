#!/usr/bin/env node
// Generates an API key for a non-interactive client (a CI agent, typically) and prints
// the LORE_API_KEYS entry to configure for it.
//
//   node scripts/generate-api-key.mjs user_2abcDEF...
//
// The raw key is shown once and never stored: the bridge only ever holds its SHA-256
// digest, so a lost key is reissued rather than recovered.

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

// 32 bytes of randomness, base64url so it survives env files, shell quoting and Jenkins
// credential fields without escaping. The prefix makes a leaked key recognisable in logs
// and greppable in a secret scanner.
const key = `lore_ci_${randomBytes(32).toString("base64url")}`;
const digest = createHash("sha256").update(key, "utf8").digest("hex");

console.log(`
API key (store this in your CI credential store now - it is not recoverable):

  ${key}

Add to the bridge's LORE_API_KEYS (comma or newline separated if you have several):

  ${userId}:${digest}

Then, on the CI side:

  lore login lore://your-server:41337 --token-type api-key --token <key>

Make sure the Clerk user has the repositories it needs in publicMetadata.resources.
`);
