// Copies the browser build of clerk-js into public/vendor/clerk so the runtime image can
// serve it without carrying the package.
//
// @clerk/clerk-js is a devDependency: it exists to produce these prebuilt files, and it
// is never imported by any Node code here. Keeping it out of `dependencies` means
// `npm prune --omit=dev` removes its whole tree from the deployed image, which matters
// because that tree pulls in Coinbase and Solana wallet SDKs carrying a long tail of
// advisories. None of it is reachable from a login page, but shipping it means every
// `npm audit` on a deployment reports vulnerabilities in code that never runs.
//
// Only the browser entry and its chunks are copied. The legacy.browser, native and
// headless variants are separate entry points that clerk.browser.js never loads.

import { existsSync, mkdirSync, readdirSync, copyFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "node_modules", "@clerk", "clerk-js", "dist");
const target = join(root, "public", "vendor", "clerk");

if (!existsSync(source)) {
  // Expected after `npm prune --omit=dev`, where the files have already been vendored.
  console.log("vendor-clerk: @clerk/clerk-js not installed, leaving public/vendor/clerk as is");
  process.exit(0);
}

// Chunk filenames embed the entry they belong to, so the browser build is exactly the
// entry plus everything tagged `_clerk.browser_`. Note this must not match
// `_clerk.headless.browser_`, which is a different entry point.
const wanted = (name) => name === "clerk.browser.js" || name.includes("_clerk.browser_");

rmSync(target, { recursive: true, force: true });
mkdirSync(target, { recursive: true });

const files = readdirSync(source).filter(wanted);
for (const file of files) {
  copyFileSync(join(source, file), join(target, file));
}

if (!files.includes("clerk.browser.js")) {
  console.error("vendor-clerk: clerk.browser.js missing from the clerk-js build");
  process.exit(1);
}

console.log(`vendor-clerk: copied ${files.length} files to public/vendor/clerk`);
