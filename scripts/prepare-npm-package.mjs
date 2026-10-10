#!/usr/bin/env node
/**
 * Builds the directory that gets published to npm: `npm-package/`.
 *
 * Why a staging directory instead of publishing the repository root:
 *  - the repository root depends on `@agenticmcpstores/trust-receipt-tsa-client`
 *    as `workspace:*`. That package is private and not on npm, and npm cannot
 *    resolve the `workspace:` protocol, so an install of the root package would
 *    fail;
 *  - the root has no `files` allow-list, so publishing it would ship tests,
 *    vectors, demos and the vendored sources.
 *
 * What it does (run `pnpm run build` first):
 *  1. copies `dist/` without source maps;
 *  2. copies the built TSA client into `dist/_vendor/tsa-client/` and rewrites
 *     every import of the workspace package name to a relative path, in the
 *     `.js` and `.d.ts` files;
 *  3. writes a publishable `package.json` whose dependencies are the verifier's
 *     own plus the TSA client's third-party dependencies;
 *  4. fails if any reference to the workspace package name is left behind.
 *
 * Then: `npm pack ./npm-package` to inspect, `npm publish ./npm-package`.
 */
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "npm-package");
const VENDOR_SRC = path.join(ROOT, "vendor", "trust-receipt-tsa-client");
const VENDOR_NAME = "@agenticmcpstores/trust-receipt-tsa-client";
const VENDOR_DEST = path.join(OUT, "dist", "_vendor", "tsa-client");

const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const fail = (msg) => {
  console.error(`prepare-npm-package: ${msg}`);
  process.exit(1);
};

const pkg = readJson(path.join(ROOT, "package.json"));
const vendorPkg = readJson(path.join(VENDOR_SRC, "package.json"));

if (!existsSync(path.join(ROOT, "dist", "index.js"))) {
  fail("dist/ is missing. Run `pnpm run build` first.");
}
if (!existsSync(path.join(VENDOR_SRC, "dist", "index.js"))) {
  fail("the vendored TSA client is not built. Run `pnpm run build` first.");
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const notMap = (src) => !src.endsWith(".map");
cpSync(path.join(ROOT, "dist"), path.join(OUT, "dist"), {
  recursive: true,
  filter: notMap,
});
cpSync(path.join(VENDOR_SRC, "dist"), VENDOR_DEST, {
  recursive: true,
  filter: notMap,
});

for (const f of ["README.md", "CHANGELOG.md", "SECURITY.md", "LICENSE"]) {
  if (existsSync(path.join(ROOT, f))) cpSync(path.join(ROOT, f), path.join(OUT, f));
}

// --- rewrite the workspace package name to a relative path ------------------
const vendorEntry = path.join(VENDOR_DEST, "index.js");
// Exact quoted specifiers, replaced as plain strings (no regular expression is
// built from the package name).
const SPECIFIERS = [`"${VENDOR_NAME}"`, `'${VENDOR_NAME}'`];

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

let rewritten = 0;
for (const file of walk(path.join(OUT, "dist"))) {
  if (file.startsWith(VENDOR_DEST + path.sep)) continue;
  if (!file.endsWith(".js") && !file.endsWith(".d.ts")) continue;
  const text = readFileSync(file, "utf8");
  if (!text.includes(VENDOR_NAME)) continue;
  let rel = path.relative(path.dirname(file), vendorEntry).split(path.sep).join("/");
  if (!rel.startsWith(".")) rel = `./${rel}`;
  let next = text;
  for (const spec of SPECIFIERS) {
    const q = spec[0];
    next = next.split(spec).join(`${q}${rel}${q}`);
  }
  writeFileSync(file, next);
  rewritten += 1;
}

for (const file of walk(path.join(OUT, "dist"))) {
  if (!file.endsWith(".js") && !file.endsWith(".d.ts")) continue;
  if (readFileSync(file, "utf8").includes(VENDOR_NAME)) {
    fail(`a reference to ${VENDOR_NAME} is left in ${path.relative(OUT, file)}`);
  }
}

// --- publishable package.json ------------------------------------------------
const { [VENDOR_NAME]: _workspaceDep, ...ownDeps } = pkg.dependencies ?? {};
const dependencies = { ...ownDeps, ...(vendorPkg.dependencies ?? {}) };
const sorted = Object.fromEntries(
  Object.entries(dependencies).sort(([a], [b]) => a.localeCompare(b))
);

const bins = {};
for (const [name, rel] of Object.entries({
  "trust-receipt": "./dist/bin/trust-receipt.js",
  "verify-bundle": "./dist/bin/verify-bundle.js",
})) {
  if (!existsSync(path.join(OUT, rel))) fail(`bin target ${rel} does not exist`);
  bins[name] = rel;
}

const out = {
  name: pkg.name,
  version: pkg.version,
  description:
    pkg.description ??
    "TrustReceipt open standard: verifier for cross-protocol agentic commerce evidence receipts",
  license: pkg.license,
  type: "module",
  main: "./dist/index.js",
  types: "./dist/index.d.ts",
  exports: {
    ".": { types: "./dist/index.d.ts", default: "./dist/index.js" },
    "./package.json": "./package.json",
  },
  bin: bins,
  files: ["dist", "README.md", "CHANGELOG.md", "SECURITY.md", "LICENSE"],
  engines: { node: ">=20" },
  dependencies: sorted,
  repository: pkg.repository,
  homepage: "https://github.com/Trusteedxyz/Trust-Receipt-Verifier#readme",
  bugs: { url: "https://github.com/Trusteedxyz/Trust-Receipt-Verifier/issues" },
  keywords: ["trustreceipt", "verifier", "agentic-commerce", "jws", "rfc3161", "eddsa"],
};
writeFileSync(path.join(OUT, "package.json"), `${JSON.stringify(out, null, 2)}\n`);

console.log(
  `prepared ${out.name}@${out.version} in ${path.relative(ROOT, OUT)}/ ` +
    `(${rewritten} files rewritten, ${Object.keys(sorted).length} dependencies)`
);
