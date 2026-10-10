import { createHash } from "node:crypto";

/**
 * Test helper: `sha256:<hex>` over a key-sorted JSON serialization. This is the
 * canonical form a status list's `manifest_hash` commits to (the same form
 * `src/revocation.ts` recomputes), written out independently so the tests do
 * not just re-use the code under test.
 */
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
  const o = value as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalStringify(o[k])}`)
    .join(",")}}`;
}

export function computeManifestHash(manifest: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalStringify(manifest)).digest("hex")}`;
}
