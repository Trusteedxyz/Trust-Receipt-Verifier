/**
 * RFC 8785 (JCS) canonical JSON for deterministic vector generation.
 * Mirrors the canonicalizer used by the issuer in `src/issuer.ts`.
 */

export function canonicalizeJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalizeJson).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sorted = Object.keys(obj)
      .sort()
      .filter((k) => obj[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + canonicalizeJson(obj[k]));
    return "{" + sorted.join(",") + "}";
  }
  throw new Error(`canonicalizeJson: unsupported type ${typeof value}`);
}

/** Pretty-print a JSON object deterministically (sorted keys, 2-space indent). */
export function prettyDeterministic(value: unknown): string {
  const canonical = canonicalizeJson(value);
  // Re-parse and stringify with indent to keep deterministic ordering AND human-readable layout.
  return JSON.stringify(JSON.parse(canonical), null, 2) + "\n";
}
