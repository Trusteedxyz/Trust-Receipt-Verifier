/**
 * Bind `jwks-snapshot.json` to signed evidence.
 *
 * The snapshot used to be a name-only REQUIRED artifact: substituted content
 * changed no verdict. It is now checked against what the JWS commits to:
 *
 *  1. Shape: `{ keys: [...] }`, non-empty, every key carries a `kid`.
 *  2. It contains the `kid` the receipt names (`verification_methods.jwks.kid`).
 *  3. EITHER `sha256(JCS({keys}))` equals the signed `jwks_sha256`
 *     (the snapshot is exactly the JWKS the issuer committed to), OR — when the
 *     snapshot declares `_snapshot_provenance.source ===
 *     "at-issuance-from-signed-history"` (the export builds it from the signed
 *     history, so the digest cannot match a multi-key live JWKS by
 *     construction) — EVERY key equals the public material of the same-`kid`
 *     entry in the root-signed `jwks-history.jws`. Provenance is attacker
 *     controlled, so it only selects WHICH proof is demanded; it never waives one.
 *
 * `_snapshot_provenance` is excluded from the digest (the producer hashes
 * `{ keys }` only).
 */
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

export type SnapshotErrorCode = "jwks_snapshot_invalid" | "jwks_snapshot_mismatch";

export interface SnapshotViolation {
  readonly code: SnapshotErrorCode;
  readonly detail: string;
}

export interface SnapshotOk {
  readonly warnings: readonly string[];
}

const PUBLIC_MEMBERS = ["kty", "crv", "x", "y", "n", "e"] as const;

function sameKeyMaterial(
  a: Record<string, unknown>,
  b: Record<string, unknown>
): boolean {
  return PUBLIC_MEMBERS.every((m) => (a[m] ?? null) === (b[m] ?? null));
}

export function verifyJwksSnapshot(input: {
  readonly snapshotBytes: Uint8Array;
  readonly kid: string;
  readonly committedJwksSha256: string;
  readonly historyEntries: readonly unknown[];
}): SnapshotViolation | SnapshotOk {
  let doc: unknown;
  try {
    doc = JSON.parse(Buffer.from(input.snapshotBytes).toString("utf8"));
  } catch {
    return { code: "jwks_snapshot_invalid", detail: "jwks-snapshot.json is not valid JSON" };
  }
  const keys = (doc as { keys?: unknown } | null)?.keys;
  if (typeof doc !== "object" || doc === null || !Array.isArray(keys) || keys.length === 0) {
    return { code: "jwks_snapshot_invalid", detail: "jwks-snapshot.json must be an object with a non-empty keys[]" };
  }
  const typed: Record<string, unknown>[] = [];
  for (const k of keys) {
    if (typeof k !== "object" || k === null || typeof (k as { kid?: unknown }).kid !== "string") {
      return { code: "jwks_snapshot_invalid", detail: "every snapshot key must be an object with a string kid" };
    }
    typed.push(k as Record<string, unknown>);
  }
  if (!typed.some((k) => k["kid"] === input.kid)) {
    return { code: "jwks_snapshot_mismatch", detail: `snapshot does not contain the receipt's signing kid ${input.kid}` };
  }

  const digest = createHash("sha256")
    .update(canonicalize({ keys: typed }) as string, "utf8")
    .digest("hex");
  if (digest === input.committedJwksSha256.toLowerCase()) return { warnings: [] };

  const provenance = (doc as { _snapshot_provenance?: { source?: unknown } })._snapshot_provenance;
  if (provenance?.source === "at-issuance-from-signed-history") {
    const history = input.historyEntries.filter(
      (e): e is { kid: string; jwk_pub: Record<string, unknown> } =>
        typeof e === "object" && e !== null &&
        typeof (e as { kid?: unknown }).kid === "string" &&
        typeof (e as { jwk_pub?: unknown }).jwk_pub === "object" &&
        (e as { jwk_pub?: unknown }).jwk_pub !== null
    );
    const allInHistory = typed.every((k) =>
      history.some((e) => e.kid === k["kid"] && sameKeyMaterial(e.jwk_pub, k))
    );
    if (allInHistory) return { warnings: ["jwks_snapshot_history_derived"] };
    return { code: "jwks_snapshot_mismatch", detail: "history-derived snapshot contains a key absent from (or different to) the signed jwks-history" };
  }
  return {
    code: "jwks_snapshot_mismatch",
    detail: `sha256(JCS(keys))=${digest} != signed verification_methods.jwks_sha256=${input.committedJwksSha256}`,
  };
}
