/**
 * TypeScript half of the SHARED legacy-compact cross-port contract.
 *
 * The Python port runs the same files in
 * `packages/verifier-python/tests/test_legacy_compact_vectors.py`. If the two
 * implementations ever disagree about the shape 100% of production emits, one of
 * these two suites goes red — which was not previously true of anything: each
 * port built its own fixtures in code and asserted its own expectations.
 *
 * See `conformance/legacy-compact-vectors/README.md`.
 */

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";

import { verifyTrustReceipt, type PublicJwk } from "../verifier.js";

const VECTOR_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../conformance/legacy-compact-vectors"
);

interface Vector {
  readonly name: string;
  readonly description: string;
  readonly jws: string;
  readonly jwks: PublicJwk[];
  readonly expected: {
    readonly valid: boolean;
    readonly variant?: string;
    readonly canonicalization?: string;
    /** `null` when the receipt carries no `expires_at` at all. */
    readonly freshnessExpired?: boolean | null;
  };
}

const vectors: Vector[] = readdirSync(VECTOR_DIR)
  .filter((f) => f.endsWith(".json"))
  .sort()
  .map((f) => JSON.parse(readFileSync(path.join(VECTOR_DIR, f), "utf8")));

describe("legacy-compact cross-port vectors", () => {
  it("finds the shared vector set", () => {
    // A silently empty directory would make every `it.each` below vanish and the
    // suite pass while testing nothing.
    expect(vectors.length).toBeGreaterThanOrEqual(5);
  });

  it.each(vectors.map((v) => [v.name, v] as const))(
    "%s",
    async (_name, vector) => {
      const result = await verifyTrustReceipt(vector.jws, {
        jwks: vector.jwks,
        clockToleranceSeconds: 0,
      });

      expect(result.valid, vector.description).toBe(vector.expected.valid);

      if (!vector.expected.valid) return;

      if (vector.expected.variant !== undefined) {
        expect(result.variant).toBe(vector.expected.variant);
      }
      if (vector.expected.canonicalization !== undefined) {
        expect(result.canonicalization).toBe(vector.expected.canonicalization);
      }
      if (vector.expected.freshnessExpired === null) {
        // No `expires_at` on the receipt ⇒ no window to report. Distinct from
        // "not expired", and both ports must keep them distinguishable.
        expect(result.freshness).toBeUndefined();
      } else if (vector.expected.freshnessExpired !== undefined) {
        expect(result.freshness?.expired).toBe(
          vector.expected.freshnessExpired
        );
      }
    }
  );
});
