/**
 * GAP H4 (T-AUD-012) — strict-mode semantic trust-anchor / jwks verification.
 *
 * The verifier historically validated `verification_methods.trust_anchor_sha256`
 * and `jwks_sha256` only by REGEX FORMAT (`zod-1.1.ts` — `/^[0-9a-f]{64}$/`), so
 * an all-zeros opaque stub anchor sailed through. T-AUD-012 closes this with an
 * explicit `mode: "strict" | "compat"` option:
 *
 *   - "compat" (default during the canary): stub / mismatched anchors and a
 *     missing agent identity are surfaced as NON-FATAL warnings (pass-with-warn)
 *     so the rollout is non-breaking.
 *   - "strict": the same conditions are FATAL rejections, and the body's
 *     `trust_anchor_sha256` is checked SEMANTICALLY against the pinned anchor
 *     (`options.trustAnchorPemSha256`).
 *
 * These tests pin the four named negative conformance vectors:
 *   - vector-anchor-stub-rejected.json          (trust_anchor_sha256 = all-zeros)
 *   - vector-user-auth-synthetic-rejected.json  (jwks_sha256 = all-zeros stub)
 *   - vector-lotl-degraded-warning.json          (TSA/LOTL degraded — warn in BOTH)
 *   - vector-agent-identity-missing-rejected.json (no agent identity binding)
 *
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-018, T-AUD-012
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyReceiptEnvelope } from "../verify-1.1.js";
import type { VerifyOptions } from "../verify-1.1.js";
import type { SignedJwksHistory } from "../types-1.1.js";
import type { PublicJwk } from "../verifier.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, "..", "..", "test-vectors", "v11-strict");

interface StrictVectorFile {
  vector_id: string;
  title: string;
  envelope: Record<string, unknown>;
  verify_options: {
    currentTime: number;
    expectedSubject?: "buyer_agent" | "merchant_admin";
    trust_anchor_sha256: string;
    tsa_root_pins?: string[];
    jwks: { keys: PublicJwk[] };
  };
  expected_strict: {
    outcome: "accepted" | "rejected";
    errorCode: string | null;
  };
  expected_compat: {
    outcome: "accepted" | "rejected";
    errorCode: string | null;
    warning: string;
  };
}

function loadVector(name: string): StrictVectorFile {
  return JSON.parse(
    readFileSync(join(VECTORS_DIR, name), "utf8")
  ) as StrictVectorFile;
}

function jwksToSignedHistory(
  jwks: { keys: PublicJwk[] },
  currentTime: number
): SignedJwksHistory {
  const payload = {
    schema_version: "1.0",
    entries: jwks.keys.map((k) => ({
      kid: (k as { kid?: string }).kid ?? "",
      jwk_pub: k as unknown as Record<string, unknown>,
      valid_from: currentTime - 86_400,
      valid_to: null,
    })),
    history_chain_sha256: "0".repeat(64),
  };
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA" })).toString(
    "base64url"
  );
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return {
    jws_compact: `${header}.${body}.AA`,
    signed_by_root_sha256: "0".repeat(64),
  };
}

function makeOptions(
  vector: StrictVectorFile,
  mode: "strict" | "compat"
): VerifyOptions {
  return {
    jwksHistory: jwksToSignedHistory(
      vector.verify_options.jwks,
      vector.verify_options.currentTime
    ),
    trustAnchorPemSha256: vector.verify_options.trust_anchor_sha256,
    policyOidAllowlist: ["1.2.3.4.5.6.7.8.9"],
    tsaRootCertSha256Allowlist: vector.verify_options.tsa_root_pins,
    expectedSubject: vector.verify_options.expectedSubject,
    allowStagingRoots: true,
    currentTimeSeconds: vector.verify_options.currentTime,
    mode,
  };
}

const VECTORS = [
  "vector-anchor-stub-rejected.json",
  "vector-user-auth-synthetic-rejected.json",
  "vector-lotl-degraded-warning.json",
  "vector-agent-identity-missing-rejected.json",
] as const;

describe("GAP H4 (T-AUD-012) strict-mode trust-anchor verification", () => {
  it.each(VECTORS)("%s — strict mode matches expected_strict", async (name) => {
    const vector = loadVector(name);
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      makeOptions(vector, "strict")
    );
    expect(result.outcome).toBe(vector.expected_strict.outcome);
    if (vector.expected_strict.errorCode !== null) {
      expect(result.errorCode).toBe(vector.expected_strict.errorCode);
    }
  });

  it.each(VECTORS)(
    "%s — compat mode is pass-with-warn (default canary behaviour)",
    async (name) => {
      const vector = loadVector(name);
      const result = await verifyReceiptEnvelope(
        vector.envelope as unknown as Parameters<
          typeof verifyReceiptEnvelope
        >[0],
        makeOptions(vector, "compat")
      );
      expect(result.outcome).toBe(vector.expected_compat.outcome);
      expect(result.warnings).toContain(vector.expected_compat.warning);
    }
  );

  it("default mode (omitted) behaves as compat — non-breaking canary default", async () => {
    const vector = loadVector("vector-anchor-stub-rejected.json");
    const opts = makeOptions(vector, "compat");
    // Strip the mode key entirely to prove the DEFAULT is compat.
    const { mode: _omit, ...rest } = opts;
    void _omit;
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      rest as VerifyOptions
    );
    expect(result.outcome).toBe("accepted");
    expect(result.warnings).toContain("trust_anchor_sha256_stub");
  });

  it("strict mode rejects the all-zeros anchor stub explicitly", async () => {
    const vector = loadVector("vector-anchor-stub-rejected.json");
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      makeOptions(vector, "strict")
    );
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("trust_anchor_stub_rejected");
  });
});
