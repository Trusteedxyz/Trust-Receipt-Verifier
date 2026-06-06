/**
 * T-CR-008 — `revocation_evidence` discriminated-union schema tests.
 *
 * Validates that {@link TimestampEvidenceSchema} accepts:
 *  - `kind: "ocsp"` with `data_b64`.
 *  - `kind: "crl"` with `data_b64`.
 *  - `kind: "unavailable"` with `reason` (constrained enum) + `attempted_at`.
 *
 * And rejects malformed `unavailable` shapes (unknown reason, missing
 * `attempted_at`, mixing fields across variants).
 */
import { describe, expect, it } from "vitest";
import { TimestampEvidenceSchema } from "../zod-1.1.js";

const BASE_RFC3161 = {
  type: "RFC3161" as const,
  tsa_endpoint: "https://tsa.example.com/tsa",
  tsr: "AAAA",
  tst: "AAAA",
  issued_at_attested: 1_700_000_000,
  imprint_algo: "sha-256" as const,
  imprint_target: "jws_compact_bytes" as const,
  nonce: "00".repeat(16),
  policy_oid: "1.2.3.4.5",
  tsa_cert_chain: [
    "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
  ],
  tsa_root_cert_sha256: "a".repeat(64),
  tolerance_seconds: 60,
};

describe("TimestampEvidenceSchema.revocation_evidence — T-CR-008", () => {
  it("accepts kind=ocsp with data_b64", () => {
    const parsed = TimestampEvidenceSchema.safeParse({
      ...BASE_RFC3161,
      revocation_evidence: { kind: "ocsp", data_b64: "AAAA" },
    });
    expect(parsed.success).toBe(true);
  });

  it("accepts kind=crl with data_b64", () => {
    const parsed = TimestampEvidenceSchema.safeParse({
      ...BASE_RFC3161,
      revocation_evidence: { kind: "crl", data_b64: "AAAA" },
    });
    expect(parsed.success).toBe(true);
  });

  it("accepts kind=unavailable with valid reason + attempted_at", () => {
    for (const reason of [
      "ocsp_unreachable",
      "crl_unreachable",
      "fetch_timeout",
      "synthetic_fixture",
    ] as const) {
      const parsed = TimestampEvidenceSchema.safeParse({
        ...BASE_RFC3161,
        revocation_evidence: {
          kind: "unavailable",
          reason,
          attempted_at: 1_700_000_000,
        },
      });
      expect(parsed.success, `reason=${reason}`).toBe(true);
    }
  });

  it("rejects kind=unavailable with unknown reason", () => {
    const parsed = TimestampEvidenceSchema.safeParse({
      ...BASE_RFC3161,
      revocation_evidence: {
        kind: "unavailable",
        reason: "no_distribution_point", // legacy issuer reason — must be remapped
        attempted_at: 1_700_000_000,
      },
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects kind=unavailable missing attempted_at", () => {
    const parsed = TimestampEvidenceSchema.safeParse({
      ...BASE_RFC3161,
      revocation_evidence: {
        kind: "unavailable",
        reason: "ocsp_unreachable",
      },
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects kind=ocsp missing data_b64", () => {
    const parsed = TimestampEvidenceSchema.safeParse({
      ...BASE_RFC3161,
      revocation_evidence: { kind: "ocsp" },
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects kind=unavailable that smuggles data_b64 (cross-variant fields)", () => {
    // The discriminated union must NOT silently accept ocsp-shaped payloads
    // under the unavailable discriminator (Zod strips unknown keys but the
    // missing required keys reason+attempted_at are absent, so it fails).
    const parsed = TimestampEvidenceSchema.safeParse({
      ...BASE_RFC3161,
      revocation_evidence: {
        kind: "unavailable",
        data_b64: "AAAA",
      },
    });
    expect(parsed.success).toBe(false);
  });
});
