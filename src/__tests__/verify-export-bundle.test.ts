/**
 * Unit tests for verify-export-bundle.ts (spec-049 T173).
 *
 * Builds synthetic ZIP fixtures with adm-zip and asserts the verifier's
 * accept/reject paths + error codes.
 *
 * @see ../src/verify-export-bundle.ts
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import AdmZip from "adm-zip";
import { createHash } from "node:crypto";

// Mock the inner v1.1 verifier so we can drive its outcome deterministically.
const verifyReceiptEnvelope = vi.fn();
vi.mock("../verify-1.1.js", () => ({
  verifyReceiptEnvelope: (envelope: unknown, opts: unknown) =>
    verifyReceiptEnvelope(envelope, opts),
}));

const { verifyExportBundle } = await import("../verify-export-bundle.js");

const TRUST_ANCHOR_PEM =
  "-----BEGIN CERTIFICATE-----\nstub-trust-anchor\n-----END CERTIFICATE-----\n";
const TRUST_ANCHOR_SHA256 = createHash("sha256")
  .update(TRUST_ANCHOR_PEM)
  .digest("hex");

const RECEIPT_ENVELOPE = {
  receipt: "h.p.s",
  timestamp_evidence: {
    type: "unavailable",
    reason: "tsa_unavailable",
    attempted_tsa: ["x"],
    attempted_at: 1,
  },
  envelope_metadata: {
    receipt_id: "11111111-1111-1111-1111-111111111111",
    created_at: 1000,
    legal_posture: "ades_candidate_no_tsa",
    legal_posture_warnings: [],
  },
};

// JWS Compact with payload {"entries":[]} — verifier requires entries[] array
const JWKS_HISTORY_JWS = "eyJhbGciOiJFZERTQSJ9.eyJlbnRyaWVzIjpbXX0.fakesig";

const JWKS_SNAPSHOT = { keys: [] };

const RETENTION_METADATA = {
  jurisdiction: "US",
  jurisdiction_code: "US",
  min_retention_years: 7,
  manual_review_required: false,
  statute_ref: "ESIGN",
  exported_at: 1000,
};

interface BundleFixture {
  envelope?: object;
  jwksSnapshot?: object;
  jwksHistoryJws?: string;
  trustAnchorPem?: string;
  retentionMetadata?: object;
  omit?: ReadonlyArray<string>;
}

function buildFixtureZip(fx: BundleFixture = {}): Buffer {
  const zip = new AdmZip();
  const omit = new Set(fx.omit ?? []);
  if (!omit.has("receipt-envelope.json")) {
    zip.addFile(
      "receipt-envelope.json",
      Buffer.from(
        JSON.stringify(fx.envelope ?? RECEIPT_ENVELOPE, null, 2) + "\n"
      )
    );
  }
  if (!omit.has("jwks-snapshot.json")) {
    zip.addFile(
      "jwks-snapshot.json",
      Buffer.from(
        JSON.stringify(fx.jwksSnapshot ?? JWKS_SNAPSHOT, null, 2) + "\n"
      )
    );
  }
  if (!omit.has("jwks-history.jws")) {
    zip.addFile(
      "jwks-history.jws",
      Buffer.from(fx.jwksHistoryJws ?? JWKS_HISTORY_JWS)
    );
  }
  if (!omit.has("trust-anchor.pem")) {
    zip.addFile(
      "trust-anchor.pem",
      Buffer.from(fx.trustAnchorPem ?? TRUST_ANCHOR_PEM)
    );
  }
  if (!omit.has("retention-policy.json")) {
    zip.addFile(
      "retention-policy.json",
      Buffer.from(
        JSON.stringify(fx.retentionMetadata ?? RETENTION_METADATA, null, 2) +
          "\n"
      )
    );
  }
  return zip.toBuffer();
}

beforeEach(() => {
  verifyReceiptEnvelope.mockReset();
});

describe("verifyExportBundle", () => {
  it("happy path → accepted with retention metadata + envelopeVerifyResult", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted",
      schema_version: "1.1",
      warnings: [],
      envelope: RECEIPT_ENVELOPE,
      recomputedLegalPosture: "ades_candidate_no_tsa",
    });

    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      // T-CR-001: fixture runs under staging-stub embedded root.
      allowStagingRoots: true,
    });

    expect(result.outcome).toBe("accepted");
    expect(result.retentionMetadata).toBeDefined();
    expect(result.envelopeVerifyResult).toBeDefined();
    expect(result.filesPresent).toContain("receipt-envelope.json");
    expect(result.filesPresent).toContain("trust-anchor.pem");
  });

  it("[T-CR-001] default (no allowStagingRoots) rejects bundle under staging-stub root", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted",
      schema_version: "1.1",
      warnings: [],
    });
    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      // No allowStagingRoots → default false → fail-closed.
    });
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jwks_history_signature_invalid");
    expect(result.errorDetail).toBe("root_not_in_trust_anchor");
    // Inner envelope verifier MUST NOT have been invoked — fail-closed
    // happens before delegation.
    expect(verifyReceiptEnvelope).not.toHaveBeenCalled();
  });

  it("rejects when bundle SHA-256 does not match expected", async () => {
    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      expectedBundleSha256: "0".repeat(64),
    });

    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toMatch(/bundle_integrity_mismatch|bundle/);
  });

  it("rejects when trust anchor SHA-256 does not match pin", async () => {
    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: "0".repeat(64),
    });

    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toMatch(/trust_anchor/);
    expect(verifyReceiptEnvelope).not.toHaveBeenCalled();
  });

  it("rejects when required artifact is missing (receipt-envelope.json)", async () => {
    const zip = buildFixtureZip({ omit: ["receipt-envelope.json"] });
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      allowStagingRoots: true,
    });

    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toMatch(/required_artifact_missing|missing/);
  });

  it("rejects when required artifact is missing (trust-anchor.pem)", async () => {
    const zip = buildFixtureZip({ omit: ["trust-anchor.pem"] });
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      allowStagingRoots: true,
    });
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toMatch(/required_artifact_missing|missing/);
  });

  it("propagates inner envelope verifier rejection", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "rejected",
      schema_version: "1.1",
      errorCode: "schema_invalid",
      warnings: [],
    });

    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      allowStagingRoots: true,
    });
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBeDefined();
  });

  it("rejects when jwks-history.jws is structurally invalid", async () => {
    const zip = buildFixtureZip({ jwksHistoryJws: "not-a-jws" });
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      allowStagingRoots: true,
    });
    expect(result.outcome).toBe("rejected");
  });
});
