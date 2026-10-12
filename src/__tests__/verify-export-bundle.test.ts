/**
 * Unit tests for verify-export-bundle.ts.
 *
 * Builds synthetic ZIP fixtures with adm-zip and asserts the verifier's
 * accept/reject paths + error codes.
 *
 * @see ../src/verify-export-bundle.ts
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import AdmZip from "adm-zip";
import { createHash, generateKeyPairSync } from "node:crypto";
import canonicalize from "canonicalize";
import { CompactSign } from "jose";
import type { IssuerRootEntry } from "../embedded-issuer-root.js";
import { STAGING_STUB_ROOT_ENTRY } from "./fixtures/staging-stub-root.js";

// Mock the inner v1.1 verifier so we can drive its outcome deterministically.
const verifyReceiptEnvelope = vi.fn();
vi.mock("../verify-1.1.js", () => ({
  verifyReceiptEnvelope: (envelope: unknown, opts: unknown) =>
    verifyReceiptEnvelope(envelope, opts),
}));

// The bundle's trust anchor is pinned but not embedded, so the verifier checks
// jwks-history.jws against the ACTIVE root. When that root was the staging
// stub, the signature check short-circuited to `embedded_root_not_production`;
// with `allowStagingRoots: true` the bundle was accepted WITHOUT verifying the
// history signature at all (the fixture signature was literally "fakesig").
// Now the active root is a test root whose private key we hold, so the happy
// path verifies a real signature, and the stub path is opted into explicitly.
const anchor = vi.hoisted(() => ({ active: null as IssuerRootEntry | null }));
vi.mock("../embedded-issuer-root.js", async (importOriginal) => {
  const real =
    await importOriginal<typeof import("../embedded-issuer-root.js")>();
  return {
    ...real,
    getActiveIssuerRoot: () => anchor.active ?? real.getActiveIssuerRoot(),
  };
});

const { verifyExportBundle } = await import("../verify-export-bundle.js");

const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");

function makeTestRoot() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const entry: IssuerRootEntry = {
    pem,
    sha256: sha256Hex(pem),
    validFrom: 0,
    validTo: null,
    verifierMinVersion: "test",
  };
  return { entry, privateKey };
}

const TEST_ROOT = makeTestRoot();
const TRUST_ANCHOR_PEM = TEST_ROOT.entry.pem;
const TRUST_ANCHOR_SHA256 = TEST_ROOT.entry.sha256;

async function signHistory(
  privateKey: ReturnType<typeof makeTestRoot>["privateKey"]
): Promise<string> {
  // Payload {"entries":[]} — the verifier requires an entries[] array.
  return new CompactSign(
    new TextEncoder().encode(JSON.stringify({ entries: [] }))
  )
    .setProtectedHeader({ alg: "EdDSA" })
    .sign(privateKey);
}

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

// Signed by TEST_ROOT. A history signed by any other key must be rejected.
const JWKS_HISTORY_JWS = await signHistory(TEST_ROOT.privateKey);
const FORGED_JWKS_HISTORY_JWS = await signHistory(makeTestRoot().privateKey);

// The snapshot is now bound to the signed body, so the fixture carries a
// real key and the mocked inner verifier returns a body committing to its digest.
const JWKS_SNAPSHOT = {
  keys: [{ kty: "OKP", crv: "Ed25519", x: "AAAA", kid: "k1" }],
};
const RECEIPT_BODY = {
  verification_methods: {
    jwks: { uri: "https://x/jwks.json", kid: "k1" },
    jwks_sha256: createHash("sha256")
      .update(canonicalize({ keys: JWKS_SNAPSHOT.keys }) as string, "utf8")
      .digest("hex"),
    trust_anchor_sha256: "a".repeat(64),
  },
};

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
  anchor.active = TEST_ROOT.entry;
});

describe("verifyExportBundle", () => {
  it("happy path → accepted with retention metadata + envelopeVerifyResult", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted",
      schema_version: "1.1",
      warnings: [],
      envelope: RECEIPT_ENVELOPE,
      receipt: RECEIPT_BODY,
      recomputedLegalPosture: "ades_candidate_no_tsa",
    });

    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
    });

    expect(result.outcome).toBe("accepted");
    expect(result.retentionMetadata).toBeDefined();
    expect(result.envelopeVerifyResult).toBeDefined();
    expect(result.filesPresent).toContain("receipt-envelope.json");
    expect(result.filesPresent).toContain("trust-anchor.pem");
    // The history signature was verified, not skipped as a staging root.
    expect(result.warnings).not.toContain(
      "jwks_history_signature_unverifiable_staging_root"
    );
  });

  it("rejects a jwks-history.jws signed by a key other than the root", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted",
      schema_version: "1.1",
      warnings: [],
      envelope: RECEIPT_ENVELOPE,
      receipt: RECEIPT_BODY,
    });
    const zip = buildFixtureZip({ jwksHistoryJws: FORGED_JWKS_HISTORY_JWS });
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
    });
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jwks_history_signature_invalid");
    expect(verifyReceiptEnvelope).not.toHaveBeenCalled();
  });

  // Audit §B1 follow-up: `accepted_degraded` is a THIRD outcome. The bundle
  // used to branch on `=== "rejected"`, so a degraded envelope fell straight
  // through to the plain `accepted` return — silently laundering a receipt with
  // an unverifiable trust anchor into an evidence bundle that looks fully
  // verified. That is exactly the confusion the new outcome exists to prevent,
  // and this is the dispute-evidence artifact, so it must not be papered over.
  it("propagates accepted_degraded instead of upgrading it to accepted", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted_degraded",
      schema_version: "1.1",
      warnings: ["trust_anchor_staging"],
      envelope: RECEIPT_ENVELOPE,
      receipt: RECEIPT_BODY,
      recomputedLegalPosture: "simple_electronic_seal",
    });

    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
    });

    expect(result.outcome).toBe("accepted_degraded");
    expect(result.outcome).not.toBe("accepted");
    expect(result.warnings).toContain("trust_anchor_staging");
    // The bundle is still usable — the envelope and metadata are returned so a
    // consumer can inspect the degraded evidence rather than being stonewalled.
    expect(result.envelope).toBeDefined();
    expect(result.retentionMetadata).toBeDefined();
    expect(result.envelopeVerifyResult?.outcome).toBe("accepted_degraded");
  });

  it("keeps a fully-verified bundle reporting plain accepted", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted",
      schema_version: "1.1",
      warnings: [],
      envelope: RECEIPT_ENVELOPE,
      receipt: RECEIPT_BODY,
      recomputedLegalPosture: "ades_candidate_no_tsa",
    });

    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
    });

    expect(result.outcome).toBe("accepted");
  });

  it("P2b: forwards mode='strict' to the inner verifier by DEFAULT (GA path)", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted",
      schema_version: "1.1",
      warnings: [],
      envelope: RECEIPT_ENVELOPE,
      receipt: RECEIPT_BODY,
    });

    const zip = buildFixtureZip();
    await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
    });

    expect(verifyReceiptEnvelope).toHaveBeenCalledTimes(1);
    const opts = verifyReceiptEnvelope.mock.calls[0]![1] as { mode?: string };
    expect(opts.mode).toBe("strict");
  });

  it("P2b: honors an explicit mode='compat' opt-out", async () => {
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted",
      schema_version: "1.1",
      warnings: [],
      envelope: RECEIPT_ENVELOPE,
      receipt: RECEIPT_BODY,
    });

    const zip = buildFixtureZip();
    await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      mode: "compat",
    });

    const opts = verifyReceiptEnvelope.mock.calls[0]![1] as { mode?: string };
    expect(opts.mode).toBe("compat");
  });

  it("default (no allowStagingRoots) rejects bundle under staging-stub root", async () => {
    anchor.active = STAGING_STUB_ROOT_ENTRY;
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

  it("allowStagingRoots: true accepts under the stub root, flagged as unverifiable", async () => {
    anchor.active = STAGING_STUB_ROOT_ENTRY;
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "accepted",
      schema_version: "1.1",
      warnings: [],
      envelope: RECEIPT_ENVELOPE,
      receipt: RECEIPT_BODY,
    });
    const zip = buildFixtureZip();
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
      allowStagingRoots: true,
    });
    expect(result.outcome).not.toBe("rejected");
    expect(result.warnings).toContain(
      "jwks_history_signature_unverifiable_staging_root"
    );
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
    });

    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toMatch(/required_artifact_missing|missing/);
  });

  it("rejects when required artifact is missing (trust-anchor.pem)", async () => {
    const zip = buildFixtureZip({ omit: ["trust-anchor.pem"] });
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
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
    });
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBeDefined();
    // The rejection must come FROM the inner verifier, not from an earlier
    // step — otherwise this test passes without testing propagation.
    expect(verifyReceiptEnvelope).toHaveBeenCalledTimes(1);
  });

  it("rejects when jwks-history.jws is structurally invalid", async () => {
    const zip = buildFixtureZip({ jwksHistoryJws: "not-a-jws" });
    const result = await verifyExportBundle(zip, {
      trustAnchorPemSha256: TRUST_ANCHOR_SHA256,
    });
    expect(result.outcome).toBe("rejected");
  });
});
