/**
 * verify-timestamp-evidence — T-CR-002 hardening tests.
 *
 * Codex P1 finding: pre-fix, the verifier passed the envelope-supplied
 * `evidence.tsa_root_cert_sha256` as a trust pin alongside the operator's
 * trust anchor. A malicious bundle could self-pin its own forged TSA chain.
 *
 * Post-fix contract:
 *   1. Envelope-claimed TSA root MUST be in `tsaRootCertSha256Allowlist`.
 *   2. Empty allowlist with no `trustAnchorPemSha256` ⇒ fail-closed
 *      (`tsa_root_not_trusted`).
 *   3. Empty allowlist + non-empty `trustAnchorPemSha256` falls back to
 *      `[trustAnchorPemSha256]` (back-compat: issuer = TSA root).
 *   4. The pin set passed to `verifyTimestamp` is the operator-controlled
 *      list, never the envelope-supplied root.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";

// Mock the TSA client BEFORE importing the SUT so the mock is hoisted.
const verifyTimestampMock = vi.fn();
vi.mock("@agenticmcpstores/trust-receipt-tsa-client", () => ({
  verifyTimestamp: (opts: unknown) => verifyTimestampMock(opts),
}));

// eslint-disable-next-line import/first
import {
  verifyTimestampEvidence,
  TSA_ROOT_NOT_TRUSTED_ERROR_CODE,
} from "../verify-timestamp-evidence.js";
// eslint-disable-next-line import/first
import type {
  ReceiptEnvelope,
  TrustReceiptV11Body,
  TimestampEvidence,
} from "../types-1.1.js";

const TRUSTED_ROOT_HEX = "a".repeat(64);
const ALT_TRUSTED_ROOT_HEX = "b".repeat(64);
const MALICIOUS_ROOT_HEX = "c".repeat(64);
const ISSUER_TRUST_ANCHOR_HEX = "d".repeat(64);

function makeEvidence(rootSha256: string): TimestampEvidence {
  return {
    type: "RFC3161",
    tsa_endpoint: "https://tsa.example.com",
    tsr: "AAAA",
    tst: "AAAA",
    issued_at_attested: 1_700_000_000,
    imprint_algo: "sha-256",
    imprint_target: "jws_compact_bytes",
    nonce: "00".repeat(16),
    policy_oid: "1.2.3.4",
    tsa_cert_chain: [
      "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
    ],
    tsa_root_cert_sha256: rootSha256,
    revocation_evidence: { kind: "ocsp", data_b64: "AAAA" },
    tolerance_seconds: 60,
  };
}

function makeEnvelope(rootSha256: string): ReceiptEnvelope {
  return {
    receipt: "header.payload.sig",
    envelope_metadata: {
      schema_version: "1.1",
      receipt_id: "rcpt-test",
      legal_posture: "ades_candidate_timestamped",
      legal_posture_warnings: [],
    },
    timestamp_evidence: makeEvidence(rootSha256),
  } as unknown as ReceiptEnvelope;
}

const RECEIPT_BODY = {
  issued_at: 1_700_000_010,
} as unknown as TrustReceiptV11Body;

describe("verifyTimestampEvidence — T-CR-002 root pin hardening", () => {
  beforeEach(() => {
    verifyTimestampMock.mockReset();
    verifyTimestampMock.mockResolvedValue({
      valid: true,
      attestedAt: 1_700_000_000,
      tsa: "https://tsa.example.com",
      policyOid: "1.2.3.4",
    });
  });

  it("accepts when envelope root is in operator allowlist", async () => {
    const result = await verifyTimestampEvidence({
      envelope: makeEnvelope(TRUSTED_ROOT_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [TRUSTED_ROOT_HEX, ALT_TRUSTED_ROOT_HEX],
    });

    expect(result.evidenceType).toBe("RFC3161");
    expect(result.valid).toBe(true);
    expect(verifyTimestampMock).toHaveBeenCalledTimes(1);
    const passedPins =
      verifyTimestampMock.mock.calls[0]?.[0]?.rootCertSha256Pins;
    // Operator allowlist only — never the issuer trust anchor when allowlist is set.
    expect(passedPins).toEqual([TRUSTED_ROOT_HEX, ALT_TRUSTED_ROOT_HEX]);
    // The envelope-supplied root must NOT have been smuggled in as a pin.
    expect(passedPins).not.toContain(MALICIOUS_ROOT_HEX);
  });

  it("rejects with tsa_root_not_trusted when envelope root is NOT in allowlist", async () => {
    const result = await verifyTimestampEvidence({
      envelope: makeEnvelope(MALICIOUS_ROOT_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [TRUSTED_ROOT_HEX],
    });

    expect(result.evidenceType).toBe("RFC3161");
    expect(result.valid).toBe(false);
    if ("errorCode" in result) {
      expect(result.errorCode).toBe(TSA_ROOT_NOT_TRUSTED_ERROR_CODE);
    } else {
      throw new Error("expected RFC3161 result with errorCode");
    }
    // Crypto verification must NOT run when the root is rejected up-front.
    expect(verifyTimestampMock).not.toHaveBeenCalled();
  });

  it("rejects fail-closed when allowlist is empty AND no trust anchor (envelope cannot self-pin)", async () => {
    const result = await verifyTimestampEvidence({
      envelope: makeEnvelope(MALICIOUS_ROOT_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: "",
      tsaRootCertSha256Allowlist: [],
    });

    expect(result.evidenceType).toBe("RFC3161");
    expect(result.valid).toBe(false);
    if ("errorCode" in result) {
      expect(result.errorCode).toBe(TSA_ROOT_NOT_TRUSTED_ERROR_CODE);
      expect(result.errorDetail).toMatch(/no TSA roots configured/i);
    } else {
      throw new Error("expected RFC3161 result with errorCode");
    }
    expect(verifyTimestampMock).not.toHaveBeenCalled();
  });

  it("rejects fail-closed when allowlist is omitted AND no trust anchor", async () => {
    const result = await verifyTimestampEvidence({
      envelope: makeEnvelope(TRUSTED_ROOT_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: "",
      // tsaRootCertSha256Allowlist omitted — defaults to [].
    });

    expect(result.valid).toBe(false);
    if ("errorCode" in result) {
      expect(result.errorCode).toBe(TSA_ROOT_NOT_TRUSTED_ERROR_CODE);
    } else {
      throw new Error("expected RFC3161 result with errorCode");
    }
    expect(verifyTimestampMock).not.toHaveBeenCalled();
  });

  it("falls back to [trustAnchorPemSha256] when allowlist is empty (back-compat: issuer = TSA root)", async () => {
    const result = await verifyTimestampEvidence({
      envelope: makeEnvelope(ISSUER_TRUST_ANCHOR_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [],
    });

    expect(result.valid).toBe(true);
    expect(verifyTimestampMock).toHaveBeenCalledTimes(1);
    const passedPins =
      verifyTimestampMock.mock.calls[0]?.[0]?.rootCertSha256Pins;
    expect(passedPins).toEqual([ISSUER_TRUST_ANCHOR_HEX]);
  });

  it("does NOT trust the envelope root via fallback when it differs from trustAnchor", async () => {
    // Even with a trust anchor present, if it doesn't match the envelope's
    // claimed root, we reject without invoking the crypto verifier.
    const result = await verifyTimestampEvidence({
      envelope: makeEnvelope(MALICIOUS_ROOT_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [],
    });

    expect(result.valid).toBe(false);
    if ("errorCode" in result) {
      expect(result.errorCode).toBe(TSA_ROOT_NOT_TRUSTED_ERROR_CODE);
    } else {
      throw new Error("expected RFC3161 result with errorCode");
    }
    expect(verifyTimestampMock).not.toHaveBeenCalled();
  });

  it("normalizes hex case when matching envelope root against allowlist", async () => {
    const result = await verifyTimestampEvidence({
      envelope: makeEnvelope(TRUSTED_ROOT_HEX.toUpperCase()),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [TRUSTED_ROOT_HEX],
    });

    expect(result.valid).toBe(true);
  });

  it("passes through unavailable evidence without consulting the allowlist", async () => {
    const envelope = {
      receipt: "header.payload.sig",
      envelope_metadata: {
        schema_version: "1.1",
        receipt_id: "rcpt-test",
        legal_posture: "ades_candidate_no_tsa",
        legal_posture_warnings: ["tsa_unavailable_fail_open"],
      },
      timestamp_evidence: {
        type: "unavailable",
        reason: "tsa_unavailable_fail_open",
        attempted_at: 1_700_000_000,
        attempted_tsa: ["https://tsa.example.com"],
      },
    } as unknown as ReceiptEnvelope;

    const result = await verifyTimestampEvidence({
      envelope,
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [],
    });

    expect(result.evidenceType).toBe("unavailable");
    expect(result.valid).toBe(false);
    expect(verifyTimestampMock).not.toHaveBeenCalled();
  });

  it("plumbs merchantTsaPolicy=fail_closed through to verifyTimestamp (T-CR-007)", async () => {
    await verifyTimestampEvidence({
      envelope: makeEnvelope(TRUSTED_ROOT_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [TRUSTED_ROOT_HEX],
      merchantTsaPolicy: "fail_closed",
    });
    const arg = verifyTimestampMock.mock.calls[0]?.[0];
    expect(arg?.merchantPolicy).toBe("fail_closed");
  });

  it("plumbs merchantTsaPolicy=fail_open through to verifyTimestamp (T-CR-007)", async () => {
    await verifyTimestampEvidence({
      envelope: makeEnvelope(TRUSTED_ROOT_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [TRUSTED_ROOT_HEX],
      merchantTsaPolicy: "fail_open",
    });
    const arg = verifyTimestampMock.mock.calls[0]?.[0];
    expect(arg?.merchantPolicy).toBe("fail_open");
  });

  it("omits merchantPolicy when caller does not pass it (TSA client default applies)", async () => {
    await verifyTimestampEvidence({
      envelope: makeEnvelope(TRUSTED_ROOT_HEX),
      receipt: RECEIPT_BODY,
      policyOidAllowlist: ["1.2.3.4"],
      trustAnchorPemSha256: ISSUER_TRUST_ANCHOR_HEX,
      tsaRootCertSha256Allowlist: [TRUSTED_ROOT_HEX],
    });
    const arg = verifyTimestampMock.mock.calls[0]?.[0];
    expect(arg?.merchantPolicy).toBeUndefined();
  });
});
