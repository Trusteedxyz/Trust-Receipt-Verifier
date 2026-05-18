/**
 * TrustReceipt v1.1 conformance test vectors — runner.
 *
 * Scope: 10 vectors in `test-vectors/v11/`:
 * - 011 buyer_agent happy path             — accepted
 * - 012 missing consent context             — rejected: missing_required_consent_context
 * - 013 receipt_subject mismatch            — rejected: receipt_subject_mismatch
 * - 017 legacy v1.0 receipt                — accepted via dispatcher → v1.0
 * - 018 pii_absent classification           — accepted
 * - 019 x402 evm_permit2                   — accepted (payment_authorization_hash + authorization_scheme)
 * - 019b x402 missing payment_authorization_hash   — rejected: schema_invalid
 * - 020 MCP mcp_tool_invocation             — accepted (authorization_scheme=mcp_tool_invocation)
 *
 * Vector 016 (rotated key export bundle) is NOT in scope here — it belongs to
 *.
 *
 * The vectors carry `verify_options.jwks` (raw JWKS) but the v1.1 verifier
 * accepts a `SignedJwksHistory` bundle. The runner builds an unsigned-but
 * structurally-valid `SignedJwksHistory` adapter on the fly: the verifier
 * parses the inner JWS payload by base64url-decoding the middle segment
 * without checking the outer signature (see
 * `parseJwksHistoryPayload` in verify-1.1.ts).
 *
 * The runner also implements a tiny dispatcher: legacy v1.0 envelopes
 * (carrying `legacy_v1_0: true` and a top-level `receipt` JWS) are routed to
 * `verifyReceiptV10` and the dispatcher appends `legacy_pre_eidas_hardening`
 * to the warnings list (per the expectation).
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyReceiptEnvelope } from "../verify-1.1.js";
import type { VerifyOptions } from "../verify-1.1.js";
import { verifyReceiptV10 } from "../verify-1.0.js";
import type { SignedJwksHistory } from "../types-1.1.js";
import type { PublicJwk } from "../verifier.js";

// ---------------------------------------------------------------------------
// Vector loading
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const VECTORS_DIR = join(__dirname, "..", "..", "test-vectors", "v11");

interface ExpectedShape {
  outcome: "accepted" | "rejected";
  errorCode: string | null;
  recomputed_legal_posture: string | null;
  warnings: string[];
}

interface VerifyOptionsShape {
  currentTime: number;
  expectedSubject?: "buyer_agent" | "merchant_admin";
  jwks: { keys: PublicJwk[] };
  tsa_root_pins?: string[];
}

interface VectorFile {
  vector_id: string;
  title: string;
  envelope: Record<string, unknown> & { legacy_v1_0?: boolean };
  expected: ExpectedShape;
  verify_options: VerifyOptionsShape;
}

function loadVector(name: string): VectorFile {
  const raw = readFileSync(join(VECTORS_DIR, name), "utf8");
  return JSON.parse(raw) as VectorFile;
}

const IN_SCOPE = [
  "011-buyer-agent-happy-path.json",
  "012-missing-consent-context.json",
  "013-receipt-subject-mismatch.json",
  "014-valid-timestamp-evidence.json",
  "015-timestamp-unavailable.json",
  "017-legacy-v10-receipt.json",
  "018-pii-absent.json",
  "019-v11-x402-permit2-required.json",
  "019b-v11-x402-missing-permit2.json",
  "020-v11-mcp-tool-invocation-required.json",
] as const;

// ---------------------------------------------------------------------------
// JWKS-history adapter (parses without signature verification — see file JSDoc)
// ---------------------------------------------------------------------------

function jwksToSignedHistory(
  jwks: { keys: PublicJwk[] },
  validFrom: number
): SignedJwksHistory {
  const payload = {
    schema_version: "1.0",
    entries: jwks.keys.map((k) => ({
      kid: (k as { kid?: string }).kid ?? "",
      jwk_pub: k as unknown as Record<string, unknown>,
      valid_from: validFrom - 86_400,
      valid_to: null,
    })),
    history_chain_sha256:
      "0000000000000000000000000000000000000000000000000000000000000000",
  };
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA" }), "utf8").toString(
    "base64url"
  );
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url"
  );
  // Signature segment is irrelevant — verifier does not check the outer JWS
  // for jwksHistory (see parseJwksHistoryPayload in verify-1.1.ts).
  const fakeSig = "AA";
  return {
    jws_compact: `${header}.${body}.${fakeSig}`,
    signed_by_root_sha256:
      "0000000000000000000000000000000000000000000000000000000000000000",
  };
}

// ---------------------------------------------------------------------------
// Tiny dispatcher (schema-version routing)
// ---------------------------------------------------------------------------

interface DispatchResult {
  outcome: "accepted" | "rejected";
  schema_version: "1.0" | "1.1";
  errorCode: string | null;
  warnings: string[];
  dispatched_to: "v1.0" | "v1.1";
  recomputedLegalPosture?: string;
}

async function dispatch(vector: VectorFile): Promise<DispatchResult> {
  // Legacy v1.0 envelope detection — flag set by issuer + `receipt` only.
  if (vector.envelope.legacy_v1_0 === true) {
    const compact = vector.envelope.receipt;
    if (typeof compact !== "string") {
      throw new Error("legacy_v1_0 envelope missing receipt JWS");
    }
    const v10 = await verifyReceiptV10(compact, vector.verify_options.jwks);
    return {
      outcome: v10.outcome,
      schema_version: "1.0",
      errorCode: v10.outcome === "rejected" ? (v10.errors?.[0] ?? null) : null,
      warnings: [...v10.warnings, "legacy_pre_eidas_hardening"],
      dispatched_to: "v1.0",
    };
  }

  // v1.1 path — all vectors use an all-zeros root SHA (staging stub).
  const opts: VerifyOptions = {
    jwksHistory: jwksToSignedHistory(
      vector.verify_options.jwks,
      vector.verify_options.currentTime
    ),
    trustAnchorPemSha256:
      "dd43bf2cd65023d79e41358226ed1197fcea36bc693f1c0fadde0e318bfd76a1",
    policyOidAllowlist: ["1.2.3.4.5.6.7.8.9"],
    expectedSubject: vector.verify_options.expectedSubject,
    allowStagingRoot: true,
  };
  const r = await verifyReceiptEnvelope(
    vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
    opts
  );
  return {
    outcome: r.outcome,
    schema_version: "1.1",
    errorCode: r.errorCode ?? null,
    warnings: r.warnings,
    dispatched_to: "v1.1",
    recomputedLegalPosture: r.recomputedLegalPosture,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("TrustReceipt v1.1 conformance vectors", () => {
  it.each(IN_SCOPE)("T06X — vector %s round-trips", async (name) => {
    const vector = loadVector(name);
    const result = await dispatch(vector);
    expect(result.outcome).toBe(vector.expected.outcome);
    expect(result.errorCode).toBe(vector.expected.errorCode);

    if (vector.vector_id === "017") {
      expect(result.dispatched_to).toBe("v1.0");
      expect(result.warnings).toContain("legacy_pre_eidas_hardening");
    } else if (vector.expected.recomputed_legal_posture !== null) {
      expect(result.recomputedLegalPosture).toBe(
        vector.expected.recomputed_legal_posture
      );
    }
  });

  it("T060 — vector 011 buyer_agent happy path is accepted", async () => {
    const r = await dispatch(loadVector("011-buyer-agent-happy-path.json"));
    expect(r.outcome).toBe("accepted");
    expect(r.recomputedLegalPosture).toBe("ades_candidate_timestamped");
  });

  it("T061 — vector 012 missing_required_consent_context", async () => {
    const r = await dispatch(loadVector("012-missing-consent-context.json"));
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("missing_required_consent_context");
  });

  it("T062 — vector 013 receipt_subject_mismatch", async () => {
    const r = await dispatch(loadVector("013-receipt-subject-mismatch.json"));
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("receipt_subject_mismatch");
  });

  it("T063 — vector 017 legacy v1.0 dispatched with warning", async () => {
    const r = await dispatch(loadVector("017-legacy-v10-receipt.json"));
    expect(r.outcome).toBe("accepted");
    expect(r.dispatched_to).toBe("v1.0");
    expect(r.warnings).toContain("legacy_pre_eidas_hardening");
  });

  it("T064 — vector 018 privacy_classification=pii_absent accepted", async () => {
    const r = await dispatch(loadVector("018-pii-absent.json"));
    expect(r.outcome).toBe("accepted");
    expect(r.recomputedLegalPosture).toBe("ades_candidate_timestamped");
  });

  it("T130 — vector 014 valid RFC 3161 timestamp evidence accepted", async () => {
    const r = await dispatch(loadVector("014-valid-timestamp-evidence.json"));
    expect(r.outcome).toBe("accepted");
    expect(r.recomputedLegalPosture).toBe("ades_candidate_timestamped");
  });

  it("T131 — vector 015 timestamp unavailable accepted with warning", async () => {
    const r = await dispatch(loadVector("015-timestamp-unavailable.json"));
    expect(r.outcome).toBe("accepted");
    expect(r.recomputedLegalPosture).toBe("ades_candidate_no_tsa");
    expect(r.warnings).toContain("tsa_unavailable");
  });

  it("T132 — vector 019 buyer_agent x402 with evm_permit2 authorization_scheme accepted", async () => {
    const r = await dispatch(loadVector("019-v11-x402-permit2-required.json"));
    expect(r.outcome).toBe("accepted");
    expect(r.recomputedLegalPosture).toBe("ades_candidate_timestamped");
  });

  it("T132b — vector 019b buyer_agent x402 missing payment_authorization_hash rejected", async () => {
    const r = await dispatch(loadVector("019b-v11-x402-missing-permit2.json"));
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("schema_invalid");
  });

  it("T133 — vector 020 buyer_agent MCP with mcp_tool_invocation authorization_scheme accepted", async () => {
    const r = await dispatch(
      loadVector("020-v11-mcp-tool-invocation-required.json")
    );
    expect(r.outcome).toBe("accepted");
    expect(r.recomputedLegalPosture).toBe("ades_candidate_timestamped");
  });

  it("scope sanity — exactly 10 vectors covered by–T064 +/T131 +–T133", () => {
    expect(IN_SCOPE.length).toBe(10);
    // Vector 016 (rotated key) belongs to.
    // Vectors 019/019b/020 cover payment_authorization_hash + authorization_scheme.
    const allFiles = readdirSync(VECTORS_DIR).filter((f) =>
      f.endsWith(".json")
    );
    expect(allFiles.length).toBeGreaterThanOrEqual(8);
    for (const f of IN_SCOPE) expect(allFiles).toContain(f);
  });
});
