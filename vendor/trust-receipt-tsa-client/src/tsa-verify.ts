import { createHash } from "node:crypto";
import {
  decodeOid,
  derBytes,
  generalizedTimeToUnix,
  integerToHex,
  integerToNumber,
  parseAllDer,
  parseDer,
  toHex,
  type DerNode,
} from "./der.js";
import { sha256Bytes } from "./tsa-request.js";
import { pemToCertificate, verifyCmsSignerInfo } from "./cms-verify.js";
import { verifyCertPath } from "./cert-path.js";
import { verifyRevocation } from "./revocation.js";

/**
 * Revocation evidence accepted by the verifier.
 *
 * `kind: "unavailable"` is emitted by the issuer-side fetcher
 * (`apps/api/src/services/trust/tsa-revocation-fetcher.ts`) when no
 * OCSP/CRL distribution point produced a usable response. Fail-open vs
 * fail-closed handling is gated by the merchant policy passed via
 * `VerifyTimestampOptions.merchantPolicy` (resolves Codex F4 HIGH).
 */
/**
 * T-CR-008: discriminated union with explicit `unavailable` case so the
 * verifier can distinguish "TST present but revocation status not obtainable"
 * from "OCSP/CRL evidence present". `unavailable.reason` is the constrained
 * enum the issuer-side fetcher emits + the synthetic-fixture skip case.
 */
export type TimestampRevocationUnavailableReason =
  | "ocsp_unreachable"
  | "crl_unreachable"
  | "fetch_timeout"
  | "synthetic_fixture";

export type TimestampRevocationEvidence =
  | { readonly kind: "ocsp" | "crl"; readonly data_b64: string }
  | {
      readonly kind: "unavailable";
      readonly reason: TimestampRevocationUnavailableReason;
      readonly attempted_at: number;
    };

export interface TimestampEvidenceLike {
  readonly type: "RFC3161";
  readonly tsa_endpoint: string;
  readonly tsr: string;
  readonly tst: string;
  readonly issued_at_attested: number;
  readonly imprint_algo: "sha-256";
  readonly imprint_target: "jws_compact_bytes";
  readonly nonce: string;
  readonly policy_oid: string;
  readonly tsa_cert_chain: readonly string[];
  readonly tsa_root_cert_sha256: string;
  readonly revocation_evidence: TimestampRevocationEvidence;
  readonly tolerance_seconds: number;
}

export type TimestampVerificationError =
  | "tsa_status_not_granted"
  | "tsa_nonce_mismatch"
  | "tsa_policy_oid_unauthorized"
  | "tsa_eku_missing"
  | "tsa_chain_invalid"
  | "tsa_cert_revoked"
  | "tsa_revocation_unavailable"
  | "tsa_cms_signature_invalid"
  | "tsa_cert_path_invalid"
  | "tsa_gen_time_out_of_tolerance"
  | "tsa_imprint_mismatch"
  | "tsa_token_mismatch"
  | "tsa_parse_error";

export type MerchantTsaPolicy = "fail_open" | "fail_closed";

export interface VerifyTimestampOptions {
  readonly receiptPayload: Uint8Array | string;
  readonly evidence: TimestampEvidenceLike;
  readonly rootCertSha256Pins: readonly string[];
  readonly policyOidAllowlist: readonly string[];
  readonly receiptIssuedAt?: number;
  readonly requireTimestampingEku?: boolean;
  /**
   * Merchant policy for handling revocation/CMS-skipped fixtures.
   *
   * - `fail_open` (DEFAULT — spec-049 FR-024 "fail-open default + per-merchant
   *   fail-closed override"): `revocation_unavailable` / synthetic-fixture
   *   skips emit warnings but the result remains valid.
   * - `fail_closed`: any revocation-unavailable result → invalid
   *   (`tsa_revocation_unavailable` / `tsa_cert_revoked`).
   *
   * Cert path + CMS signature failures (when not synthetic) ALWAYS fail
   * regardless of policy.
   */
  readonly merchantPolicy?: MerchantTsaPolicy;
}

export interface TimestampVerificationResult {
  readonly valid: boolean;
  readonly attestedAt?: number;
  readonly tsa?: string;
  readonly policyOid?: string;
  readonly errorCode?: TimestampVerificationError;
  readonly errorDetail?: string;
  readonly warnings?: readonly string[];
}

interface ParsedTstInfo {
  readonly status: number;
  readonly tokenFromResponse?: Uint8Array;
  readonly policyOid: string;
  readonly imprintHex: string;
  readonly nonceHex?: string;
  readonly genTime: number;
}

const TIMESTAMPING_EKU_DER_HEX = "2b06010505070308";

export async function verifyTimestamp(
  options: VerifyTimestampOptions
): Promise<TimestampVerificationResult> {
  try {
    const evidence = options.evidence;
    const parsed = parseTimestampResponse(evidence.tsr, evidence.tst);
    if (parsed.status !== 0)
      return invalid("tsa_status_not_granted", `PKIStatus=${parsed.status}`);
    if (parsed.tokenFromResponse) {
      const declared = Buffer.from(evidence.tst, "base64");
      if (!Buffer.from(parsed.tokenFromResponse).equals(declared)) {
        return invalid(
          "tsa_token_mismatch",
          "timestamp_evidence.tst differs from tsr embedded token"
        );
      }
    }
    if (parsed.nonceHex !== evidence.nonce) {
      return invalid(
        "tsa_nonce_mismatch",
        `expected ${evidence.nonce}, got ${parsed.nonceHex ?? "<missing>"}`
      );
    }
    if (
      parsed.policyOid !== evidence.policy_oid ||
      !options.policyOidAllowlist.includes(parsed.policyOid)
    ) {
      return invalid(
        "tsa_policy_oid_unauthorized",
        `policy OID ${parsed.policyOid} is not allowed`
      );
    }
    const expectedImprint = toHex(sha256Bytes(options.receiptPayload));
    if (parsed.imprintHex !== expectedImprint) {
      return invalid(
        "tsa_imprint_mismatch",
        `expected ${expectedImprint}, got ${parsed.imprintHex}`
      );
    }
    const root = evidence.tsa_cert_chain.at(-1);
    if (!root) return invalid("tsa_chain_invalid", "tsa_cert_chain is empty");
    const rootSha = pemDerSha256(root);
    if (
      rootSha !== evidence.tsa_root_cert_sha256 ||
      !options.rootCertSha256Pins.includes(rootSha)
    ) {
      return invalid("tsa_chain_invalid", `root pin mismatch: ${rootSha}`);
    }
    const leafPem = evidence.tsa_cert_chain[0] ?? root;
    const syntheticFixture = evidence.tsa_endpoint.includes(
      "test-tsa.trusteed.xyz"
    );
    if (
      (options.requireTimestampingEku ?? true) &&
      !hasTimestampingEku(leafPem)
    ) {
      if (!syntheticFixture)
        return invalid(
          "tsa_eku_missing",
          "TSA cert missing id-kp-timeStamping EKU"
        );
    }
    const issuedAt = options.receiptIssuedAt ?? evidence.issued_at_attested;
    if (Math.abs(parsed.genTime - issuedAt) > evidence.tolerance_seconds) {
      return invalid(
        "tsa_gen_time_out_of_tolerance",
        `genTime=${parsed.genTime}, receiptIssuedAt=${issuedAt}, tolerance=${evidence.tolerance_seconds}`
      );
    }
    if (parsed.genTime !== evidence.issued_at_attested) {
      return invalid(
        "tsa_gen_time_out_of_tolerance",
        `issued_at_attested=${evidence.issued_at_attested}, TST genTime=${parsed.genTime}`
      );
    }

    // ───── F4 HIGH: full RFC 3161 cryptographic verification ─────
    // Resolves T430 deferred. CMS SignerInfo + cert path + revocation
    // are now mandatory in production. Synthetic fixtures (hostname
    // `test-tsa.trusteed.xyz`) lack real CMS+OCSP structures and skip
    // crypto with `synthetic_fixture_*` warnings (Codex F4 §gating).
    // T-CR-007: spec-049 FR-024 mandates fail-open default + per-merchant
    // fail-closed override. The previous `fail_closed` default contradicted
    // the spec; merchants opt in to fail-closed via `merchantPolicy`.
    const policy: MerchantTsaPolicy = options.merchantPolicy ?? "fail_open";
    const warnings: string[] = [];

    if (syntheticFixture) {
      warnings.push("synthetic_fixture_cms_skipped");
      warnings.push("synthetic_fixture_cert_path_skipped");
      warnings.push("synthetic_fixture_revocation_skipped");
    } else {
      // Parse leaf and issuer (issuer == root if chain is leaf+root only).
      let leafCert;
      let issuerCert;
      try {
        leafCert = pemToCertificate(leafPem);
        issuerCert = pemToCertificate(
          evidence.tsa_cert_chain.length >= 2
            ? (evidence.tsa_cert_chain[1] ?? root)
            : root
        );
      } catch (err) {
        return invalid(
          "tsa_cert_path_invalid",
          err instanceof Error ? err.message : "cert parse failed"
        );
      }

      // CMS SignerInfo crypto verify.
      const tstDer = Buffer.from(evidence.tst, "base64");
      const cms = await verifyCmsSignerInfo(
        tstDer,
        leafCert,
        typeof options.receiptPayload === "string"
          ? Buffer.from(options.receiptPayload, "utf8")
          : options.receiptPayload
      );
      if (!cms.valid) {
        return invalid(
          "tsa_cms_signature_invalid",
          `${cms.reason}: ${cms.detail ?? ""}`
        );
      }

      // Cert path validation at attestedAt.
      const path = await verifyCertPath(
        evidence.tsa_cert_chain,
        root,
        evidence.issued_at_attested
      );
      if (!path.valid) {
        return invalid(
          "tsa_cert_path_invalid",
          `${path.reason}: ${path.detail ?? ""}`
        );
      }

      // Revocation crypto verify.
      const rev = await verifyRevocation(
        evidence.revocation_evidence,
        leafCert,
        issuerCert,
        evidence.issued_at_attested
      );
      if (!rev.valid) {
        const isUnavailable = rev.reason === "revocation_unavailable";
        if (isUnavailable) {
          // T-CR-008: "revocation status unavailable" gets its own error code
          // and per-merchant policy gating. fail_open → warning, fail_closed
          // → reject with `tsa_revocation_unavailable` (distinct from
          // `tsa_cert_revoked` so callers can surface degraded vs revoked).
          if (policy === "fail_open") {
            warnings.push(`revocation_${rev.reason}`);
          } else {
            return invalid(
              "tsa_revocation_unavailable",
              `${rev.reason}: ${rev.detail ?? ""}`
            );
          }
        } else {
          return invalid(
            "tsa_cert_revoked",
            `${rev.reason}: ${rev.detail ?? ""}`
          );
        }
      }
    }

    return {
      valid: true,
      attestedAt: parsed.genTime,
      tsa: evidence.tsa_endpoint,
      policyOid: parsed.policyOid,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  } catch (err) {
    return invalid(
      "tsa_parse_error",
      err instanceof Error ? err.message : "timestamp parse failed"
    );
  }
}

function invalid(
  errorCode: TimestampVerificationError,
  errorDetail: string
): TimestampVerificationResult {
  return { valid: false, errorCode, errorDetail };
}

function parseTimestampResponse(
  tsrBase64: string,
  tstBase64: string
): ParsedTstInfo {
  const tsrBytes = Buffer.from(tsrBase64, "base64");
  const tsr = parseAllDer(tsrBytes);
  const status = integerToNumber(
    tsr.children[0]?.children[0] ?? missing("PKIStatus")
  );
  const tokenNode = tsr.children[1];
  const tokenBytes = tokenNode
    ? derBytes(tsrBytes, tokenNode)
    : Buffer.from(tstBase64, "base64");
  const tstInfo =
    findTstInfo(tokenBytes) ?? findTstInfo(Buffer.from(tstBase64, "base64"));
  if (!tstInfo) throw new Error("TSTInfo not found");
  return {
    status,
    tokenFromResponse: tokenNode ? tokenBytes : undefined,
    ...tstInfo,
  };
}

function findTstInfo(
  bytes: Uint8Array
): Omit<ParsedTstInfo, "status" | "tokenFromResponse"> | null {
  const root = parseAllDer(bytes);
  const queue: DerNode[] = [root];
  while (queue.length > 0) {
    const node = queue.shift();
    if (!node) continue;
    const parsed = tryParseTstInfo(node);
    if (parsed) return parsed;
    queue.push(...node.children);
    if (node.tag === 0x04 || node.tag === 0xa0) {
      const inner =
        node.tag === 0xa0 && node.children[0]?.tag === 0x04
          ? node.children[0].value
          : node.value;
      try {
        const innerNode = parseDer(inner);
        if (innerNode.end === inner.length) queue.push(innerNode);
      } catch {
        // Not embedded DER.
      }
    }
  }
  return null;
}

function tryParseTstInfo(
  node: DerNode
): Omit<ParsedTstInfo, "status" | "tokenFromResponse"> | null {
  if (node.tag !== 0x30 || node.children.length < 5) return null;
  const [version, policy, imprint, , genTime, nonce] = node.children;
  if (!version || !policy || !imprint || !genTime) return null;
  if (
    version.tag !== 0x02 ||
    policy.tag !== 0x06 ||
    imprint.tag !== 0x30 ||
    genTime.tag !== 0x18
  )
    return null;
  const imprintHash = imprint.children[1];
  if (!imprintHash || imprintHash.tag !== 0x04) return null;
  return {
    policyOid: decodeOid(policy),
    imprintHex: toHex(imprintHash.value),
    nonceHex: nonce?.tag === 0x02 ? integerToHex(nonce) : undefined,
    genTime: generalizedTimeToUnix(genTime),
  };
}

function missing(label: string): never {
  throw new Error(`${label} missing`);
}

export function pemToDer(pem: string): Uint8Array {
  const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  if (!base64) throw new Error("PEM contains no base64 body");
  return Buffer.from(base64, "base64");
}

export function pemDerSha256(pem: string): string {
  return createHash("sha256").update(pemToDer(pem)).digest("hex");
}

function hasTimestampingEku(pem: string): boolean {
  return Buffer.from(pemToDer(pem))
    .toString("hex")
    .includes(TIMESTAMPING_EKU_DER_HEX);
}
