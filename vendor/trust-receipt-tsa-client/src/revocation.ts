/**
 * OCSP / CRL revocation evidence cryptographic verification.
 *
 * Resolves Codex F4 HIGH (was T430 deferred): previous verifier only
 * checked that `revocation_evidence.data_b64` was non-empty — no parsing,
 * no signature verification, no status check, no freshness window.
 *
 * Per RFC 3161 §2.4.2, the TSA leaf cert MUST NOT be revoked at TST genTime.
 */
import * as asn1js from "asn1js";
import {
  BasicOCSPResponse,
  Certificate,
  CertificateRevocationList,
  OCSPResponse,
} from "pkijs";

export type RevocationReason =
  | "ocsp_parse_error"
  | "ocsp_signature_invalid"
  | "ocsp_status_revoked"
  | "ocsp_status_unknown"
  | "ocsp_stale"
  | "crl_parse_error"
  | "crl_signature_invalid"
  | "crl_serial_revoked"
  | "crl_stale"
  | "revocation_kind_unsupported"
  | "revocation_unavailable"
  | "revocation_data_missing";

export interface RevocationVerifyResult {
  readonly valid: boolean;
  readonly reason?: RevocationReason;
  readonly detail?: string;
}

/**
 * Input shape accepted by {@link verifyRevocation}. The `unavailable` variant
 * carries a structured `reason` enum + `attempted_at` (T-CR-008). For
 * `ocsp` / `crl` variants `data_b64` is the ASN.1 DER-encoded response.
 */
export interface RevocationEvidenceInput {
  readonly kind: "ocsp" | "crl" | "unavailable";
  readonly data_b64?: string;
  readonly reason?: string;
  readonly attempted_at?: number;
}

const TOLERANCE_SECONDS = 24 * 60 * 60; // 24h tolerance when nextUpdate absent.

export async function verifyRevocation(
  evidence: RevocationEvidenceInput,
  leafCert: Certificate,
  issuerCert: Certificate,
  attestedAtSeconds: number
): Promise<RevocationVerifyResult> {
  if (evidence.kind === "unavailable") {
    return invalid(
      "revocation_unavailable",
      `unavailable: ${evidence.reason ?? "unknown"}`
    );
  }
  if (!evidence.data_b64 || evidence.data_b64.length === 0) {
    return invalid("revocation_data_missing", "empty data_b64");
  }
  const der = Buffer.from(evidence.data_b64, "base64");
  if (evidence.kind === "ocsp") {
    return verifyOcsp(der, leafCert, issuerCert, attestedAtSeconds);
  }
  if (evidence.kind === "crl") {
    return verifyCrl(der, leafCert, issuerCert, attestedAtSeconds);
  }
  return invalid(
    "revocation_kind_unsupported",
    `kind=${String(evidence.kind)}`
  );
}

async function verifyOcsp(
  der: Uint8Array,
  leafCert: Certificate,
  issuerCert: Certificate,
  attestedAtSeconds: number
): Promise<RevocationVerifyResult> {
  let basicResp: BasicOCSPResponse;
  try {
    const asn = asn1js.fromBER(toBuffer(der));
    if (asn.offset === -1) {
      return invalid("ocsp_parse_error", "fromBER failed");
    }
    // Outer envelope may be either OCSPResponse (with responseBytes) OR
    // a raw BasicOCSPResponse — accept both.
    let basicSchema = asn.result;
    try {
      const ocspResp = new OCSPResponse({ schema: asn.result });
      const respBytes = ocspResp.responseBytes;
      if (respBytes?.response) {
        const inner = asn1js.fromBER(respBytes.response.valueBlock.valueHex);
        if (inner.offset === -1) {
          return invalid("ocsp_parse_error", "responseBytes inner");
        }
        basicSchema = inner.result;
      }
    } catch {
      // Not OCSPResponse — try BasicOCSPResponse directly.
    }
    basicResp = new BasicOCSPResponse({ schema: basicSchema });
  } catch (err) {
    return invalid(
      "ocsp_parse_error",
      err instanceof Error ? err.message : "parse"
    );
  }
  // Crypto signature verification.
  try {
    const sigOk = await basicResp.verify({ trustedCerts: [issuerCert] });
    if (!sigOk) {
      return invalid(
        "ocsp_signature_invalid",
        "BasicOCSPResponse.verify=false"
      );
    }
  } catch (err) {
    return invalid(
      "ocsp_signature_invalid",
      err instanceof Error ? err.message : "verify threw"
    );
  }
  // Locate the SingleResponse for our leaf cert via serial match.
  const responses = basicResp.tbsResponseData.responses;
  const leafSerial = leafCert.serialNumber.valueBlock.toString();
  const single = responses.find((r) => {
    return r.certID.serialNumber.valueBlock.toString() === leafSerial;
  });
  if (!single) {
    return invalid(
      "ocsp_parse_error",
      `no SingleResponse for serial ${leafSerial}`
    );
  }
  // certStatus is a CHOICE — pkijs exposes the chosen variant via certStatus.idBlock.tagNumber.
  const tag = single.certStatus.idBlock?.tagNumber;
  // 0=good, 1=revoked, 2=unknown
  if (tag === 1) {
    return invalid("ocsp_status_revoked", `serial ${leafSerial}`);
  }
  if (tag === 2) {
    return invalid("ocsp_status_unknown", `serial ${leafSerial}`);
  }
  // Freshness window.
  const thisUpdate = readPkijsDate(single.thisUpdate);
  const nextUpdate = single.nextUpdate
    ? readPkijsDate(single.nextUpdate)
    : undefined;
  const attestedMs = attestedAtSeconds * 1000;
  if (thisUpdate.getTime() > attestedMs + TOLERANCE_SECONDS * 1000) {
    return invalid(
      "ocsp_stale",
      `thisUpdate=${thisUpdate.toISOString()} > attestedAt+tol`
    );
  }
  if (nextUpdate && nextUpdate.getTime() < attestedMs) {
    return invalid(
      "ocsp_stale",
      `nextUpdate=${nextUpdate.toISOString()} < attestedAt`
    );
  }
  return { valid: true };
}

async function verifyCrl(
  der: Uint8Array,
  leafCert: Certificate,
  issuerCert: Certificate,
  attestedAtSeconds: number
): Promise<RevocationVerifyResult> {
  let crl: CertificateRevocationList;
  try {
    const asn = asn1js.fromBER(toBuffer(der));
    if (asn.offset === -1) return invalid("crl_parse_error", "fromBER failed");
    crl = new CertificateRevocationList({ schema: asn.result });
  } catch (err) {
    return invalid(
      "crl_parse_error",
      err instanceof Error ? err.message : "parse"
    );
  }
  try {
    const ok = await crl.verify({ issuerCertificate: issuerCert });
    if (!ok) {
      return invalid("crl_signature_invalid", "CRL.verify=false");
    }
  } catch (err) {
    return invalid(
      "crl_signature_invalid",
      err instanceof Error ? err.message : "verify threw"
    );
  }
  // Freshness.
  const attestedMs = attestedAtSeconds * 1000;
  // pkijs Time type — for OCSP it wraps `{ value: Date }`; for CRL it can
  // surface as a plain Date in some pkijs versions. Normalize both shapes.
  const thisUpdate = readPkijsDate(crl.thisUpdate);
  const nextUpdate = crl.nextUpdate ? readPkijsDate(crl.nextUpdate) : undefined;
  if (thisUpdate.getTime() > attestedMs + TOLERANCE_SECONDS * 1000) {
    return invalid("crl_stale", `thisUpdate too late`);
  }
  if (nextUpdate && nextUpdate.getTime() < attestedMs) {
    return invalid("crl_stale", `nextUpdate too early`);
  }
  // Serial in revokedCertificates?
  const leafSerial = leafCert.serialNumber.valueBlock.toString();
  for (const r of crl.revokedCertificates ?? []) {
    if (r.userCertificate.valueBlock.toString() === leafSerial) {
      return invalid("crl_serial_revoked", `serial ${leafSerial} revoked`);
    }
  }
  return { valid: true };
}

function readPkijsDate(value: unknown): Date {
  if (value instanceof Date) return value;
  if (
    value &&
    typeof value === "object" &&
    "value" in value &&
    (value as { value: unknown }).value instanceof Date
  ) {
    return (value as { value: Date }).value;
  }
  throw new Error("pkijs Time has no Date value");
}

function toBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy.buffer;
}

function invalid(
  reason: RevocationReason,
  detail: string
): RevocationVerifyResult {
  return { valid: false, reason, detail };
}
