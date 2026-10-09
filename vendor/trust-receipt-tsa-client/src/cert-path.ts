/**
 * X.509 certificate path validation for the TSA chain.
 *
 * Resolves Codex F4 HIGH (was T430 deferred): previous verifier only
 * checked the root SHA-256 pin — intermediate signatures, validity windows,
 * and keyUsage on intermediates were NOT validated cryptographically.
 *
 * Path validation runs at the `attestedAt` time (TST genTime), NOT at
 * current wall clock — per RFC 3161 §2.4.2 the TSA cert MUST be valid at
 * the moment the timestamp was produced.
 */
import { Certificate, CertificateChainValidationEngine } from "pkijs";
import { pemToCertificate } from "./cms-verify.js";

export type CertPathReason =
  | "cert_path_signature_invalid"
  | "cert_path_expired"
  | "cert_path_key_usage_missing"
  | "cert_path_root_mismatch"
  | "cert_path_empty"
  | "cert_path_parse_error";

export interface CertPathResult {
  readonly valid: boolean;
  readonly reason?: CertPathReason;
  readonly detail?: string;
}

const KEY_USAGE_KEY_CERT_SIGN = 0x04; // bit 5 in DER bit string.

/**
 * Verify the certificate chain (leaf → intermediates → root).
 *
 * @param chainPems  PEM strings, leaf first, root last.
 * @param pinnedRootPem  PEM of the expected anchor (must equal chainPems[last]).
 * @param attestedAtSeconds  Unix seconds — validity check is performed at this time.
 */
export async function verifyCertPath(
  chainPems: readonly string[],
  pinnedRootPem: string,
  attestedAtSeconds: number
): Promise<CertPathResult> {
  if (chainPems.length === 0) {
    return invalid("cert_path_empty", "tsa_cert_chain is empty");
  }
  let chain: Certificate[];
  let root: Certificate;
  try {
    chain = chainPems.map((pem) => pemToCertificate(pem));
    root = pemToCertificate(pinnedRootPem);
  } catch (err) {
    return invalid(
      "cert_path_parse_error",
      err instanceof Error ? err.message : "parse"
    );
  }
  // Pin: chain root must equal pinned root.
  const chainRoot = chain[chain.length - 1];
  if (!chainRoot) {
    return invalid("cert_path_empty", "tsa_cert_chain is empty");
  }
  if (!certEquals(chainRoot, root)) {
    return invalid(
      "cert_path_root_mismatch",
      "chain root differs from pinned root"
    );
  }
  // Validity window check at attestedAt for each cert.
  const attestedDate = new Date(attestedAtSeconds * 1000);
  for (const cert of chain) {
    const notBefore = cert.notBefore.value as Date;
    const notAfter = cert.notAfter.value as Date;
    if (attestedDate < notBefore || attestedDate > notAfter) {
      return invalid(
        "cert_path_expired",
        `cert validity ${notBefore.toISOString()}..${notAfter.toISOString()} excludes attestedAt ${attestedDate.toISOString()}`
      );
    }
  }
  // keyCertSign on intermediates (every cert except leaf, which is index 0).
  for (let i = 1; i < chain.length; i++) {
    const cert = chain[i];
    if (cert && !hasKeyCertSign(cert)) {
      return invalid(
        "cert_path_key_usage_missing",
        `intermediate at index ${i} missing keyCertSign keyUsage`
      );
    }
  }
  // Crypto chain verification using pkijs engine.
  try {
    const leaf = chain[0];
    if (!leaf) {
      return invalid("cert_path_empty", "leaf missing");
    }
    const engine = new CertificateChainValidationEngine({
      certs: [leaf, ...chain.slice(1, -1)],
      trustedCerts: [chainRoot],
      checkDate: attestedDate,
    });
    const result = await engine.verify();
    if (!result.result) {
      return invalid(
        "cert_path_signature_invalid",
        result.resultMessage ?? "chain engine returned false"
      );
    }
    return { valid: true };
  } catch (err) {
    return invalid(
      "cert_path_signature_invalid",
      err instanceof Error ? err.message : "engine threw"
    );
  }
}

function certEquals(a: Certificate, b: Certificate): boolean {
  // Compare DER-encoded TBSCertificate as a stable identity check.
  const aDer = new Uint8Array(a.toSchema(true).toBER(false));
  const bDer = new Uint8Array(b.toSchema(true).toBER(false));
  if (aDer.length !== bDer.length) return false;
  for (let i = 0; i < aDer.length; i++) if (aDer[i] !== bDer[i]) return false;
  return true;
}

function hasKeyCertSign(cert: Certificate): boolean {
  for (const ext of cert.extensions ?? []) {
    if (ext.extnID === "2.5.29.15") {
      // keyUsage extension — parsedValue is a BitString-like object.
      const parsed = ext.parsedValue as
        | { valueBlock?: { valueHexView?: Uint8Array } }
        | undefined;
      const bytes = parsed?.valueBlock?.valueHexView;
      if (!bytes || bytes.length === 0) return false;
      const firstByte = bytes[0];
      if (firstByte === undefined) return false;
      return (firstByte & KEY_USAGE_KEY_CERT_SIGN) !== 0;
    }
  }
  return false;
}

function invalid(reason: CertPathReason, detail: string): CertPathResult {
  return { valid: false, reason, detail };
}
