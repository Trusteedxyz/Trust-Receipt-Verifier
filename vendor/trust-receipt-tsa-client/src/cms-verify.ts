/**
 * CMS SignedData verification for RFC 3161 TimeStampToken.
 *
 * Per RFC 3161 §2.4.2, the TimeStampToken is a CMS ContentInfo wrapping
 * SignedData whose eContent is a DER-encoded TSTInfo. The SignerInfo
 * signature MUST be verified against the TSA leaf certificate's public key.
 *
 * Resolves Codex F4 HIGH (was T430 deferred): previous verifier only
 * inspected EKU bytes — no cryptographic SignerInfo verification.
 */
import * as asn1js from "asn1js";
import { Certificate, ContentInfo, SignedData } from "pkijs";

export type CmsVerifyReason =
  | "cms_signer_info_missing"
  | "cms_parse_error"
  | "cms_signer_message_digest_mismatch"
  | "cms_signature_algo_unsupported"
  | "cms_signature_invalid"
  | "synthetic_fixture_cms_skipped";

export interface CmsVerifyResult {
  readonly valid: boolean;
  readonly reason?: CmsVerifyReason;
  readonly detail?: string;
  readonly warning?: CmsVerifyReason;
}

/**
 * Verify the CMS SignedData layer of a TimeStampToken.
 *
 * @param tstDer  Raw DER bytes of the TimeStampToken (CMS ContentInfo)
 * @param leafCert  pkijs Certificate of the TSA signing certificate
 *                  (must equal the cert that produced the SignerInfo)
 * @param stampedData  The bytes that were timestamped (the receipt payload).
 *                  pkijs REQUIRES them for an id-ct-TSTInfo eContent: it hashes
 *                  them against TSTInfo.messageImprint and otherwise aborts with
 *                  "Missed detached data input array", so a genuine token could
 *                  never verify (found by the TR-091 local fake TSA).
 */
export async function verifyCmsSignerInfo(
  tstDer: Uint8Array,
  leafCert: Certificate,
  stampedData?: Uint8Array
): Promise<CmsVerifyResult> {
  let signedData: SignedData;
  try {
    const asn = asn1js.fromBER(toArrayBuffer(tstDer));
    if (asn.offset === -1) {
      return invalid("cms_parse_error", "asn1 fromBER failed");
    }
    const ci = new ContentInfo({ schema: asn.result });
    signedData = new SignedData({ schema: ci.content });
  } catch (err) {
    return invalid(
      "cms_parse_error",
      err instanceof Error ? err.message : "unknown"
    );
  }
  const signers = signedData.signerInfos;
  if (!signers || signers.length === 0) {
    return invalid("cms_signer_info_missing", "no SignerInfo");
  }
  // SignedData.verify performs:
  //   - eContent ↔ messageDigest signed-attribute check
  //   - signedAttrs DER re-encoding (SET OF substitution per RFC 5652 §5.4)
  //   - signature verification via WebCrypto using the signer cert's pubkey
  try {
    const result = await signedData.verify({
      signer: 0,
      ...(stampedData ? { data: toArrayBuffer(stampedData) } : {}),
      trustedCerts: [leafCert],
      checkChain: false,
      extendedMode: true,
    });
    if (!result || result.signatureVerified !== true) {
      const code = result?.message?.includes("messageDigest")
        ? "cms_signer_message_digest_mismatch"
        : "cms_signature_invalid";
      return invalid(code, result?.message ?? "verify returned false");
    }
    return { valid: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : "verify threw";
    if (/algorithm|unsupported|not implemented/i.test(message)) {
      return invalid("cms_signature_algo_unsupported", message);
    }
    if (/messageDigest/i.test(message)) {
      return invalid("cms_signer_message_digest_mismatch", message);
    }
    return invalid("cms_signature_invalid", message);
  }
}

function invalid(reason: CmsVerifyReason, detail: string): CmsVerifyResult {
  return { valid: false, reason, detail };
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  // Always return a freshly-owned ArrayBuffer to avoid SharedArrayBuffer.
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy.buffer;
}

export function pemToCertificate(pem: string): Certificate {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const der = Buffer.from(body, "base64");
  const asn = asn1js.fromBER(toArrayBuffer(der));
  if (asn.offset === -1) throw new Error("certificate DER parse failed");
  return new Certificate({ schema: asn.result });
}
