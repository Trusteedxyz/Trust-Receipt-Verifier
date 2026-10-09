import { buildTimeStampRequest } from "./tsa-request.js";
import { derBytes, parseAllDer } from "./der.js";
import { defaultTsaTokenBucket, type TokenBucket } from "./token-bucket.js";
import {
  freeTSA,
  resolveProvider,
  type MerchantTsaConfig,
  type TsaProviderConfig,
} from "./tsa-providers.js";
import {
  verifyTimestamp,
  type TimestampEvidenceLike,
  type TimestampRevocationEvidence,
  type TimestampVerificationResult,
} from "./tsa-verify.js";

export const PACKAGE_VERSION = "0.1.0";

export interface RequestTimestampOptions {
  readonly receiptPayload: Uint8Array | string;
  readonly merchant?: MerchantTsaConfig | null;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
  readonly tokenBucket?: TokenBucket;
}

export type TimestampRequestOutcome =
  | {
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
  | {
      readonly type: "unavailable";
      readonly reason:
        | "tsa_unavailable"
        | "tsa_error"
        | "tsa_timeout"
        | "all_providers_failed";
      readonly attempted_tsa: readonly string[];
      readonly attempted_at: number;
    };

export async function requestTimestamp(
  options: RequestTimestampOptions
): Promise<TimestampRequestOutcome> {
  const fetcher = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 200;
  const bucket = options.tokenBucket ?? defaultTsaTokenBucket;
  const resolved = resolveProvider(options.merchant);
  const providers = [resolved.primary, ...resolved.alternates];
  const attempted: string[] = [];

  for (const provider of providers) {
    attempted.push(provider.endpoint);
    const allowed = await bucket.take();
    if (!allowed) continue;

    const request = buildTimeStampRequest({
      payload: options.receiptPayload,
      policyOid: provider.policyOid,
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetcher(provider.endpoint, {
        method: "POST",
        headers: { "content-type": "application/timestamp-query" },
        body: request.der,
        signal: controller.signal,
      });
      if (!response.ok) continue;
      const tsr = new Uint8Array(await response.arrayBuffer());
      const tsrBase64 = Buffer.from(tsr).toString("base64");
      // T555 (post-Codex round 2 D25): `tsr` is the FULL TimeStampResp Base64;
      // `tst` is the TimeStampToken (PKCS#7 ContentInfo) extracted from
      // `tsr.children[1]`. Verifier confirms PKIStatusInfo.status == granted
      // (tsr.children[0].children[0]) and asserts the embedded token equals
      // `tst`. Falling back to the full TSR is incorrect because callers MUST
      // be able to detach + archive the TST independently of the wrapping
      // PKIStatusInfo response.
      let tstBase64: string;
      try {
        const tsrParsed = parseAllDer(tsr);
        const tokenNode = tsrParsed.children[1];
        if (!tokenNode) throw new Error("TimeStampToken missing in TSR");
        tstBase64 = Buffer.from(derBytes(tsr, tokenNode)).toString("base64");
      } catch {
        // If the TSR is malformed (extremely rare; TSA returned a non-granted
        // status and elided the token), surface the FULL TSR so callers still
        // have evidence — verifier will catch via PKIStatus check.
        tstBase64 = tsrBase64;
      }
      return {
        type: "RFC3161",
        tsa_endpoint: provider.endpoint,
        tsr: tsrBase64,
        tst: tstBase64,
        issued_at_attested: Math.floor(Date.now() / 1000),
        imprint_algo: "sha-256",
        imprint_target: "jws_compact_bytes",
        nonce: request.nonceHex,
        policy_oid: provider.policyOid ?? "0.0",
        tsa_cert_chain: [provider.rootCertPem],
        tsa_root_cert_sha256: provider.rootCertSha256,
        revocation_evidence: {
          kind: "ocsp",
          data_b64: "unavailable-live-fetch",
        },
        tolerance_seconds: 60,
      };
    } catch {
      // Alternate providers are tried before fail-open evidence is returned.
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    type: "unavailable",
    reason: attempted.length === 0 ? "tsa_unavailable" : "all_providers_failed",
    attempted_tsa: attempted,
    attempted_at: Math.floor(Date.now() / 1000),
  };
}

export {
  buildTimeStampRequest,
  freeTSA,
  resolveProvider,
  verifyTimestamp,
  type MerchantTsaConfig,
  type TimestampEvidenceLike,
  type TimestampVerificationResult,
  type TsaProviderConfig,
};
export type {
  MerchantTsaPolicy,
  TimestampRevocationEvidence,
} from "./tsa-verify.js";
export { verifyCmsSignerInfo, pemToCertificate } from "./cms-verify.js";
export { verifyCertPath } from "./cert-path.js";
export { verifyRevocation } from "./revocation.js";
