import { createHash } from "node:crypto";

export interface TsaProviderConfig {
  readonly name: string;
  readonly endpoint: string;
  readonly policyOid?: string;
  readonly rootCertPem: string;
  readonly rootCertSha256: string;
}

export interface MerchantTsaConfig {
  readonly trustReceiptTsaEndpoint?: string | null;
  readonly trustReceiptTsaAlternate?: string | null;
  readonly trustReceiptTsaPolicy?: "fail_open" | "fail_closed" | string | null;
}

const FREETSA_ROOT_CERT_PEM = [
  "-----BEGIN CERTIFICATE-----",
  "MIIBsjCCAVigAwIBAgIUTrusteedFreeTSAScaffoldRootMAoGCCqGSM49BAMD",
  "MDExLzAtBgNVBAMMJmZyZWVUU0EgUEgtMSBTY2FmZm9sZCBSb290IC0gUmVw",
  "bGFjZSBpbiBwcm9kMB4XDTI2MDMwMTAwMDAwMFoXDTM2MDMwMTAwMDAwMFow",
  "MTEvMC0GA1UEAwwmZnJlZVRTQSBQSC0xIFNjYWZmb2xkIFJvb3QgLSBSZXBs",
  "YWNlIGluIHByb2QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATScaffoldOnly",
  "q8f4hmS9iX1sG8nMG6PpWdx6pJbVJ5o0YzjKQZGNvdGV4LXBsYWNlaG9s",
  "ZGVyLW5vdC1hLXByb2R1Y3Rpb24tdHJ1c3QtYW5jaG9yMAoGCCqGSM49",
  "BAMDA2gAMGUCMQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMHoAAAAAAAAAAAAAAAAA",
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
  "-----END CERTIFICATE-----",
  "",
].join("\n");

// T441 — SSL.com free RFC 3161 TSA alternate provider.
// Root cert scaffold: replace with live SSL.com Root CA EV RSA R2 PEM in T564.
// Endpoint: https://ts.ssl.com (standard port 443, Content-Type: application/timestamp-query).
const SSLCOM_ROOT_CERT_PEM = [
  "-----BEGIN CERTIFICATE-----",
  "SCAFFOLD_SSLCOM_ROOT_REPLACE_IN_T564_ssl_com_root_ca_ev_rsa_r2",
  "-----END CERTIFICATE-----",
  "",
].join("\n");

function pemSha256(pem: string): string {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return createHash("sha256").update(Buffer.from(b64, "base64")).digest("hex");
}

export const freeTSA: TsaProviderConfig = {
  name: "freetsa",
  endpoint: "https://freetsa.org/tsr",
  rootCertPem: FREETSA_ROOT_CERT_PEM,
  rootCertSha256: pemSha256(FREETSA_ROOT_CERT_PEM),
};

// T441 — ssl.com/free is the default system alternate when the merchant has not
// configured their own alternate endpoint. Automatic failover in index.ts iterates
// [primary, ...alternates] in order; ssl.com is tried before the fail-open path.
export const sslComTSA: TsaProviderConfig = {
  name: "ssl.com-free",
  endpoint: "https://ts.ssl.com",
  rootCertPem: SSLCOM_ROOT_CERT_PEM,
  rootCertSha256: pemSha256(SSLCOM_ROOT_CERT_PEM),
};

export function resolveProvider(merchant?: MerchantTsaConfig | null): {
  readonly primary: TsaProviderConfig;
  readonly alternates: readonly TsaProviderConfig[];
  readonly policy: "fail_open" | "fail_closed";
} {
  const primary = merchant?.trustReceiptTsaEndpoint
    ? {
        ...freeTSA,
        name: "merchant-primary",
        endpoint: merchant.trustReceiptTsaEndpoint,
      }
    : freeTSA;

  // Merchant-configured alternate takes precedence; fall back to ssl.com system default.
  const alternates: TsaProviderConfig[] = merchant?.trustReceiptTsaAlternate
    ? [
        {
          ...freeTSA,
          name: "merchant-alternate",
          endpoint: merchant.trustReceiptTsaAlternate,
        },
      ]
    : [sslComTSA];

  return {
    primary,
    alternates,
    policy:
      merchant?.trustReceiptTsaPolicy === "fail_closed"
        ? "fail_closed"
        : "fail_open",
  };
}
