/**
 * Clean-room export-bundle verifier (spec-049 T153).
 *
 * Validates an export bundle ZIP entirely offline: unzips in memory, pins
 * the trust anchor, structurally validates the JWKS history JWS, delegates
 * envelope verification to {@link verifyReceiptEnvelope} (T051), and
 * surfaces retention metadata.
 *
 * Required artifacts: receipt-envelope.json, jwks-snapshot.json,
 * jwks-history.jws, trust-anchor.pem, retention-policy.json. Optional:
 * tsa-cert-chain.pem, tsa-revocation-evidence.{ocsp,crl},
 * redacted-consent-record.json, verifier-version.txt, README.md.
 *
 * TODO(T420/T421): full root-cert chain verify of jwks-history.jws against
 * trust-anchor.pem (Phase 9). Today we structurally validate the JWS and
 * pin the trust anchor by SHA-256 — that pin prevents arbitrary root
 * substitution by the bundle producer. T425 tightens this by ALSO
 * requiring the bundle's `trust-anchor.pem` to match either the
 * caller-supplied pin (R16) OR an entry in {@link EMBEDDED_ISSUER_ROOTS}
 * (T423) — bundles whose anchor is unknown to both are rejected with
 * `trust_anchor_unknown`. A JWKS bundled alone is NOT a trust anchor
 * (post-Codex round 2 D3).
 *
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-032, FR-032b, FR-033, FR-033b
 * @see specs/049-trust-receipt-eidas-hardening/research.md R6, R16, post-Codex round 2 D3
 */

import AdmZip from "adm-zip";
import { createHash } from "node:crypto";
import { verifyReceiptEnvelope } from "./verify-1.1.js";
import { verifyJwksHistorySignature } from "./verify-jwks-history.js";
import {
  EMBEDDED_ISSUER_ROOTS,
  findIssuerRootBySha256,
  getActiveIssuerRoot,
} from "./embedded-issuer-root.js";
import type {
  V11VerifyResult,
  V11VerifyErrorCode,
  VerifyOptions as V11VerifyOptions,
} from "./verify-1.1.js";
import type {
  ReceiptEnvelope,
  SignedJwksHistory,
  ReceiptSubject,
} from "./types-1.1.js";

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

export type BundleArtifactName =
  | "receipt-envelope.json"
  | "jwks-snapshot.json"
  | "jwks-history.jws"
  | "trust-anchor.pem"
  | "tsa-cert-chain.pem"
  | "tsa-revocation-evidence.ocsp"
  | "tsa-revocation-evidence.crl"
  | "redacted-consent-record.json"
  | "retention-policy.json"
  | "verifier-version.txt"
  | "README.md";

const REQUIRED_ARTIFACTS: readonly BundleArtifactName[] = [
  "receipt-envelope.json",
  "jwks-snapshot.json",
  "jwks-history.jws",
  "trust-anchor.pem",
  "retention-policy.json",
] as const;

const KNOWN_ARTIFACTS: readonly BundleArtifactName[] = [
  ...REQUIRED_ARTIFACTS,
  "tsa-cert-chain.pem",
  "tsa-revocation-evidence.ocsp",
  "tsa-revocation-evidence.crl",
  "redacted-consent-record.json",
  "verifier-version.txt",
  "README.md",
] as const;

export type BundleVerifyErrorCode =
  | "bundle_integrity_mismatch"
  | "bundle_zip_invalid"
  | "required_artifact_missing"
  | "missing_trust_anchor"
  | "missing_jwks_history"
  | "trust_anchor_pin_mismatch"
  | "trust_anchor_unknown"
  | "jwks_history_jws_invalid"
  | "jwks_history_payload_invalid"
  | "jwks_history_signature_invalid"
  | "retention_policy_invalid"
  | "envelope_invalid_json"
  | V11VerifyErrorCode;

export interface BundleVerifyOptions {
  /**
   * Optional integrity check: expected SHA-256 of the ZIP bytes (lower-hex).
   * Typically passed by the caller from the HTTP `X-Bundle-Sha256` header
   * per FR-033b.
   */
  expectedBundleSha256?: string;
  /** Trust anchor pinning (R16): SHA-256 of issuer root cert (lower-hex). */
  trustAnchorPemSha256: string;
  /** Optional policy OID allowlist for TSA validation. */
  policyOidAllowlist?: readonly string[];
  /** Optional expected receipt subject. */
  expectedSubject?: ReceiptSubject;
  /**
   * Opt-in escape hatch for staging-stub trust anchors (T-CR-001). Forwarded
   * to {@link verifyReceiptEnvelope} via its own `allowStagingRoots` flag.
   * Default `false` (production fail-closed). See `verify-1.1.ts` for the
   * full security rationale.
   */
  allowStagingRoots?: boolean;
  /**
   * Operator-controlled allowlist of TSA root cert SHA-256 hashes (64-hex,
   * lowercase). Forwarded to {@link verifyReceiptEnvelope}. Default `[]` ⇒
   * fail-closed: any RFC 3161 timestamp is rejected with
   * `tsa_root_not_trusted`. (T-CR-002)
   */
  tsaRootCertSha256Allowlist?: readonly string[];
}

export interface BundleRetentionMetadata {
  retention_period_years?: number;
  retention_basis?: string;
  archive_format?: string;
  [k: string]: unknown;
}

export interface BundleVerifyResult {
  outcome: "accepted" | "rejected";
  errorCode?: BundleVerifyErrorCode;
  errorDetail?: string;
  warnings: string[];
  envelope?: ReceiptEnvelope;
  retentionMetadata?: BundleRetentionMetadata;
  /** Subset of bundle file names actually present (informational). */
  filesPresent?: BundleArtifactName[];
  /** Inner v1.1 envelope verifier (T051) result, if it ran. */
  envelopeVerifyResult?: V11VerifyResult;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function reject(
  code: BundleVerifyErrorCode,
  detail: string,
  warnings: string[] = [],
  partial: Partial<BundleVerifyResult> = {}
): BundleVerifyResult {
  return {
    outcome: "rejected",
    errorCode: code,
    errorDetail: detail,
    warnings,
    ...partial,
  };
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function utf8(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("utf8");
}

function isJwsCompact(s: string): boolean {
  const parts = s.trim().split(".");
  return (
    parts.length === 3 &&
    parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p) && p.length > 0)
  );
}

function parseHistoryPayload(jwsCompact: string): { entries?: unknown } | null {
  const parts = jwsCompact.trim().split(".");
  if (parts.length !== 3) return null;
  try {
    const obj = JSON.parse(
      Buffer.from(parts[1] ?? "", "base64url").toString("utf8")
    ) as unknown;
    if (typeof obj !== "object" || obj === null) return null;
    return obj as { entries?: unknown };
  } catch {
    return null;
  }
}

function unzipInMemory(zipBuffer: Buffer): {
  files: Map<BundleArtifactName, Uint8Array>;
  unknownNames: string[];
} | null {
  let zip: AdmZip;
  try {
    zip = new AdmZip(zipBuffer);
  } catch {
    return null;
  }
  const files = new Map<BundleArtifactName, Uint8Array>();
  const unknownNames: string[] = [];
  const knownSet = new Set<string>(KNOWN_ARTIFACTS);
  for (const entry of zip.getEntries()) {
    if (entry.isDirectory) continue;
    const name = entry.entryName;
    // Reject path traversal — only plain top-level names allowed.
    if (name.includes("..") || name.includes("/") || name.includes("\\"))
      continue;
    if (knownSet.has(name)) {
      files.set(name as BundleArtifactName, new Uint8Array(entry.getData()));
    } else {
      unknownNames.push(name);
    }
  }
  return { files, unknownNames };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Verify an export bundle ZIP entirely offline. See file-level JSDoc.
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-032, FR-032b, FR-033, FR-033b
 */
export async function verifyExportBundle(
  zipBuffer: Buffer,
  options: BundleVerifyOptions
): Promise<BundleVerifyResult> {
  const warnings: string[] = [];

  // 1. Integrity check (FR-033b) -------------------------------------------
  if (options.expectedBundleSha256) {
    const actual = sha256Hex(zipBuffer);
    const expected = options.expectedBundleSha256.toLowerCase();
    if (actual !== expected) {
      return reject(
        "bundle_integrity_mismatch",
        `expected sha256=${expected}, got sha256=${actual}`
      );
    }
  }

  // 2. Unzip in memory -----------------------------------------------------
  const unzipped = unzipInMemory(zipBuffer);
  if (!unzipped) {
    return reject("bundle_zip_invalid", "ZIP buffer could not be parsed");
  }
  const { files, unknownNames } = unzipped;
  for (const name of unknownNames) {
    warnings.push(`bundle_unknown_artifact:${name}`);
  }

  // 3. Required-artifact check --------------------------------------------
  // T425: trust-anchor.pem + jwks-history.jws emit specific error codes so
  // callers can distinguish "bundle missing trust anchor entirely" (security
  // posture) from a generic missing-file (operator error).
  for (const required of REQUIRED_ARTIFACTS) {
    if (!files.has(required)) {
      const code: BundleVerifyErrorCode =
        required === "trust-anchor.pem"
          ? "missing_trust_anchor"
          : required === "jwks-history.jws"
            ? "missing_jwks_history"
            : "required_artifact_missing";
      return reject(code, `missing required artifact: ${required}`, warnings);
    }
  }

  const filesPresent: BundleArtifactName[] = Array.from(files.keys());
  // Required-artifact loop above guarantees these `.get()` calls return bytes.
  const mustGet = (name: BundleArtifactName): Uint8Array => files.get(name)!;

  // 4. Trust anchor pin (R16) + embedded-root fallback (FR-032b, D3).
  // Bundle's `trust-anchor.pem` must match EITHER (a) caller-supplied pin
  // OR (b) an entry in EMBEDDED_ISSUER_ROOTS (T423, current/retired).
  // Otherwise → `trust_anchor_unknown`. A JWKS bundled alone is NOT a
  // trust anchor (post-Codex round 2 D3).
  const trustAnchorActual = sha256Hex(mustGet("trust-anchor.pem"));
  const expectedAnchor = options.trustAnchorPemSha256.toLowerCase();
  const matchesPin = trustAnchorActual === expectedAnchor;
  const embeddedMatch = findIssuerRootBySha256(trustAnchorActual);
  if (!matchesPin && !embeddedMatch) {
    return reject(
      "trust_anchor_unknown",
      `trust-anchor.pem sha256=${trustAnchorActual} did not match pin=${expectedAnchor} nor any of ${EMBEDDED_ISSUER_ROOTS.length} embedded issuer root(s)`,
      warnings,
      { filesPresent }
    );
  }
  if (!matchesPin && embeddedMatch) {
    warnings.push(
      `trust_anchor_via_embedded_root:${embeddedMatch.sha256}:v${embeddedMatch.verifierMinVersion}`
    );
  }

  // 5. JWKS history JWS structural validation. Full root-cert chain verify
  // of jwks-history.jws against trust-anchor.pem is deferred to T420/T421.
  const historyJwsCompact = utf8(mustGet("jwks-history.jws")).trim();
  if (!isJwsCompact(historyJwsCompact)) {
    return reject(
      "jwks_history_jws_invalid",
      "jwks-history.jws is not a JWS Compact (3 base64url segments)",
      warnings,
      { filesPresent }
    );
  }
  const historyPayload = parseHistoryPayload(historyJwsCompact);
  if (!historyPayload || !Array.isArray(historyPayload.entries)) {
    return reject(
      "jwks_history_payload_invalid",
      "jwks-history.jws payload missing or has no entries[]",
      warnings,
      { filesPresent }
    );
  }

  const signedJwksHistory: SignedJwksHistory = {
    jws_compact: historyJwsCompact,
    signed_by_root_sha256: trustAnchorActual,
  };

  // 5b. Cryptographic signature verification of jwks-history.jws against the
  // embedded issuer-root cert (Codex F1 finding). Staging stub root → fall
  // back to structural-only with a warning. T420 ceremony makes this a hard
  // requirement.
  const rootEntry = getActiveIssuerRoot();
  const historyVerify = await verifyJwksHistorySignature(
    signedJwksHistory,
    rootEntry
  );
  if (!historyVerify.valid) {
    if (historyVerify.reason === "embedded_root_not_production") {
      // T-CR-001 / Codex round 2 D2/D3: staging fallback is opt-in only.
      // Without `allowStagingRoots: true`, the bundle is REJECTED with
      // detail `root_not_in_trust_anchor` so a forged JWKS cannot piggy-back
      // on an unverifiable staging root.
      if (!(options.allowStagingRoots ?? false)) {
        return reject(
          "jwks_history_signature_invalid",
          "root_not_in_trust_anchor",
          warnings,
          { filesPresent }
        );
      }
      warnings.push("jwks_history_signature_unverifiable_staging_root");
    } else {
      return reject(
        "jwks_history_signature_invalid",
        `jwks-history.jws signature verification failed: ${historyVerify.reason ?? "unknown"}`,
        warnings,
        { filesPresent }
      );
    }
  }

  // 6. Retention policy ----------------------------------------------------
  let retentionMetadata: BundleRetentionMetadata | undefined;
  try {
    const parsed = JSON.parse(
      utf8(mustGet("retention-policy.json"))
    ) as unknown;
    if (typeof parsed !== "object" || parsed === null) {
      return reject(
        "retention_policy_invalid",
        "retention-policy.json is not a JSON object",
        warnings,
        { filesPresent }
      );
    }
    retentionMetadata = parsed as BundleRetentionMetadata;
  } catch (err) {
    return reject(
      "retention_policy_invalid",
      err instanceof Error ? err.message : "retention-policy.json invalid",
      warnings,
      { filesPresent }
    );
  }

  // 7. Envelope verification (delegate to T051) ----------------------------
  const v11Options: V11VerifyOptions = {
    jwksHistory: signedJwksHistory,
    trustAnchorPemSha256: expectedAnchor,
    policyOidAllowlist: [...(options.policyOidAllowlist ?? [])],
    tsaRootCertSha256Allowlist: options.tsaRootCertSha256Allowlist,
    expectedSubject: options.expectedSubject,
    allowStagingRoots: options.allowStagingRoots ?? false,
  };
  let envelopeResult: V11VerifyResult;
  try {
    envelopeResult = await verifyReceiptEnvelope(
      utf8(mustGet("receipt-envelope.json")),
      v11Options
    );
  } catch (err) {
    return reject(
      "envelope_invalid_json",
      err instanceof Error ? err.message : "envelope verifier threw",
      warnings,
      { filesPresent, retentionMetadata }
    );
  }
  for (const w of envelopeResult.warnings) warnings.push(w);

  if (envelopeResult.outcome === "rejected") {
    return {
      outcome: "rejected",
      errorCode: envelopeResult.errorCode ?? "envelope_invalid_json",
      errorDetail: envelopeResult.errorDetail ?? "envelope verification failed",
      warnings,
      filesPresent,
      retentionMetadata,
      envelopeVerifyResult: envelopeResult,
    };
  }

  // 8. Accepted -----------------------------------------------------------
  return {
    outcome: "accepted",
    warnings,
    envelope: envelopeResult.envelope,
    retentionMetadata,
    filesPresent,
    envelopeVerifyResult: envelopeResult,
  };
}
