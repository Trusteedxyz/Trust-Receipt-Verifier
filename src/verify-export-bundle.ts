/**
 * Clean-room export-bundle verifier.
 *
 * Validates an export bundle ZIP entirely offline: unzips in memory, pins
 * the trust anchor, structurally validates the JWKS history JWS, delegates
 * envelope verification to {@link verifyReceiptEnvelope}, and
 * surfaces retention metadata.
 *
 * Required artifacts: receipt-envelope.json, jwks-snapshot.json,
 * jwks-history.jws, trust-anchor.pem, retention-policy.json. Optional:
 * tsa-cert-chain.pem, tsa-revocation-evidence.{ocsp,crl},
 * redacted-consent-record.json, verifier-version.txt, README.md.
 *
 * TODO: full root-cert chain verify of jwks-history.jws against
 * trust-anchor.pem (Phase 9). Today we structurally validate the JWS and
 * pin the trust anchor by SHA-256 — that pin prevents arbitrary root
 * substitution by the bundle producer. This is tightened by ALSO
 * requiring the bundle's `trust-anchor.pem` to match either the
 * caller-supplied pin OR an entry in {@link EMBEDDED_ISSUER_ROOTS}
 * — bundles whose anchor is unknown to both are rejected with
 * `trust_anchor_unknown`. A JWKS bundled alone is NOT a trust anchor.
 */

import { createHash } from "node:crypto";
import {
  ZipReaderError,
  extractZipEntry,
  readZipDirectory,
  type ZipEntry,
} from "./zip-reader.js";
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
import { verifyJwksSnapshot } from "./verify-jwks-snapshot.js";
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
  | "bundle_limits_exceeded"
  | "required_artifact_missing"
  | "missing_trust_anchor"
  | "missing_jwks_history"
  | "trust_anchor_pin_mismatch"
  | "trust_anchor_unknown"
  | "jwks_history_jws_invalid"
  | "jwks_history_payload_invalid"
  | "jwks_history_signature_invalid"
  | "retention_policy_invalid"
  | "jwks_snapshot_invalid"
  | "jwks_snapshot_mismatch"
  | "envelope_invalid_json"
  | V11VerifyErrorCode;

export interface BundleVerifyOptions {
  /**
   * Optional integrity check: expected SHA-256 of the ZIP bytes (lower-hex).
   * Typically passed by the caller from the HTTP `X-Bundle-Sha256` header.
   */
  expectedBundleSha256?: string;
  /** Trust anchor pinning: SHA-256 of issuer root cert (lower-hex). */
  trustAnchorPemSha256: string;
  /** Optional policy OID allowlist for TSA validation. */
  policyOidAllowlist?: readonly string[];
  /** Optional expected receipt subject. */
  expectedSubject?: ReceiptSubject;
  /**
   * Opt-in escape hatch for staging-stub trust anchors. Forwarded
   * to {@link verifyReceiptEnvelope} via its own `allowStagingRoots` flag.
   * Default `false` (production fail-closed). See `verify-1.1.ts` for the
   * full security rationale.
   */
  allowStagingRoots?: boolean;
  /**
   * Operator-controlled allowlist of TSA root cert SHA-256 hashes (64-hex,
   * lowercase). Forwarded to {@link verifyReceiptEnvelope}. Default `[]` ⇒
   * fail-closed: any RFC 3161 timestamp is rejected with
   * `tsa_root_not_trusted`.
   */
  tsaRootCertSha256Allowlist?: readonly string[];
  /**
   * P2b — verification strictness forwarded to {@link verifyReceiptEnvelope}.
   *
   * Export bundles are a GA / long-term-archive consumer, so this defaults to
   * `"strict"`: opaque-stub or non-matching `trust_anchor_sha256` / `jwks_sha256`
   * pins become REAL rejections instead of warnings. The portable
   * `verifyReceiptEnvelope` GLOBAL default stays `"compat"` (unchanged) for
   * other callers; only this GA-facing bundle path defaults to strict. Callers
   * may explicitly pass `"compat"` to opt out.
   */
  mode?: "strict" | "compat";
  /**
   * Resource ceilings applied while unpacking the ZIP (zip-bomb defence).
   * Every field is optional; see {@link DEFAULT_BUNDLE_LIMITS}. Exceeding any
   * of them rejects the bundle with `bundle_limits_exceeded` BEFORE the
   * offending data is inflated.
   */
  limits?: Partial<BundleLimits>;
}

export interface BundleLimits {
  /** Maximum size of the ZIP file itself, in bytes. */
  maxCompressedBytes: number;
  /** Maximum number of entries in the archive (files + directories). */
  maxEntries: number;
  /** Maximum uncompressed size of any single entry, in bytes. */
  maxEntryBytes: number;
  /** Maximum summed uncompressed size of all entries, in bytes. */
  maxTotalBytes: number;
  /**
   * Maximum uncompressed:compressed ratio of an entry. Only enforced for
   * entries larger than {@link BUNDLE_RATIO_CHECK_MIN_BYTES} (tiny files can
   * legitimately compress very well and are bounded by the absolute caps).
   */
  maxCompressionRatio: number;
}

/**
 * Defaults are generous for real bundles (a handful of JSON/PEM files, a few
 * KiB each; a CRL for TSA revocation evidence is the largest realistic
 * member) and small enough to make memory exhaustion impractical.
 */
export const DEFAULT_BUNDLE_LIMITS: BundleLimits = Object.freeze({
  maxCompressedBytes: 16 * 1024 * 1024,
  maxEntries: 64,
  maxEntryBytes: 8 * 1024 * 1024,
  maxTotalBytes: 32 * 1024 * 1024,
  maxCompressionRatio: 100,
});

export const BUNDLE_RATIO_CHECK_MIN_BYTES = 256 * 1024;

export interface BundleRetentionMetadata {
  retention_period_years?: number;
  retention_basis?: string;
  archive_format?: string;
  [k: string]: unknown;
}

export interface BundleVerifyResult {
  /**
   * `accepted_degraded` mirrors the inner v1.1 verifier: the bundle is
   * structurally sound and its receipt signature verified, but the receipt
   * DECLARES that its trust anchor is unverifiable (`trust_anchor_staging`).
   *
   * It is propagated, never flattened into `accepted`. This is the
   * dispute-evidence artifact — presenting a receipt with no chain of trust as
   * fully verified is precisely the failure mode the third outcome exists to
   * prevent. Consumers that branch on `=== "accepted"` keep refusing it.
   */
  outcome: "accepted" | "accepted_degraded" | "rejected";
  errorCode?: BundleVerifyErrorCode;
  errorDetail?: string;
  warnings: string[];
  envelope?: ReceiptEnvelope;
  retentionMetadata?: BundleRetentionMetadata;
  /** Subset of bundle file names actually present (informational). */
  filesPresent?: BundleArtifactName[];
  /** Inner v1.1 envelope verifier result, if it ran. */
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

type UnzipResult =
  | {
      ok: true;
      files: Map<BundleArtifactName, Uint8Array>;
      unknownNames: string[];
    }
  | { ok: false; kind: "invalid" }
  | { ok: false; kind: "limits"; detail: string };

const limitsExceeded = (detail: string): UnzipResult => ({
  ok: false,
  kind: "limits",
  detail,
});

/**
 * Unpacks the ZIP in memory under {@link BundleLimits}, using the strict
 * in-house reader (`zip-reader.ts`).
 *
 * Declared sizes (central directory) are checked before anything is inflated.
 * They are attacker-controlled, so they are NOT trusted as a bound: each known
 * entry is inflated with `maxOutputLength` set to its declared size, the real
 * length must equal the declared one, and the CRC-32 must match.
 */
function unzipInMemory(zipBuffer: Buffer, limits: BundleLimits): UnzipResult {
  if (zipBuffer.length > limits.maxCompressedBytes) {
    return limitsExceeded(
      `ZIP is ${zipBuffer.length} bytes, limit is ${limits.maxCompressedBytes}`
    );
  }
  try {
    return unzipChecked(zipBuffer, limits);
  } catch (err) {
    if (err instanceof ZipReaderError) {
      return err.kind === "limits"
        ? limitsExceeded(err.message)
        : { ok: false, kind: "invalid" };
    }
    return { ok: false, kind: "invalid" };
  }
}

function unzipChecked(zipBuffer: Buffer, limits: BundleLimits): UnzipResult {
  const entries: ZipEntry[] = readZipDirectory(zipBuffer, {
    maxEntries: limits.maxEntries,
  });

  // Pass 1: declared sizes only (nothing inflated yet).
  let declaredTotal = 0;
  for (const entry of entries) {
    if (entry.isDirectory) continue;
    const size = entry.uncompressedSize;
    if (size > limits.maxEntryBytes) {
      return limitsExceeded(
        `entry "${entry.name}" declares ${size} bytes, limit is ${limits.maxEntryBytes}`
      );
    }
    declaredTotal += size;
    if (declaredTotal > limits.maxTotalBytes) {
      return limitsExceeded(
        `declared total exceeds ${limits.maxTotalBytes} bytes`
      );
    }
    if (
      size > BUNDLE_RATIO_CHECK_MIN_BYTES &&
      size / Math.max(entry.compressedSize, 1) > limits.maxCompressionRatio
    ) {
      return limitsExceeded(
        `entry "${entry.name}" compression ratio exceeds ${limits.maxCompressionRatio}:1`
      );
    }
  }

  // Pass 2: inflate the entries we use, bounded by the declared size.
  const files = new Map<BundleArtifactName, Uint8Array>();
  const unknownNames: string[] = [];
  const knownSet = new Set<string>(KNOWN_ARTIFACTS);
  let actualTotal = 0;
  for (const entry of entries) {
    if (entry.isDirectory) continue;
    const name = entry.name;
    // Only plain top-level names are used. (Names that are unsafe outright -
    // NUL, backslash, absolute, ".." segments - were already rejected by the
    // reader; this also skips ordinary sub-directory members.)
    if (name.includes("..") || name.includes("/") || name.includes("\\"))
      continue;
    if (!knownSet.has(name)) {
      unknownNames.push(name);
      continue;
    }
    const data = extractZipEntry(zipBuffer, entry, limits.maxEntryBytes);
    actualTotal += data.length;
    if (actualTotal > limits.maxTotalBytes) {
      return limitsExceeded(`total exceeds ${limits.maxTotalBytes} bytes`);
    }
    files.set(name as BundleArtifactName, new Uint8Array(data));
  }
  return { ok: true, files, unknownNames };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Verify an export bundle ZIP entirely offline. See file-level JSDoc.
 */
export async function verifyExportBundle(
  zipBuffer: Buffer,
  options: BundleVerifyOptions
): Promise<BundleVerifyResult> {
  const warnings: string[] = [];

  // 1. Integrity check -------------------------------------------
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
  const unzipped = unzipInMemory(zipBuffer, {
    ...DEFAULT_BUNDLE_LIMITS,
    ...options.limits,
  });
  if (!unzipped.ok) {
    return unzipped.kind === "limits"
      ? reject("bundle_limits_exceeded", unzipped.detail)
      : reject("bundle_zip_invalid", "ZIP buffer could not be parsed");
  }
  const { files, unknownNames } = unzipped;
  for (const name of unknownNames) {
    warnings.push(`bundle_unknown_artifact:${name}`);
  }

  // 3. Required-artifact check --------------------------------------------
  // trust-anchor.pem + jwks-history.jws emit specific error codes so
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

  // 4. Trust anchor pin + embedded-root fallback.
  // Bundle's `trust-anchor.pem` must match EITHER (a) caller-supplied pin
  // OR (b) an entry in EMBEDDED_ISSUER_ROOTS (current/retired).
  // Otherwise → `trust_anchor_unknown`. A JWKS bundled alone is NOT a
  // trust anchor.
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
  // of jwks-history.jws against trust-anchor.pem is deferred.
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
  // embedded issuer-root cert. Staging stub root → fall
  // back to structural-only with a warning. A production root makes this a hard
  // requirement.
  // The root is the one FOUND BY FINGERPRINT of the bundle's
  // own trust-anchor.pem (already matched against pin/embedded above), not
  // "whichever root is active today" — after a rotation an archived bundle is
  // signed by a RETIRED root. Only a pin-only match (root not embedded) keeps
  // the previous fallback to the active root.
  const rootEntry = embeddedMatch ?? getActiveIssuerRoot();
  const historyVerify = await verifyJwksHistorySignature(
    signedJwksHistory,
    rootEntry
  );
  if (!historyVerify.valid) {
    if (historyVerify.reason === "embedded_root_not_production") {
      // Staging fallback is opt-in only.
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

  // 7. Envelope verification (delegate to the envelope verifier) --------------
  const v11Options: V11VerifyOptions = {
    jwksHistory: signedJwksHistory,
    trustAnchorPemSha256: expectedAnchor,
    policyOidAllowlist: [...(options.policyOidAllowlist ?? [])],
    tsaRootCertSha256Allowlist: options.tsaRootCertSha256Allowlist,
    expectedSubject: options.expectedSubject,
    allowStagingRoots: options.allowStagingRoots ?? false,
    // P2b — GA bundle path defaults to strict anchor/jwks pin verification.
    mode: options.mode ?? "strict",
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

  // 7b. jwks-snapshot.json bound to signed evidence ----------
  const signedBody = envelopeResult.receipt;
  const snapshotKid = signedBody?.verification_methods?.jwks?.kid;
  const committed = signedBody?.verification_methods?.jwks_sha256;
  if (typeof snapshotKid !== "string" || typeof committed !== "string") {
    return reject(
      "jwks_snapshot_invalid",
      "verified receipt body carries no verification_methods.jwks.kid / jwks_sha256 to bind the snapshot to",
      warnings,
      { filesPresent, retentionMetadata, envelopeVerifyResult: envelopeResult }
    );
  }
  const snapshotCheck = verifyJwksSnapshot({
    snapshotBytes: mustGet("jwks-snapshot.json"),
    kid: snapshotKid,
    committedJwksSha256: committed,
    historyEntries: historyPayload.entries as unknown[],
  });
  if ("code" in snapshotCheck) {
    return reject(snapshotCheck.code, snapshotCheck.detail, warnings, {
      filesPresent,
      retentionMetadata,
      envelopeVerifyResult: envelopeResult,
    });
  }
  for (const w of snapshotCheck.warnings) warnings.push(w);

  // 8. Accepted -----------------------------------------------------------
  // Carry the inner verifier's degradation through verbatim. Branching on
  // `!== "rejected"` above would otherwise collapse `accepted_degraded` into
  // `accepted` and hide an unverifiable trust anchor inside the bundle.
  return {
    outcome:
      envelopeResult.outcome === "accepted_degraded"
        ? "accepted_degraded"
        : "accepted",
    warnings,
    envelope: envelopeResult.envelope,
    retentionMetadata,
    filesPresent,
    envelopeVerifyResult: envelopeResult,
  };
}
