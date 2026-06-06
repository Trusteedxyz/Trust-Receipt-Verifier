/**
 * Spec 054 T100 — Portable Binding Hash Recompute Service (FR-004).
 *
 * Stateless mirror of the server-side `BindingHashBuilderService`
 * (`apps/api/src/services/trust/x402-binding/binding-hash-builder.service.ts`).
 *
 * External auditors use this to RECOMPUTE the 5-component binding hash from
 * archived receipt components and verify it matches the `binding_hash`
 * declared inside the receipt's `x402_binding` extension. Same recipe,
 * different intent (builder constructs; recompute verifies).
 *
 * Recipe (FR-004 + research.md §R2 + manifest v1.0.0):
 *
 *   binding_hash = sha256(
 *     "trtx402:v1:"                              // domain separator (ASCII)
 *     || 0x00                                    // component separator
 *     || sha256(jcs(paymentRequirements))        // c1
 *     || 0x00
 *     || sha256(jcs(paymentPayload_subset))      // c2 (scheme-specific)
 *     || 0x00
 *     || sha256(canonical_uri_utf8_bytes)        // c3 (NOT JCS)
 *     || 0x00
 *     || sha256(jcs(settlement_evidence_subset)) // c4 (6 nominated fields)
 *     || 0x00
 *     || sha256(jcs(output_commitment))          // c5 (full object, JCS)
 *   )
 *
 * The manifest v1.0.0 (server-side
 * `apps/api/src/services/trust/x402-binding/manifests/v1.0.0.json`) is embedded
 * inline as constants below — the portable verifier MUST be free of filesystem
 * and runtime config dependencies. Bumping the manifest version is a SemVer
 * breaking change: add a new constant table and ship a new verifier release.
 *
 * @see specs/058-trustreceipt-x402-binding/spec.md FR-004/FR-005/FR-020
 * @see specs/058-trustreceipt-x402-binding/research.md §R2
 * @see specs/058-trustreceipt-x402-binding/tasks.md T100
 */

import { createHash } from "node:crypto";

import canonicalize from "canonicalize";

import type { OutputCommitment } from "../zod-1.1.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Authorization schemes that participate in the spec-054 v1.0 binding hash.
 *
 * Only `evm_permit2` and `svm_token_authorization` are LIVE in v1.0. The other
 * three (`zk_authorization`, `gasless_relay`, `account_abstraction_session_key`)
 * are RESERVED for v1.1 and rejected by this service with
 * `unsupported_authorization_scheme` — matching server-side FR-020 fail-fast.
 */
export type RecomputeAuthorizationScheme =
  | "evm_permit2"
  | "svm_token_authorization"
  | "zk_authorization"
  | "gasless_relay"
  | "account_abstraction_session_key";

export interface BindingHashRecomputeInput {
  /** Raw paymentRequirements object as emitted by the merchant. JCS-canonicalized internally. */
  readonly paymentRequirements: Record<string, unknown>;
  /** Raw paymentPayload object as submitted by the agent. Subset hashed depends on scheme. */
  readonly paymentPayload: Record<string, unknown>;
  /** Authorization scheme. Must match what the receipt declared. */
  readonly authorizationScheme: RecomputeAuthorizationScheme;
  /** Canonical absolute resource URI. Hashed as UTF-8 bytes (NOT JCS). */
  readonly resourceUri: string;
  /** Settlement evidence. ONLY {txHash, network, amount, asset, payTo, payer} enters the hash. */
  readonly settlementEvidence: SettlementEvidenceInput;
  /** Output commitment object (component e of FR-004). Hashed as sha256(jcs(object)). */
  readonly outputCommitment: OutputCommitment;
}

/**
 * Settlement evidence shape. Only the 6 nominated fields enter the hash;
 * extras may be present (blockHeight, confirmations, observedAt, ...) and
 * are ignored. All 6 hashed fields MUST be non-empty string|number.
 */
export interface SettlementEvidenceInput {
  readonly txHash: string;
  readonly network: string;
  readonly amount: string | number;
  readonly asset: string;
  readonly payTo: string;
  readonly payer: string;
  readonly [key: string]: unknown;
}

export interface BindingHashRecomputeResult {
  /** Tagged final digest: `sha256:<64-hex>`. */
  readonly bindingHashTagged: string;
  /** Per-component tagged digests — useful for mismatch localization. */
  readonly componentHashesTagged: {
    readonly payment_requirements: string;
    readonly payment_payload: string;
    readonly resource_uri: string;
    readonly settlement_evidence_subset: string;
    readonly output_commitment: string;
  };
}

export type BindingHashRecomputeErrorCode =
  | "unsupported_authorization_scheme"
  | "invalid_settlement_evidence"
  | "invalid_resource_uri"
  | "invalid_output_commitment"
  | "jcs_canonicalization_failed";

export class BindingHashRecomputeError extends Error {
  readonly name = "BindingHashRecomputeError";
  constructor(
    public readonly code: BindingHashRecomputeErrorCode,
    message: string
  ) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Embedded manifest constants — mirror of manifests/v1.0.0.json
// ---------------------------------------------------------------------------

/** ASCII bytes of `"trtx402:v1:"`. */
const DOMAIN_SEPARATOR: Buffer = Buffer.from("trtx402:v1:", "utf8");

/** Single NUL byte (0x00) used as component separator. */
const NUL_BYTE: Buffer = Buffer.from([0x00]);

/** Nominated settlement-evidence fields (order is informational; JCS sorts keys). */
const SETTLEMENT_EVIDENCE_SUBSET_FIELDS = [
  "txHash",
  "network",
  "amount",
  "asset",
  "payTo",
  "payer",
] as const;

/**
 * Scheme-specific paymentPayload subset fields, frozen from manifest v1.0.0.
 *
 * v1.0 LIVE schemes: evm_permit2, svm_token_authorization. The remaining
 * three are RESERVED — declared here as `null` so the typed map covers all
 * RecomputeAuthorizationScheme values, and the lookup returns `null` to
 * trigger the `unsupported_authorization_scheme` fail-fast path.
 */
const SCHEME_SUBSET_FIELDS: Readonly<
  Record<RecomputeAuthorizationScheme, readonly string[] | null>
> = {
  evm_permit2: [
    "permit2_authorization",
    "owner",
    "spender",
    "token",
    "amount",
    "nonce",
    "deadline",
    "signature",
  ],
  svm_token_authorization: [
    "mint",
    "authority",
    "amount",
    "expiry",
    "recent_blockhash",
    "signature",
  ],
  // RESERVED for v1.1 — fail-fast on use.
  zk_authorization: null,
  gasless_relay: null,
  account_abstraction_session_key: null,
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type JsonSafe =
  | null
  | boolean
  | number
  | string
  | JsonSafe[]
  | { [k: string]: JsonSafe };

function sha256Bytes(bytes: Buffer): Buffer {
  return createHash("sha256").update(bytes).digest();
}

function untagSha256(tagged: string): string {
  return tagged.startsWith("sha256:") ? tagged.slice("sha256:".length) : tagged;
}

function jcsCanonicalize(value: JsonSafe): string {
  let canonical: string | undefined;
  try {
    canonical = canonicalize(value);
  } catch (err) {
    throw new BindingHashRecomputeError(
      "jcs_canonicalization_failed",
      `canonicalize() threw: ${(err as Error)?.message ?? String(err)}`
    );
  }
  if (typeof canonical !== "string") {
    throw new BindingHashRecomputeError(
      "jcs_canonicalization_failed",
      "canonicalize() returned non-string (cyclic or unsupported value)"
    );
  }
  return canonical;
}

function jcsSha256Bytes(value: JsonSafe): Buffer {
  return sha256Bytes(Buffer.from(jcsCanonicalize(value), "utf8"));
}

function validateResourceUri(uri: string): void {
  if (typeof uri !== "string" || uri.length === 0) {
    throw new BindingHashRecomputeError(
      "invalid_resource_uri",
      "resourceUri must be a non-empty string"
    );
  }
  try {
    // URL constructor requires an absolute URI — relative URIs throw.
    // eslint-disable-next-line no-new
    new URL(uri);
  } catch {
    throw new BindingHashRecomputeError(
      "invalid_resource_uri",
      `resourceUri is not a valid absolute URI: ${uri}`
    );
  }
}

function buildSettlementEvidenceSubset(
  evidence: SettlementEvidenceInput
): Record<string, JsonSafe> {
  const subset: Record<string, JsonSafe> = {};
  for (const field of SETTLEMENT_EVIDENCE_SUBSET_FIELDS) {
    const raw = (evidence as Record<string, unknown>)[field];
    if (raw === undefined || raw === null || raw === "") {
      throw new BindingHashRecomputeError(
        "invalid_settlement_evidence",
        `settlementEvidence.${field} is required and must be non-empty`
      );
    }
    if (typeof raw !== "string" && typeof raw !== "number") {
      throw new BindingHashRecomputeError(
        "invalid_settlement_evidence",
        `settlementEvidence.${field} must be string|number (got ${typeof raw})`
      );
    }
    subset[field] = raw;
  }
  return subset;
}

function buildPaymentPayloadSubset(
  payload: Record<string, unknown>,
  fields: readonly string[]
): Record<string, JsonSafe> {
  const subset: Record<string, JsonSafe> = {};
  for (const field of fields) {
    // FR-004: strict projection. Missing fields project to `null` (JCS
    // preserves `null`), preserving determinism regardless of whether the
    // payload omits the field or explicitly nulls it.
    const raw = (payload as Record<string, unknown>)[field];
    subset[field] = raw === undefined ? null : (raw as JsonSafe);
  }
  return subset;
}

function validateOutputCommitmentShape(commitment: OutputCommitment): void {
  if (
    commitment === null ||
    typeof commitment !== "object" ||
    Array.isArray(commitment)
  ) {
    throw new BindingHashRecomputeError(
      "invalid_output_commitment",
      "outputCommitment must be a non-null object"
    );
  }
  const kind = (commitment as { kind?: unknown }).kind;
  if (typeof kind !== "string" || kind.length === 0) {
    throw new BindingHashRecomputeError(
      "invalid_output_commitment",
      "outputCommitment.kind is required and must be a non-empty string"
    );
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Recompute the FR-004 binding hash from its 5 components.
 *
 * Fail-fast order (matches server-side BindingHashBuilderService):
 *   1. Authorization scheme is LIVE in v1.0 (FR-020).
 *   2. Resource URI well-formed (FR-005).
 *   3. Settlement evidence subset complete (6 nominated fields).
 *   4. Output commitment shape sane.
 *
 * Throws `BindingHashRecomputeError` with a typed `code` on validation
 * failure. Auditors typically catch and report the code as the
 * mismatch-localization reason.
 */
export function recomputeBindingHash(
  input: BindingHashRecomputeInput
): BindingHashRecomputeResult {
  // (1) FR-020 — scheme allowlist BEFORE any hashing.
  const payloadFields = SCHEME_SUBSET_FIELDS[input.authorizationScheme];
  if (!payloadFields) {
    throw new BindingHashRecomputeError(
      "unsupported_authorization_scheme",
      `Authorization scheme "${input.authorizationScheme}" is not supported in binding profile v1.0`
    );
  }

  // (2) FR-005 — URI sanity BEFORE hashing.
  validateResourceUri(input.resourceUri);

  // (3) Output commitment shape — also surface obvious malformations early.
  validateOutputCommitmentShape(input.outputCommitment);

  // Component 1 — paymentRequirements (full object, JCS).
  const c1Bytes = jcsSha256Bytes(
    input.paymentRequirements as unknown as JsonSafe
  );
  const c1Tagged = `sha256:${c1Bytes.toString("hex")}`;

  // Component 2 — paymentPayload subset by scheme (JCS).
  const payloadSubset = buildPaymentPayloadSubset(
    input.paymentPayload,
    payloadFields
  );
  const c2Bytes = jcsSha256Bytes(payloadSubset);
  const c2Tagged = `sha256:${c2Bytes.toString("hex")}`;

  // Component 3 — canonical URI UTF-8 bytes, plain sha256 (NOT JCS).
  const c3Bytes = sha256Bytes(Buffer.from(input.resourceUri, "utf8"));
  const c3Tagged = `sha256:${c3Bytes.toString("hex")}`;

  // Component 4 — settlement evidence subset (6 fields, JCS).
  const evidenceSubset = buildSettlementEvidenceSubset(
    input.settlementEvidence
  );
  const c4Bytes = jcsSha256Bytes(evidenceSubset);
  const c4Tagged = `sha256:${c4Bytes.toString("hex")}`;

  // Component 5 — output commitment (full object, sha256(jcs(commitment))).
  // Mirrors OutputCommitmentValidator.computeCommitmentBindingHashTagged
  // server-side. Field order is irrelevant — JCS normalises.
  const c5Bytes = jcsSha256Bytes(input.outputCommitment as unknown as JsonSafe);
  const c5Tagged = `sha256:${c5Bytes.toString("hex")}`;

  // Final composition: domain_separator || NUL || c1 || NUL || ... || NUL || c5
  const composed = Buffer.concat([
    DOMAIN_SEPARATOR,
    NUL_BYTE,
    c1Bytes,
    NUL_BYTE,
    c2Bytes,
    NUL_BYTE,
    c3Bytes,
    NUL_BYTE,
    c4Bytes,
    NUL_BYTE,
    c5Bytes,
  ]);

  const finalHex = createHash("sha256").update(composed).digest("hex");

  return {
    bindingHashTagged: `sha256:${finalHex}`,
    componentHashesTagged: {
      payment_requirements: c1Tagged,
      payment_payload: c2Tagged,
      resource_uri: c3Tagged,
      settlement_evidence_subset: c4Tagged,
      output_commitment: c5Tagged,
    },
  };
}

/** Internal helper — re-exported untag for advanced callers / tests. */
export const __internals = {
  untagSha256,
  DOMAIN_SEPARATOR_ASCII: "trtx402:v1:",
} as const;
