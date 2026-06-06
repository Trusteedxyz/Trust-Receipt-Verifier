/**
 * Spec 054 T101 — Portable VerifierX402Extension (FR-005/006/008a/020/022/023).
 *
 * Wraps the spec-049 verifier baseline with the spec-054 x402_binding
 * verification pipeline. Stateless — receives JWKS document + envelope +
 * optional `componentsForBinding` for binding_hash recomputation.
 *
 * Pipeline (fail-fast):
 *   1. Parse JWS Compact shape (3 parts, EdDSA, kid).
 *   2. Decode payload → TrustReceiptV11BodySchema.
 *   3. Assert `x402_binding` is present.
 *   4. Optional binding_profile_version match.
 *   5. Resolve signing key via `validateDelegation` (FR-008a, branch A/B).
 *   6. Verify Ed25519 receipt signature over JWS signing input bytes.
 *   7. expires_at check → warning only (audit reconstruction).
 *   8. FR-020 authorization_scheme allowlist.
 *   9. FR-022 inferred-identity guard.
 *  10. FR-005/006 binding_hash recompute (if components provided).
 *  11. Optional mismatched-component localization via `declaredComponentsForLocalization`.
 *  12. Envelope structural checks (timestamp_evidence/envelope_metadata).
 *
 * @see specs/058-trustreceipt-x402-binding/spec.md FR-005/FR-006/FR-008a/FR-020/FR-022/FR-023
 * @see specs/058-trustreceipt-x402-binding/tasks.md T101
 */

import { createPublicKey, verify as cryptoVerify } from "node:crypto";

import {
  recomputeBindingHash,
  BindingHashRecomputeError,
  type BindingHashRecomputeInput,
  type BindingHashRecomputeResult,
} from "./binding-hash-recompute.js";
import {
  validateDelegation,
  type MerchantJwksDocument,
  type JwksKey,
} from "./delegation-validator.js";
import {
  TrustReceiptV11BodySchema,
  type TrustReceiptV11Body,
} from "../zod-1.1.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type VerifierExtensionRejectReason =
  | "unknown_kid"
  | "delegation_signature_invalid"
  | "delegation_out_of_window"
  | "delegate_merchant_root_kid_missing"
  | "receipt_signature_invalid"
  | "envelope_metadata_mismatch"
  | "schema_invalid"
  | "x402_binding_missing"
  | "binding_hash_match_failed"
  | "binding_mismatch"
  | "unsupported_authorization_scheme"
  | "inferred_identity_not_allowed"
  | "expired"
  | "internal_error";

export type MismatchedComponent =
  | "payment_requirements"
  | "payment_payload"
  | "resource_uri"
  | "settlement_evidence_subset"
  | "output_commitment";

export type VerifierExtensionResult =
  | {
      readonly valid: true;
      readonly posture: "confirmed" | "settlement_failed";
      readonly verification_posture: "unverified" | "observed" | "enforced";
      readonly kid: string;
      readonly delegation_branch: "direct" | "delegated";
      readonly binding_hash_match: boolean;
      readonly warnings: readonly string[];
    }
  | {
      readonly valid: false;
      readonly reason: VerifierExtensionRejectReason;
      readonly mismatched_component?: MismatchedComponent;
      readonly warnings: readonly string[];
      readonly details?: Record<string, unknown>;
    };

export interface ReceiptEnvelopeInput {
  /** JWS Compact serialization (header.payload.signature). */
  readonly receipt: string;
  readonly timestamp_evidence?: unknown;
  readonly envelope_metadata?: unknown;
  readonly protocol_artifact_sidecars?: unknown;
}

export interface VerifierX402ExtensionArgs {
  readonly envelope: ReceiptEnvelopeInput;
  readonly jwks: MerchantJwksDocument;
  /**
   * OPTIONAL — when provided, the verifier recomputes the binding_hash from
   * the 5 components and compares against the declared hash. Skipping this
   * field means signature+delegation-only verification.
   */
  readonly componentsForBinding?: BindingHashRecomputeInput;
  /**
   * OPTIONAL — auditor-only mismatch localization. When the declared signed
   * components differ from the verification components, providing the
   * declared set here lets the verifier identify which of the 5 components
   * caused the binding_hash mismatch.
   */
  readonly declaredComponentsForLocalization?: BindingHashRecomputeInput;
  /** OPTIONAL — when given, must match envelope's binding_profile_version. */
  readonly expectedBindingProfileVersion?: string;
  /**
   * F9 fix (Codex audit 2026-05-18) — when supplied, the verifier invokes the
   * canonical spec-049 `verifyReceiptEnvelope(...)` after spec-054 binding
   * checks pass. This adds TSA RFC 3161 verification, JWKS history validation,
   * legal-posture recomputation, and envelope metadata mismatch detection
   * (all OUTSIDE the scope of the spec-054 binding-only pipeline).
   *
   * Callers that have the canonical inputs (jwksHistory + trustAnchor) SHOULD
   * supply this. The hosted `/verify` endpoint MUST supply this in production
   * to satisfy the full envelope-trust chain. CLI auditors with only offline
   * inputs may omit; in that case the result includes warning
   * `envelope_canonical_verification_skipped`.
   */
  readonly envelopeVerificationOptions?: import("../verify-1.1.js").VerifyOptions;
}

export interface VerifierX402ExtensionDeps {
  /**
   * Optional metric emitter — emit `x402_binding_verification_total{result,
   * posture}` per call.
   */
  readonly emitVerificationMetric?: (args: {
    readonly result: string;
    readonly posture: string;
  }) => void;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface ParsedJws {
  readonly header: { readonly alg: string; readonly kid: string };
  readonly headerBase64Url: string;
  readonly payloadBase64Url: string;
  readonly signature: Buffer;
  readonly body: TrustReceiptV11Body;
}

function decodeBase64UrlJson<T>(input: string): T {
  const buf = Buffer.from(input, "base64url");
  const text = buf.toString("utf8");
  return JSON.parse(text) as T;
}

function parseJwsCompact(
  jws: string
):
  | { readonly ok: true; readonly parsed: ParsedJws }
  | { readonly ok: false; readonly details: Record<string, unknown> } {
  if (typeof jws !== "string" || jws.length === 0) {
    return { ok: false, details: { error: "empty_jws" } };
  }
  const parts = jws.split(".");
  if (parts.length !== 3) {
    return {
      ok: false,
      details: { error: "jws_shape_invalid", parts_count: parts.length },
    };
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let header: unknown;
  try {
    header = decodeBase64UrlJson(headerB64);
  } catch (err) {
    return {
      ok: false,
      details: {
        error: "header_decode_failed",
        message: (err as Error).message,
      },
    };
  }
  if (
    typeof header !== "object" ||
    header === null ||
    typeof (header as Record<string, unknown>)["alg"] !== "string" ||
    typeof (header as Record<string, unknown>)["kid"] !== "string"
  ) {
    return { ok: false, details: { error: "header_missing_alg_or_kid" } };
  }
  const alg = (header as Record<string, unknown>)["alg"] as string;
  const kid = (header as Record<string, unknown>)["kid"] as string;
  if (alg !== "EdDSA") {
    return {
      ok: false,
      details: { error: "unsupported_alg", alg },
    };
  }

  let payloadJson: unknown;
  try {
    payloadJson = decodeBase64UrlJson(payloadB64);
  } catch (err) {
    return {
      ok: false,
      details: {
        error: "payload_decode_failed",
        message: (err as Error).message,
      },
    };
  }
  const parsed = TrustReceiptV11BodySchema.safeParse(payloadJson);
  if (!parsed.success) {
    return {
      ok: false,
      details: {
        error: "schema_validation_failed",
        issues: parsed.error.issues.map((i) => ({
          path: i.path,
          message: i.message,
        })),
      },
    };
  }

  let signature: Buffer;
  try {
    signature = Buffer.from(sigB64, "base64url");
  } catch (err) {
    return {
      ok: false,
      details: {
        error: "signature_decode_failed",
        message: (err as Error).message,
      },
    };
  }

  return {
    ok: true,
    parsed: {
      header: { alg, kid },
      headerBase64Url: headerB64,
      payloadBase64Url: payloadB64,
      signature,
      body: parsed.data,
    },
  };
}

function verifyEd25519Signature(
  publicKeyJwk: JwksKey,
  signingInput: string,
  signature: Buffer
): boolean {
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: publicKeyJwk.x },
      format: "jwk",
    });
  } catch {
    return false;
  }
  try {
    return cryptoVerify(
      null,
      Buffer.from(signingInput, "utf8"),
      publicKey,
      signature
    );
  } catch {
    return false;
  }
}

const SUPPORTED_BINDING_AUTHORIZATION_SCHEMES = new Set([
  "evm_permit2",
  "svm_token_authorization",
]);

function localizeMismatch(
  recomputed: BindingHashRecomputeResult,
  declared: BindingHashRecomputeResult
): MismatchedComponent | undefined {
  const components: readonly MismatchedComponent[] = [
    "payment_requirements",
    "payment_payload",
    "resource_uri",
    "settlement_evidence_subset",
    "output_commitment",
  ];
  for (const c of components) {
    if (
      recomputed.componentHashesTagged[c] !== declared.componentHashesTagged[c]
    ) {
      return c;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Public class
// ---------------------------------------------------------------------------

export class VerifierX402Extension {
  private readonly deps: VerifierX402ExtensionDeps;

  constructor(deps?: VerifierX402ExtensionDeps) {
    this.deps = deps ?? {};
  }

  verify(args: VerifierX402ExtensionArgs): VerifierExtensionResult {
    const warnings: string[] = [];
    if (args.envelopeVerificationOptions === undefined) {
      warnings.push("envelope_canonical_verification_skipped");
    }
    const result = this.verifyInternal(args, warnings);
    this.emit(result);
    return result;
  }

  /**
   * F9 fix (Codex audit 2026-05-18) — full-chain verification.
   *
   * Combines the spec-054 binding-only pipeline (sync `verify()`) with the
   * canonical spec-049 `verifyReceiptEnvelope(...)` for TSA RFC 3161 + JWKS
   * history + legal-posture recomputation + envelope metadata mismatch.
   *
   * Returns the spec-054 result IF binding checks failed (canonical check
   * never runs in that case). When binding checks pass AND
   * `envelopeVerificationOptions` is supplied, the canonical check runs and
   * its failure reason wins (we surface the strictest gate).
   *
   * Hosted verifier `/api/v1/x402-binding/verify` MUST use this method when
   * production-ready. CLI auditors with only offline inputs use sync
   * `verify(args)` (the warning surfaces the skip honestly).
   */
  async verifyFullChain(
    args: VerifierX402ExtensionArgs
  ): Promise<VerifierExtensionResult> {
    const bindingResult = this.verify(args);
    if (!bindingResult.valid) return bindingResult;
    if (args.envelopeVerificationOptions === undefined) {
      // Caller already received the `envelope_canonical_verification_skipped`
      // warning via sync `verify()`. Surface bindingResult as-is.
      return bindingResult;
    }
    const { verifyReceiptEnvelope } = await import("../verify-1.1.js");
    const envelopeJson = JSON.stringify(args.envelope);
    const canonical = await verifyReceiptEnvelope(
      envelopeJson,
      args.envelopeVerificationOptions
    );
    if (canonical.outcome !== "accepted") {
      return {
        valid: false,
        reason: "schema_invalid",
        warnings: [
          ...bindingResult.warnings,
          `canonical_verifier_${canonical.errorCode ?? "unknown"}`,
          ...(canonical.errorDetail
            ? [`canonical_detail_${canonical.errorDetail}`]
            : []),
        ],
      };
    }
    return {
      ...bindingResult,
      warnings: [...bindingResult.warnings, "envelope_canonical_verified"],
    };
  }

  private verifyInternal(
    args: VerifierX402ExtensionArgs,
    warnings: string[]
  ): VerifierExtensionResult {
    // (1+2) Parse JWS Compact + decode payload.
    const parsedJws = parseJwsCompact(args.envelope.receipt);
    if (!parsedJws.ok) {
      return {
        valid: false,
        reason: "schema_invalid",
        warnings,
        details: parsedJws.details,
      };
    }
    const { header, headerBase64Url, payloadBase64Url, signature, body } =
      parsedJws.parsed;

    // (3) x402_binding presence.
    if (!body.x402_binding) {
      return { valid: false, reason: "x402_binding_missing", warnings };
    }
    const x402 = body.x402_binding;

    // (4) Expected binding_profile_version (optional).
    if (
      args.expectedBindingProfileVersion !== undefined &&
      args.expectedBindingProfileVersion !== x402.binding_profile_version
    ) {
      return {
        valid: false,
        reason: "schema_invalid",
        warnings,
        details: {
          binding_profile_version_mismatch: true,
          expected: args.expectedBindingProfileVersion,
          actual: x402.binding_profile_version,
        },
      };
    }

    // (5) Delegation resolution (FR-008a).
    const delegation = validateDelegation({
      jwks: args.jwks,
      receiptKid: header.kid,
      receiptIssuedAt: x402.issued_at,
    });
    switch (delegation.outcome) {
      case "unknown_kid":
        return { valid: false, reason: "unknown_kid", warnings };
      case "delegation_signature_invalid":
        return {
          valid: false,
          reason: "delegation_signature_invalid",
          warnings,
        };
      case "delegation_out_of_window":
        return { valid: false, reason: "delegation_out_of_window", warnings };
      case "delegate_merchant_root_kid_missing":
        return {
          valid: false,
          reason: "delegate_merchant_root_kid_missing",
          warnings,
        };
      case "jwks_invalid_shape":
        return {
          valid: false,
          reason: "schema_invalid",
          warnings,
          details: { jwks_invalid_shape: true },
        };
      case "accepted_direct":
      case "accepted_delegated":
        // Continue to signature verification.
        break;
      default: {
        // Exhaustiveness guard.
        const _exhaustive: never = delegation.outcome;
        return {
          valid: false,
          reason: "internal_error",
          warnings,
          details: { unhandled_outcome: _exhaustive as unknown as string },
        };
      }
    }
    if (!delegation.publicKeyJwk || !delegation.branch) {
      return {
        valid: false,
        reason: "internal_error",
        warnings,
        details: { error: "delegation_accepted_without_public_key" },
      };
    }

    // (6) Receipt signature verification.
    const signingInput = `${headerBase64Url}.${payloadBase64Url}`;
    const sigOk = verifyEd25519Signature(
      delegation.publicKeyJwk,
      signingInput,
      signature
    );
    if (!sigOk) {
      return { valid: false, reason: "receipt_signature_invalid", warnings };
    }

    // (7) expires_at warning (body uses Unix seconds).
    const nowSec = Math.floor(Date.now() / 1000);
    if (body.expires_at < nowSec) {
      warnings.push("receipt_expired_but_signature_valid");
    }

    // (8) FR-020 authorization_scheme allowlist for v1.0 binding.
    if (
      !SUPPORTED_BINDING_AUTHORIZATION_SCHEMES.has(x402.authorization_scheme)
    ) {
      return {
        valid: false,
        reason: "unsupported_authorization_scheme",
        warnings,
        details: { value: x402.authorization_scheme },
      };
    }

    // (9) FR-022 — verification_posture="unverified" cannot carry chain.
    if (
      x402.verification_posture === "unverified" &&
      x402.agent_authorization_chain !== null
    ) {
      return {
        valid: false,
        reason: "inferred_identity_not_allowed",
        warnings,
      };
    }

    // (10) Binding hash recomputation (FR-005/006).
    let bindingHashMatch = false;
    if (args.componentsForBinding) {
      let recomputed: BindingHashRecomputeResult;
      try {
        recomputed = recomputeBindingHash(args.componentsForBinding);
      } catch (err) {
        if (err instanceof BindingHashRecomputeError) {
          // Surface as schema_invalid — the auditor supplied components that
          // can't compose a valid binding hash.
          return {
            valid: false,
            reason:
              err.code === "unsupported_authorization_scheme"
                ? "unsupported_authorization_scheme"
                : "schema_invalid",
            warnings,
            details: { code: err.code, message: err.message },
          };
        }
        return {
          valid: false,
          reason: "internal_error",
          warnings,
          details: { message: (err as Error).message },
        };
      }
      if (recomputed.bindingHashTagged === x402.binding_hash) {
        bindingHashMatch = true;
      } else {
        // (11) Localization (optional).
        let mismatched: MismatchedComponent | undefined;
        if (args.declaredComponentsForLocalization) {
          try {
            const declared = recomputeBindingHash(
              args.declaredComponentsForLocalization
            );
            mismatched = localizeMismatch(recomputed, declared);
          } catch {
            // Ignore localization errors — fall through with reason only.
          }
        }
        const failure: VerifierExtensionResult = {
          valid: false,
          reason: "binding_mismatch",
          warnings,
          ...(mismatched ? { mismatched_component: mismatched } : {}),
          details: {
            declared_binding_hash: x402.binding_hash,
            recomputed_binding_hash: recomputed.bindingHashTagged,
          },
        };
        return failure;
      }
    } else {
      warnings.push("binding_hash_match_skipped_no_components_provided");
    }

    // (12) Envelope structural checks (light).
    if (
      args.envelope.envelope_metadata !== undefined &&
      (typeof args.envelope.envelope_metadata !== "object" ||
        args.envelope.envelope_metadata === null)
    ) {
      return {
        valid: false,
        reason: "envelope_metadata_mismatch",
        warnings,
        details: { error: "envelope_metadata_not_object" },
      };
    }
    if (args.envelope.timestamp_evidence === undefined) {
      warnings.push("no_timestamp_evidence");
    }

    return {
      valid: true,
      posture: x402.posture,
      verification_posture: x402.verification_posture,
      kid: header.kid,
      delegation_branch: delegation.branch,
      binding_hash_match: bindingHashMatch,
      warnings,
    };
  }

  private emit(result: VerifierExtensionResult): void {
    if (!this.deps.emitVerificationMetric) return;
    if (result.valid) {
      this.deps.emitVerificationMetric({
        result: "valid",
        posture: result.verification_posture,
      });
    } else {
      this.deps.emitVerificationMetric({
        result: result.reason,
        posture: "unknown",
      });
    }
  }
}
