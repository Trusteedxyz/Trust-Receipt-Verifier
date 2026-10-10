/**
 * Internal helpers for the v1.1 envelope verifier (stub detection, JWKS-history
 * parsing / chain recomputation, legal_posture recomputation, TSA error
 * mapping) plus the public provider-assertion predicates. Split out of
 * verify-1.1.ts (file-size limit); behaviour unchanged.
 */

import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import type {
  LegalPosture,
  ReceiptSubject,
  SignedJwksHistory,
  JwksHistoryEntry,
  Rfc9421ProviderAssertion,
  HumanProviderAssertion,
  VisaTapProviderAssertion,
} from "./types-1.1.js";
import type { V11VerifyErrorCode } from "./verify-1.1-types.js";

/**
 * The all-zeros / opaque SHA-256 stub. A `trust_anchor_sha256` or `jwks_sha256`
 * equal to this is structurally well-formed (passes the Zod regex) but carries
 * NO real chain-of-trust binding — it is the placeholder emitted by issuers
 * before a production anchor ceremony. Strict mode rejects it.
 */
export const STUB_SHA256 = "0".repeat(64);

/**
 * A SHA-256 hex value is treated as an opaque/synthetic stub when it is the
 * all-zeros placeholder or any single repeated nibble (e.g. all-`f`). These
 * carry no entropy and cannot be a genuine digest.
 */
export function isOpaqueStubSha256(value: string): boolean {
  if (value === STUB_SHA256) return true;
  return /^([0-9a-f])\1{63}$/.test(value);
}

// ---------------------------------------------------------------------------
// Trust-provider assertion type predicates (public API)
// ---------------------------------------------------------------------------

export function isRfc9421ProviderAssertion(
  a: unknown
): a is Rfc9421ProviderAssertion {
  return (
    typeof a === "object" &&
    a !== null &&
    (a as Record<string, unknown>)["provider"] === "rfc9421-native"
  );
}

export function isHumanProviderAssertion(
  a: unknown
): a is HumanProviderAssertion {
  return (
    typeof a === "object" &&
    a !== null &&
    (a as Record<string, unknown>)["provider"] === "human"
  );
}

export function isVisaTapProviderAssertion(
  a: unknown
): a is VisaTapProviderAssertion {
  return (
    typeof a === "object" &&
    a !== null &&
    (a as Record<string, unknown>)["provider"] === "visa"
  );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

export interface ParsedJwksHistoryPayload {
  schema_version?: string;
  entries: JwksHistoryEntry[];
  history_chain_sha256?: string;
}

/**
 * Parse the inner payload of `jwksHistory.jws_compact` without verifying its
 * signature. The history bundle MUST also be signature-verified upstream when
 * reading from an untrusted source; here we use it only to look up the kid.
 *
 * Returns null on any structural problem.
 */
export function parseJwksHistoryPayload(
  signed: SignedJwksHistory
): ParsedJwksHistoryPayload | null {
  const parts = signed.jws_compact.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1] ?? "", "base64url").toString("utf8");
    const obj = JSON.parse(json) as ParsedJwksHistoryPayload;
    if (!Array.isArray(obj.entries)) return null;
    return obj;
  } catch {
    return null;
  }
}

/**
 * Resolve a `kid` in the JWKS history. Returns the entry or `null` if the
 * kid is unknown.
 */
export function resolveKid(
  history: ParsedJwksHistoryPayload,
  kid: string
): JwksHistoryEntry | null {
  for (const entry of history.entries ?? []) {
    if (entry.kid === kid) return entry;
  }
  return null;
}

/**
 * both `body.issued_at` AND `timestamp_evidence.issued_at_attested` MUST
 * fall inside the resolved kid's `[valid_from, valid_to]` window. A null
 * `valid_to` means "still active".
 */
export function isWithinValidityWindow(
  entry: JwksHistoryEntry,
  ...timestamps: number[]
): boolean {
  for (const ts of timestamps) {
    if (ts < entry.valid_from) return false;
    if (entry.valid_to !== null && ts > entry.valid_to) return false;
  }
  return true;
}

/** Synchronous SHA-256 hex of a UTF-8 string. */
export function sha256HexStr(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * recompute the append-only JWKS-history hash chain over `entries`.
 *
 * MUST stay byte-identical to the issuer's history-chain computation:
 *
 *   chain_0 = sha256( canonicalize_RFC8785([]) )
 *   chain_i = sha256( chain_{i-1} || canonicalize_RFC8785(entry_i) )
 *
 * The returned value is the final rolling chain after folding every entry.
 * Entries are folded in the order presented (the issuer orders by
 * `valid_from asc`).
 */
export function recomputeHistoryChainSha256(
  entries: ReadonlyArray<JwksHistoryEntry>
): string {
  let chain = sha256HexStr(canonicalize([] as unknown[]) ?? "[]");
  for (const entry of entries) {
    const entryCanonical =
      canonicalize(entry as unknown as Record<string, unknown>) ?? "{}";
    chain = sha256HexStr(chain + entryCanonical);
  }
  return chain;
}

/**
 * Recompute the verifier-authoritative legal_posture from observed evidence
 * The truth table:
 *
 * - merchant_admin subject ⇒ `merchant_admin_action`
 * - buyer_agent + tst-present + agent-identity ⇒ `ades_candidate_timestamped`
 * - buyer_agent + tst-absent + agent-identity ⇒ `ades_candidate_no_tsa`
 * - buyer_agent + tst-present + no agent-identity ⇒ `degraded_no_agent_identity`
 * - buyer_agent + tst-absent + no agent-identity ⇒ `simple_electronic_seal`
 *
 * Agent-identity is considered "verified" when ANY of the following is true:
 *  - `body.trust_provider_assertions` is a non-empty array (adapter
 *    output — preferred signal), OR
 *  - `body.authorization_evidence.protocol_authorization_ref` is set (the
 *    receipt cites a signed protocol mandate such as AP2/MCAP/UCP, which
 *    inherently binds an agent identity at the protocol layer).
 *
 * We stay loose because adapter shapes vary and not every issuer
 * embeds a `trust_provider_assertions` field at issuance time.
 *
 * Staging floor: a body declaring `trust_anchor_staging` has NO
 * verifiable chain of trust behind it. Whatever agent identity or timestamp it
 * carries, the strongest posture it can honestly claim is
 * `simple_electronic_seal` — so the verifier floors it there rather than
 * recomputing a stronger posture and then rejecting the issuer's honest
 * self-downgrade as a mismatch.
 *
 * The floor is evaluated FIRST and DOMINATES the entire truth table above,
 * including `merchant_admin`. `merchant_admin_action` names a subject, not a
 * strength level, so letting it short-circuit would report a receipt with an
 * unverifiable anchor as if the anchor were irrelevant. Mirrors the issuer-side
 * invariant.
 */
export function recomputeLegalPosture(
  body: {
    receipt_subject: ReceiptSubject;
    trust_provider_assertions?: unknown;
    authorization_evidence?: { protocol_authorization_ref?: string };
    legal_posture_warnings?: ReadonlyArray<{ reason: string }>;
  },
  envelope: { timestamp_evidence: { type: string } }
): LegalPosture {
  const declaresStagingAnchor = (body.legal_posture_warnings ?? []).some(
    (w) => w.reason === "trust_anchor_staging"
  );
  if (declaresStagingAnchor) {
    return "simple_electronic_seal";
  }
  if (body.receipt_subject === "merchant_admin") {
    return "merchant_admin_action";
  }
  const tstPresent = envelope.timestamp_evidence.type === "RFC3161";
  const assertions = body.trust_provider_assertions ?? [];
  const hasAssertions = Array.isArray(assertions) && assertions.length > 0;
  const hasProtocolAuthRef =
    typeof body.authorization_evidence?.protocol_authorization_ref ===
      "string" &&
    body.authorization_evidence.protocol_authorization_ref.length > 0;
  const agentIdentityVerified = hasAssertions || hasProtocolAuthRef;
  if (tstPresent && agentIdentityVerified) return "ades_candidate_timestamped";
  if (!tstPresent && agentIdentityVerified) return "ades_candidate_no_tsa";
  if (tstPresent && !agentIdentityVerified) return "degraded_no_agent_identity";
  return "simple_electronic_seal";
}

export function mapTimestampError(code: string | undefined): V11VerifyErrorCode {
  switch (code) {
    case "tsa_status_not_granted":
    case "tsa_nonce_mismatch":
    case "tsa_policy_oid_unauthorized":
    case "tsa_eku_missing":
    case "tsa_chain_invalid":
    case "tsa_cert_revoked":
    case "tsa_revocation_unavailable":
    case "tsa_gen_time_out_of_tolerance":
    case "tsa_imprint_mismatch":
    case "tsa_token_mismatch":
    case "tsa_root_not_trusted":
      return code;
    default:
      return "tsa_invalid";
  }
}
