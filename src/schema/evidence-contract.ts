/**
 * Evidence contract of the TrustReceipt v1.1 body.
 *
 * The v1.1 path used to emit a poorer body than v1.0 for the same event.
 * These fields close that gap WITHOUT changing `schema_version` or the frozen
 * artifact: they are optional and additive, declared here because the root of
 * the v1.1 body is `.strict()` and an undeclared key would reject the whole
 * body.
 *
 * A claim is emitted in exactly one of two ways, never both:
 *   - present: under its flat name, as in the v1.0 compact form;
 *   - absent: as an `evidence_absent` entry with a reason from a closed enum.
 *     An absence must not look like a success, nor like an oversight.
 *
 * `esign_disclosure`: while no disclosure document stores its text, no receipt
 * can prove which text was shown, so the issuer declares the absence
 * (`not_captured`) instead of signing the hash of a version number.
 */
import { z } from "zod";

/** Claims that may be declared absent. Closed: adding one is a contract change. */
export const EvidenceClaimSchema = z.enum([
  "outcome",
  "amount",
  "policy",
  "mandate",
  "state_witness",
  "operation_link",
  "output_hash",
  "esign_disclosure",
]);
export type EvidenceClaim = z.infer<typeof EvidenceClaimSchema>;

/** Absence reasons. Closed so that absences are auditable and countable. */
export const AbsentReasonSchema = z.enum([
  "not_applicable",
  "not_captured",
  "producer_does_not_supply",
  "job_predates_field",
  "withheld_privacy",
]);
export type AbsentReason = z.infer<typeof AbsentReasonSchema>;

export const EvidenceAbsentEntrySchema = z
  .object({ claim: EvidenceClaimSchema, reason: AbsentReasonSchema })
  .strict();

/**
 * `amount` in the currency's MINOR UNITS (cents for EUR, yen for JPY,
 * thousandths for KWD), as an unsigned integer string with no leading zeros:
 * the same value v1.0 signs and the mandate uses (`mandate_max_amount_cents`).
 * Up to 18 digits (fits a 64-bit integer).
 *
 * `"49.99"` used to be accepted too: two forms for the same datum and no mark
 * in the body saying which one. See `amount_unit`.
 */
const MinorUnitsAmount = z.string().regex(/^(0|[1-9]\d{0,17})$/);
/** ISO 4217, upper case. */
const CurrencyCode = z.string().regex(/^[A-Z]{3}$/);

/** Fields the v1.1 body declares for parity with v1.0. */
export const EvidenceContractFields = {
  outcome: z.enum(["SUCCESS", "FAILURE"]).optional(),
  amount: MinorUnitsAmount.optional(),
  /**
   * Unit of `amount`, SIGNED. Required whenever `amount` is present: without
   * it `"amount":"4999","currency":"EUR"` reads as either 4999 EUR or 49.99 EUR.
   */
  amount_unit: z.literal("minor").optional(),
  currency: CurrencyCode.optional(),
  output_hash_status: z.enum(["captured", "not_captured"]).optional(),
  checkout_session_id: z.string().min(1).optional(),
  evidence_absent: z.array(EvidenceAbsentEntrySchema).optional(),
} as const;

export const EVIDENCE_CONTRACT_KEYS = Object.keys(
  EvidenceContractFields
) as readonly (keyof typeof EvidenceContractFields)[];

/**
 * Body keys that materialise each claim when it is PRESENT. The test of this
 * contract checks that every name exists in the v1.1 body shape, so a made-up
 * name cannot silently disable the "present and absent at once" detection.
 *
 * `output_hash` is not a key of the v1.1 body (the output hash travels outside
 * it): its coherence is checked against `output_hash_status`.
 */
export const PRESENT_KEYS: Readonly<Record<EvidenceClaim, readonly string[]>> =
  {
    outcome: ["outcome"],
    amount: ["amount", "currency", "amount_unit"],
    policy: [
      "evaluation_id",
      "rules_triggered",
      "deciding_rule",
      "rule_set_version",
      "evaluated_rules",
      "policy_snapshot_hash",
      "enforcement_result",
      "escalation_target",
    ],
    mandate: [
      "mandate_id",
      "mandate_max_amount_cents",
      "mandate_currency",
      "mandate_subject",
      "mandate_audience",
      "mandate_expires_at",
      "mandate_claims_hash",
      "mandate_verification",
    ],
    state_witness: [
      "state_witness_resolution",
      "state_witness_reasons",
      "state_witness_authoritative_hash",
    ],
    operation_link: [
      "operation_id",
      "supersedes_receipt_hash",
      "superseded_reason",
      "reconfirmed_state_hash",
    ],
    output_hash: [],
    esign_disclosure: ["esign_disclosure_version", "esign_disclosure_hash"],
  };

/** Does the body declare `claim` as absent? */
export function isDeclaredAbsent(
  body: { evidence_absent?: readonly { claim: string }[] | undefined },
  claim: EvidenceClaim
): boolean {
  return (body.evidence_absent ?? []).some((e) => e.claim === claim);
}

/**
 * Inconsistencies in the evidence contract. Empty = consistent. Consumed by
 * the `superRefine` of the v1.1 body.
 */
export function evidenceContractIssues(
  body: Record<string, unknown>
): string[] {
  const issues: string[] = [];
  if ((body["amount"] === undefined) !== (body["currency"] === undefined)) {
    issues.push("amount and currency must be present together");
  }
  if ((body["amount"] === undefined) !== (body["amount_unit"] === undefined)) {
    issues.push(
      "amount requires amount_unit (minor) and amount_unit requires amount"
    );
  }
  const absent =
    (body["evidence_absent"] as { claim: EvidenceClaim }[] | undefined) ?? [];
  const seen = new Set<string>();
  for (const { claim } of absent) {
    if (seen.has(claim)) {
      issues.push(`evidence_absent lists ${claim} more than once`);
    }
    seen.add(claim);
    const present = PRESENT_KEYS[claim].filter((k) => body[k] !== undefined);
    if (present.length > 0) {
      issues.push(
        `${claim} is declared absent but present via ${present.join(", ")}`
      );
    }
  }
  if (seen.has("output_hash") && body["output_hash_status"] === "captured") {
    issues.push(
      "output_hash is declared absent but output_hash_status is captured"
    );
  }
  return issues;
}

/**
 * Presents a signed `amount` (minor units) in major units, using the
 * currency's ISO 4217 exponent: `("4999","EUR")` -> `"49.99"`,
 * `("4999","JPY")` -> `"4999"`, `("4999","KWD")` -> `"4.999"`.
 *
 * This is PRESENTATION, not evidence: what is signed remains `amount` in minor
 * units. Returns `null` if the input is not the signed form.
 */
export function formatAmountForDisplay(
  amount: string,
  currency: string
): string | null {
  if (!/^(0|[1-9]\d{0,17})$/.test(amount) || !/^[A-Z]{3}$/.test(currency)) {
    return null;
  }
  let exponent: number;
  try {
    exponent =
      new Intl.NumberFormat("en", {
        style: "currency",
        currency,
      }).resolvedOptions().maximumFractionDigits ?? 2;
  } catch {
    return null;
  }
  if (exponent === 0) return amount;
  const padded = amount.padStart(exponent + 1, "0");
  return `${padded.slice(0, -exponent)}.${padded.slice(-exponent)}`;
}
