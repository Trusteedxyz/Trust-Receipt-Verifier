/**
 * `amount` in minor units, with the unit SIGNED.
 *
 * v1.0 signs an integer in minor units (`4999`) and v1.1 the same value as a
 * string (`"4999"`). With nothing else in the body, a third party reading
 * `"amount":"4999","currency":"EUR"` cannot tell whether it is 4999 EUR or
 * 49.99 EUR, and comparing it with `mandate_max_amount_cents` would require
 * guessing. The verifier also used to accept `"49.99"`, which nobody emits:
 * two forms for the same datum.
 *
 * Decision: minor units with no conversion (as in v1.0 and the mandate), with
 * a signed `amount_unit: "minor"`. `formatAmountForDisplay` presents it in
 * major units using the currency's ISO 4217 exponent, outside of what is
 * signed.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TrustReceiptV11BodySchema } from "../zod-1.1.js";
import { formatAmountForDisplay } from "../schema/evidence-contract.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
function happyBody(): Record<string, unknown> {
  const raw = readFileSync(
    join(
      __dirname,
      "..",
      "..",
      "test-vectors",
      "v11",
      "011-buyer-agent-happy-path.json"
    ),
    "utf8"
  );
  const jws = (JSON.parse(raw) as { envelope: { receipt: string } }).envelope
    .receipt;
  return JSON.parse(
    Buffer.from(jws.split(".")[1]!, "base64url").toString("utf8")
  );
}
const parse = (b: Record<string, unknown>) =>
  TrustReceiptV11BodySchema.safeParse(b);
const con = (extra: Record<string, unknown>) => ({ ...happyBody(), ...extra });

describe("amount with a signed unit", () => {
  it("accepts an integer amount in minor units with amount_unit minor", () => {
    expect(
      parse(con({ amount: "4999", currency: "EUR", amount_unit: "minor" }))
        .success
    ).toBe(true);
    expect(
      parse(con({ amount: "0", currency: "EUR", amount_unit: "minor" })).success
    ).toBe(true);
  });

  it("rejects amount without amount_unit (ambiguous: 4999 EUR or 49.99 EUR?)", () => {
    expect(parse(con({ amount: "4999", currency: "EUR" })).success).toBe(false);
  });

  it("rejects decimals: nobody emits them and they would be a second form of the same datum", () => {
    expect(
      parse(con({ amount: "49.99", currency: "EUR", amount_unit: "minor" }))
        .success
    ).toBe(false);
  });

  it("rejects leading zeros and oversized values", () => {
    expect(
      parse(con({ amount: "04999", currency: "EUR", amount_unit: "minor" }))
        .success
    ).toBe(false);
    expect(
      parse(
        con({ amount: "9".repeat(19), currency: "EUR", amount_unit: "minor" })
      ).success
    ).toBe(false);
  });

  it("rejects amount_unit without amount, and any other unit", () => {
    expect(parse(con({ amount_unit: "minor" })).success).toBe(false);
    expect(
      parse(con({ amount: "4999", currency: "EUR", amount_unit: "major" }))
        .success
    ).toBe(false);
  });

  it("amount declared absent while amount_unit is present is inconsistent", () => {
    expect(
      parse(
        con({
          amount_unit: "minor",
          evidence_absent: [{ claim: "amount", reason: "not_captured" }],
        })
      ).success
    ).toBe(false);
  });
});

describe("formatAmountForDisplay (not signed)", () => {
  it("uses each currency's ISO 4217 exponent", () => {
    expect(formatAmountForDisplay("4999", "EUR")).toBe("49.99");
    expect(formatAmountForDisplay("4999", "JPY")).toBe("4999");
    expect(formatAmountForDisplay("4999", "KWD")).toBe("4.999");
    expect(formatAmountForDisplay("5", "EUR")).toBe("0.05");
    expect(formatAmountForDisplay("0", "EUR")).toBe("0.00");
  });
  it("does not invent: non-integer input or invalid currency returns null", () => {
    expect(formatAmountForDisplay("49.99", "EUR")).toBeNull();
    expect(formatAmountForDisplay("4999", "eur")).toBeNull();
  });
});
