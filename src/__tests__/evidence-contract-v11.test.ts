/**
 * Evidence contract of the v1.1 body.
 *
 * - New claims declared as optional: `outcome`, `amount` + `currency`,
 *   `output_hash_status`, `checkout_session_id` and the `evidence_absent`
 *   block.
 * - The ESIGN disclosure requirement is lifted when its absence is DECLARED in
 *   `evidence_absent` (no disclosure document stores its text today, so no
 *   receipt can prove what was shown: the honest move is to sign the
 *   absence). Declared absent and present at once is an inconsistent body.
 * - The root stays `.strict()`: an unknown key is rejected.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TrustReceiptV11BodySchema } from "../zod-1.1.js";

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
  ) as Record<string, unknown>;
}

function withoutEsign(): Record<string, unknown> {
  const body = happyBody();
  delete body["esign_disclosure_version"];
  delete body["esign_disclosure_hash"];
  return body;
}

const parse = (body: Record<string, unknown>) =>
  TrustReceiptV11BodySchema.safeParse(body);

describe("new claims of the v1.1 body", () => {
  it("the reference vector still verifies without the new fields", () => {
    expect(parse(happyBody()).success).toBe(true);
  });

  it("accepts outcome, amount+currency, output_hash_status and checkout_session_id", () => {
    const body = {
      ...happyBody(),
      outcome: "SUCCESS",
      // Minor units with the signed unit: what the issuer emits. `"49.99"`
      // is emitted by nobody and is no longer accepted.
      amount: "4999",
      currency: "EUR",
      amount_unit: "minor",
      output_hash_status: "captured",
      checkout_session_id: "64f8399a-190d-4a8d-a43e-03fb0a28b2d4",
    };
    expect(parse(body).success).toBe(true);
  });

  it("rejects amount without currency and currency without amount", () => {
    expect(
      parse({ ...happyBody(), amount: "4999", amount_unit: "minor" }).success
    ).toBe(false);
    expect(parse({ ...happyBody(), currency: "EUR" }).success).toBe(false);
  });

  it("rejects out-of-enum or badly formatted values", () => {
    expect(parse({ ...happyBody(), outcome: "MAYBE" }).success).toBe(false);
    expect(parse({ ...happyBody(), output_hash_status: "lost" }).success).toBe(
      false
    );
    expect(
      parse({
        ...happyBody(),
        amount: "49,99",
        currency: "EUR",
        amount_unit: "minor",
      }).success
    ).toBe(false);
    expect(
      parse({
        ...happyBody(),
        amount: "4999",
        currency: "eur",
        amount_unit: "minor",
      }).success
    ).toBe(false);
  });

  it("an unknown key is still rejected (strict root intact)", () => {
    expect(parse({ ...happyBody(), outcome_extra: "x" }).success).toBe(false);
  });
});

describe("evidence_absent", () => {
  it("accepts a declared absence with a reason from the enum", () => {
    const body = {
      ...happyBody(),
      evidence_absent: [
        { claim: "outcome", reason: "producer_does_not_supply" },
      ],
    };
    expect(parse(body).success).toBe(true);
  });

  it("rejects a claim or a reason outside the enum", () => {
    expect(
      parse({
        ...happyBody(),
        evidence_absent: [{ claim: "made_up", reason: "not_captured" }],
      }).success
    ).toBe(false);
    expect(
      parse({
        ...happyBody(),
        evidence_absent: [{ claim: "outcome", reason: "just_because" }],
      }).success
    ).toBe(false);
  });

  it("rejects a claim declared both present and absent", () => {
    const body = {
      ...happyBody(),
      outcome: "SUCCESS",
      evidence_absent: [{ claim: "outcome", reason: "not_captured" }],
    };
    expect(parse(body).success).toBe(false);
  });

  it("rejects the same claim declared absent twice", () => {
    const body = {
      ...happyBody(),
      evidence_absent: [
        { claim: "outcome", reason: "not_captured" },
        { claim: "outcome", reason: "not_applicable" },
      ],
    };
    expect(parse(body).success).toBe(false);
  });
});

describe("PRESENT_KEYS points at real keys of the v1.1 body", () => {
  it("every key exists in the shape (a made-up name would disable detection)", async () => {
    const { PRESENT_KEYS } = await import("../schema/evidence-contract.js");
    let node = TrustReceiptV11BodySchema as unknown as {
      shape?: Record<string, unknown>;
      _def?: { schema?: unknown; innerType?: unknown };
    };
    while (!node.shape && (node._def?.schema || node._def?.innerType)) {
      node = (node._def.schema ?? node._def.innerType) as typeof node;
    }
    const shape = node.shape ?? {};
    expect(Object.keys(shape).length).toBeGreaterThan(20);
    for (const [claim, keys] of Object.entries(PRESENT_KEYS)) {
      for (const k of keys) {
        expect(k in shape, `${claim} -> ${k} is not in the v1.1 body`).toBe(
          true
        );
      }
    }
  });

  it("output_hash declared absent with output_hash_status captured: rejected", () => {
    const body = {
      ...happyBody(),
      output_hash_status: "captured",
      evidence_absent: [{ claim: "output_hash", reason: "not_captured" }],
    };
    expect(parse(body).success).toBe(false);
  });
});

describe("ESIGN disclosure declared absent", () => {
  it("no disclosure and NOT declared absent: rejected (the requirement still applies)", () => {
    expect(parse(withoutEsign()).success).toBe(false);
  });

  it("no disclosure and declared absent (not_captured): accepted", () => {
    const body = {
      ...withoutEsign(),
      evidence_absent: [{ claim: "esign_disclosure", reason: "not_captured" }],
    };
    expect(parse(body).success).toBe(true);
  });

  it("disclosure present and also declared absent: rejected", () => {
    const body = {
      ...happyBody(),
      evidence_absent: [{ claim: "esign_disclosure", reason: "not_captured" }],
    };
    expect(parse(body).success).toBe(false);
  });

  it("consent_evidence_ref is still required when the disclosure is missing", () => {
    const body = {
      ...withoutEsign(),
      evidence_absent: [{ claim: "esign_disclosure", reason: "not_captured" }],
    };
    delete body["consent_evidence_ref"];
    expect(parse(body).success).toBe(false);
  });
});

describe("consent_disclosure_version inside the consent context", () => {
  /** Body with no disclosure and no version inside the consent context. */
  function withoutAnyDisclosure(): Record<string, unknown> {
    const body = withoutEsign();
    const ctx = {
      ...(body["buyer_agent_consent_context"] as Record<string, unknown>),
    };
    delete ctx["consent_disclosure_version"];
    return { ...body, buyer_agent_consent_context: ctx };
  }

  it("may be missing when the disclosure is declared absent", () => {
    const body = {
      ...withoutAnyDisclosure(),
      evidence_absent: [{ claim: "esign_disclosure", reason: "not_captured" }],
    };
    expect(parse(body).success).toBe(true);
  });

  it("may not be missing when the disclosure is NOT declared absent", () => {
    // Without the declared absence, the top-level version and hash are
    // required; the top-level disclosure is restored here to isolate the
    // consent context.
    const happy = happyBody();
    const body = {
      ...withoutAnyDisclosure(),
      esign_disclosure_version: happy["esign_disclosure_version"],
      esign_disclosure_hash: happy["esign_disclosure_hash"],
    };
    expect(parse(body).success).toBe(false);
  });
});
