/**
 * Generates the SHARED legacy-compact conformance vectors consumed by BOTH
 * publishable verifiers (TypeScript and Python).
 *
 * ## Why these have to exist
 *
 * The v1.1 envelope path has had 53 shared spec-054 vectors since 2026-06-02 and
 * both ports run all of them. The v0.9-legacy compact path — which is what 100%
 * of production actually emits — had none. Each port built its fixtures in code
 * and asserted its own expectations, so nothing forced them to agree. The Python
 * suite even documented "cross-port parity with
 * `packages/verifier-ts/test/legacy-compact.test.ts`", a file that does not
 * exist. A divergence on the live corpus was structurally invisible.
 *
 * ## Determinism
 *
 * Vectors carry the SIGNED JWS and the public JWKS, never a private key: both
 * ports verify the same bytes rather than each signing their own. The key is
 * generated once, here, and its public half is embedded. Regenerating produces a
 * different key and therefore different vectors — which is fine, they are
 * checked in, and this script exists to be run deliberately, not in CI.
 *
 * Run: pnpm --filter trust-receipt-verifier exec tsx scripts/generate-legacy-compact-vectors.ts
 */

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CompactSign, exportJWK, generateKeyPair } from "jose";

const OUT_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../conformance/legacy-compact-vectors"
);

const KID = "legacy-compact-vector-key";
const MERCHANT_ID = "store_vector_1";

/** Fixed instant so `iat`/`expires_at` are reproducible across regenerations. */
const ISSUED_AT = 1_760_000_000;

interface VectorSpec {
  readonly name: string;
  readonly description: string;
  readonly payload: Record<string, unknown>;
  /** Corrupt the signed bytes after signing. */
  readonly tamper?: boolean;
  /** Serve a JWKS that does not contain the signing kid. */
  readonly unknownKid?: boolean;
  readonly expected: Record<string, unknown>;
}

function base(
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    iss: `merchant:${MERCHANT_ID}`,
    sub: "call_vector_1",
    iat: ISSUED_AT,
    callId: "call_vector_1",
    merchantId: MERCHANT_ID,
    agentId: "did:agent:vector",
    bucket: "checkout",
    tool: "complete_checkout",
    inputHash: "a".repeat(64),
    outputHash: "b".repeat(64),
    outputHashStatus: "captured",
    trust_provider_assertions: [],
    kid: KID,
    ...overrides,
  };
}

const SPECS: readonly VectorSpec[] = [
  {
    name: "L001-jcs-regime-valid",
    description:
      "Enriched legacy compact declaring the RFC 8785 regime. Both ports must " +
      "verify it and report canonicalization 'jcs'.",
    payload: base({
      schema_version: "1.0",
      canon: "jcs",
      expires_at: ISSUED_AT + 7 * 365 * 24 * 60 * 60,
      protocol: "MCP",
      policy_decision: "allow",
    }),
    expected: {
      valid: true,
      variant: "legacy_compact",
      canonicalization: "jcs",
      freshnessExpired: false,
    },
  },
  {
    name: "L002-json-stringify-legacy-regime",
    description:
      "Pre-enrichment payload with NO `canon` marker. Absence is meaningful — " +
      "it is the historic JSON.stringify regime, not an error — and both ports " +
      "must classify it that way rather than rejecting it.",
    payload: base(),
    expected: {
      valid: true,
      variant: "legacy_compact",
      canonicalization: "json-stringify-legacy",
      freshnessExpired: null,
    },
  },
  {
    name: "L003-expired-still-verifies",
    description:
      "`expires_at` far in the past. FR-018 requires v1.0 receipts to keep " +
      "verifying for >= 7 years, so expiry is INFORMATIVE: the receipt is valid " +
      "and its staleness is reported, never fatal.",
    payload: base({
      schema_version: "1.0",
      canon: "jcs",
      expires_at: ISSUED_AT + 86_400,
    }),
    expected: {
      valid: true,
      variant: "legacy_compact",
      canonicalization: "jcs",
      freshnessExpired: true,
    },
  },
  {
    name: "L006-policy-evidence-forward-compat",
    description:
      "Compact payload carrying the R-02 policy-evidence fields " +
      "(`policy_snapshot_hash`, `rules_triggered`, `deciding_rule`, " +
      "`enforcement_result`, `escalation_target`). Both ports MUST verify it. " +
      "This vector does NOT add a conformance requirement: it EXERCISES the " +
      "one v1.0-FINAL already publishes — `changelog.md` §Backward compatibility " +
      "commits parsers to tolerate unknown fields for future MINOR additions. " +
      "Without it, that commitment was prose nobody executed, and the two ports " +
      "could diverge on it invisibly.",
    payload: base({
      schema_version: "1.0",
      canon: "jcs",
      expires_at: ISSUED_AT + 7 * 365 * 24 * 60 * 60,
      protocol: "MCP",
      policy_decision: "review",
      policy_snapshot_hash: "c".repeat(64),
      rules_triggered: [
        "R031.merchant-kill-switch",
        "R043.agent-checkout-approval-required",
      ],
      deciding_rule: "R031.merchant-kill-switch",
      enforcement_result: "enforced",
      escalation_target: "merchant",
    }),
    expected: {
      valid: true,
      variant: "legacy_compact",
      canonicalization: "jcs",
      freshnessExpired: false,
    },
  },
  {
    name: "L007-signers-declaration",
    description:
      "Compact payload carrying the R-03 `signers` declaration. Both ports MUST " +
      "verify it. The declaration lives INSIDE the signed body on purpose: it is " +
      "not a signature but the claim of WHO signed and who held the key, and " +
      "outside the signature anyone could edit `platform_held` → `party_held` " +
      "and upgrade their own verification class. This vector pins that the field " +
      "survives verification in both implementations.",
    payload: base({
      schema_version: "1.0",
      canon: "jcs",
      expires_at: ISSUED_AT + 7 * 365 * 24 * 60 * 60,
      protocol: "MCP",
      policy_decision: "allow",
      signers: [
        {
          party: "issuer",
          kid: KID,
          custody: "platform_held",
          relation_to_subject: "processor",
        },
      ],
    }),
    expected: {
      valid: true,
      variant: "legacy_compact",
      canonicalization: "jcs",
      freshnessExpired: false,
    },
  },
  {
    name: "L004-tampered-payload",
    description:
      "Signed bytes altered after signing. Must fail identically in both ports " +
      "— this is the control that stops the other vectors passing vacuously.",
    payload: base({ schema_version: "1.0", canon: "jcs" }),
    tamper: true,
    expected: { valid: false },
  },
  {
    name: "L005-unknown-kid",
    description:
      "Signature is intact but the kid is absent from the JWKS. Must fail: an " +
      "unresolvable key is not a verified receipt.",
    payload: base({ schema_version: "1.0", canon: "jcs" }),
    unknownKid: true,
    expected: { valid: false },
  },
];

async function main(): Promise<void> {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const publicJwk = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };

  mkdirSync(OUT_DIR, { recursive: true });

  for (const spec of SPECS) {
    let jws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify(spec.payload))
    )
      .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "trust-receipt+jwt" })
      .sign(privateKey);

    if (spec.tamper) {
      // Flip one character of the payload segment; the signature no longer covers it.
      const [header, body, signature] = jws.split(".");
      const flipped =
        body!.slice(0, -2) +
        (body!.slice(-2, -1) === "A" ? "B" : "A") +
        body!.slice(-1);
      jws = `${header}.${flipped}.${signature}`;
    }

    const jwks = spec.unknownKid
      ? [{ ...publicJwk, kid: "some-other-key" }]
      : [publicJwk];

    writeFileSync(
      path.join(OUT_DIR, `${spec.name}.json`),
      `${JSON.stringify(
        {
          name: spec.name,
          description: spec.description,
          jws,
          jwks,
          expected: spec.expected,
        },
        null,
        2
      )}\n`,
      "utf8"
    );
  }

  writeFileSync(
    path.join(OUT_DIR, "README.md"),
    [
      "# Legacy-compact cross-port vectors",
      "",
      "Shared fixtures for the v0.9-legacy compact path — the shape 100% of",
      "production emits. Consumed by BOTH publishable verifiers:",
      "",
      "- TypeScript: `src/__tests__/legacy-compact-vectors.test.ts`",
      "- Python: `packages/verifier-python/tests/test_legacy_compact_vectors.py`",
      "",
      "Each file carries the signed JWS and the public JWKS, never a private key,",
      "so both ports verify the SAME bytes instead of each signing their own.",
      "",
      "Regenerate deliberately (a new key means new vectors):",
      "",
      "```",
      "pnpm --filter trust-receipt-verifier exec tsx scripts/generate-legacy-compact-vectors.ts",
      "```",
      "",
      `Generated ${SPECS.length} vectors.`,
      "",
    ].join("\n"),
    "utf8"
  );

  console.log(`Wrote ${SPECS.length} vectors to ${OUT_DIR}`);
}

void main();
