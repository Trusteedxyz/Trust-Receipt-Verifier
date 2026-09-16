/**
 * Spec 058 T157 — conformance vector loader/runner (FR-024, SC-002).
 *
 * `test-vectors/v11-x402-binding/README.md` documents 11 required vectors and
 * an intended `test:vectors:x402-binding` script — neither existed as an
 * automated gate before this file. Two of the eleven (002, 003) already had
 * partial coverage in `binding-hash-recompute.test.ts` (self-consistency +
 * format only, not README-drift or full-corpus checks). This file closes the
 * gap honestly, in three tiers matched to what each vector actually contains:
 *
 * 1. **Drift check** (all 11): every file the README lists exists on disk and
 *    vice versa — mirrors the discipline spec-054's own vector corpus uses
 *    (`lint-vectors.sh`), applied here for the first time to this corpus.
 * 2. **Structural check** (all 11): required top-level fields present per the
 *    vector's own `test_kind` convention (there are two distinct shapes in
 *    this corpus — see the two `describe` blocks below).
 * 3. **Full re-derivation** (004a, 004b, 005d — the 3 vectors whose `inputs`
 *    are concrete, placeholder-free JWKS + kid + timestamp values): actually
 *    calls the real portable `validateDelegation()` and asserts its output
 *    against the vector's declared `expected` block, component by component.
 *
 * **Deliberately NOT attempted**: byte-exact re-derivation for
 * 001/005a/005b/005c/008/009. Inspection shows these vectors use documented
 * placeholder strings by design (`"binding_hash_declared":
 * "sha256:DECLARED_PLACEHOLDER_RECOMPUTE_FROM_DECLARED_COMPONENTS"`,
 * `"resource_uri": "<same as resource_uri_declared>"`) — they are
 * acceptance-criteria templates for human/spec review, not machine-runnable
 * fixtures, and asserting a fake "recompute matches" against a placeholder
 * would be a false gate, not a real one. 002/003's own binding-hash coverage
 * (format + determinism, not literal-value match — same reason) lives in
 * `binding-hash-recompute.test.ts` and is not duplicated here.
 *
 * @see specs/058-trustreceipt-x402-binding/tasks.md T157
 * @see packages/trust-receipt-verifier/test-vectors/v11-x402-binding/README.md
 */

import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { describe, expect, test } from "vitest";

import {
  validateDelegation,
  type MerchantJwksDocument,
} from "../delegation-validator.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const VECTORS_DIR = resolve(
  __dirname,
  "..",
  "..",
  "..",
  "test-vectors",
  "v11-x402-binding"
);

// README's own "Required vectors (FR-024, post-Codex round 2)" list —
// duplicated here deliberately (not parsed from the .md) so this test fails
// loudly if either side drifts, rather than silently trusting prose.
const REQUIRED_VECTOR_FILES = [
  "001-discovery-happy.json",
  "002-evm-permit2-happy.json",
  "003-svm-token-authorization-happy.json",
  "004a-direct-issuer-happy.json",
  "004b-delegated-issuer-happy.json",
  "005a-binding-mismatch-resource.json",
  "005b-binding-mismatch-payload.json",
  "005c-binding-mismatch-settlement.json",
  "005d-binding-mismatch-unknown-kid.json",
  "008-pii-filter.json",
  "009-pii-challenge-attestation.json",
] as const;

interface VectorFile {
  readonly vector_id: string;
  readonly name: string;
  readonly version: string;
  readonly test_kind: string;
  readonly inputs: Record<string, unknown>;
  readonly expected?: Record<string, unknown>;
  readonly expected_invariants?: Record<string, unknown>;
  readonly [key: string]: unknown;
}

function loadVectorFile(filename: string): VectorFile {
  const path = resolve(VECTORS_DIR, filename);
  return JSON.parse(readFileSync(path, "utf8")) as VectorFile;
}

function listVectorFilesOnDisk(): string[] {
  return readdirSync(VECTORS_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();
}

// ---------------------------------------------------------------------------
// Tier 1 — drift check
// ---------------------------------------------------------------------------

describe("conformance vectors — README/disk parity (FR-024)", () => {
  test("every README-listed vector exists on disk", () => {
    const onDisk = new Set(listVectorFilesOnDisk());
    for (const filename of REQUIRED_VECTOR_FILES) {
      expect(onDisk.has(filename), `missing vector file: ${filename}`).toBe(
        true
      );
    }
  });

  test("every JSON file on disk is a README-listed vector (no undocumented drift)", () => {
    const documented = new Set<string>(REQUIRED_VECTOR_FILES);
    for (const filename of listVectorFilesOnDisk()) {
      expect(
        documented.has(filename),
        `vector file on disk not documented in README.md: ${filename} — ` +
          "add it to REQUIRED_VECTOR_FILES here AND to the README list, " +
          "or remove it if it was a stray."
      ).toBe(true);
    }
  });

  test("FR-024 minimum vector count (>=10) is satisfied", () => {
    expect(REQUIRED_VECTOR_FILES.length).toBeGreaterThanOrEqual(10);
  });
});

// ---------------------------------------------------------------------------
// Tier 2 — structural well-formedness (all 11)
// ---------------------------------------------------------------------------

describe("conformance vectors — structural well-formedness", () => {
  for (const filename of REQUIRED_VECTOR_FILES) {
    test(`${filename} — parses and declares vector_id/name/version/test_kind/inputs`, () => {
      const vec = loadVectorFile(filename);
      expect(typeof vec.vector_id).toBe("string");
      expect(vec.vector_id.length).toBeGreaterThan(0);
      expect(typeof vec.name).toBe("string");
      expect(typeof vec.version).toBe("string");
      expect(typeof vec.test_kind).toBe("string");
      expect(typeof vec.inputs).toBe("object");
      expect(vec.inputs).not.toBeNull();
      // Every vector declares SOME expected-outcome block — either the common
      // `expected` shape or 008's `expected_invariants` variant.
      expect(
        vec.expected !== undefined || vec.expected_invariants !== undefined,
        `${filename} declares neither "expected" nor "expected_invariants"`
      ).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// Tier 3 — full re-derivation for the 3 concrete, placeholder-free vectors
// ---------------------------------------------------------------------------

interface DelegationVectorInputs {
  readonly jwks: MerchantJwksDocument;
  readonly receipt_kid: string;
  readonly receipt_issued_at: string;
}

interface DelegationVectorExpected {
  readonly outcome: string;
  readonly branch: "direct" | "delegated" | null;
  readonly public_key_jwk: { readonly kid: string } | null;
  readonly merchant_root_kid: string | null;
  readonly delegate_role: string | null;
}

describe("conformance vectors — full re-derivation (delegation-shaped, concrete)", () => {
  const cases: ReadonlyArray<{
    readonly filename: string;
    readonly label: string;
  }> = [
    { filename: "004a-direct-issuer-happy.json", label: "rama A directa" },
    {
      filename: "004b-delegated-issuer-happy.json",
      label: "rama B delegada",
    },
    {
      filename: "005d-binding-mismatch-unknown-kid.json",
      label: "kid desconocido rechazado",
    },
  ];

  for (const { filename, label } of cases) {
    test(`${filename} (${label}) — validateDelegation() matches declared "expected" exactly`, () => {
      const vec = loadVectorFile(filename);
      const inputs = vec.inputs as unknown as DelegationVectorInputs;
      const expected = vec.expected as unknown as DelegationVectorExpected;

      const result = validateDelegation({
        jwks: inputs.jwks,
        receiptKid: inputs.receipt_kid,
        receiptIssuedAt: inputs.receipt_issued_at,
      });

      expect(result.outcome).toBe(expected.outcome);
      expect(result.branch ?? null).toBe(expected.branch);
      expect(result.publicKeyJwk?.kid ?? null).toBe(
        expected.public_key_jwk?.kid ?? null
      );
      expect(result.merchantRootKid ?? null).toBe(expected.merchant_root_kid);
      expect(result.delegateRole ?? null).toBe(expected.delegate_role);
    });
  }
});
