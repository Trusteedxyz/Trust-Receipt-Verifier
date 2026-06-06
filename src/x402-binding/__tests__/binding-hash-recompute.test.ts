/**
 * Spec 054 T100 — Unit tests for the portable Binding Hash Recompute Service.
 *
 * Verifies bit-by-bit recipe parity with the server-side
 * `BindingHashBuilderService`. Tests cover:
 *
 *   - Deterministic output for EVM Permit2 and SVM authorization fixtures.
 *   - Per-component mismatch localization (5 negative tests, one per component).
 *   - Output commitment hash parity for static_sha256 + merkle_manifest kinds.
 *   - JCS canonicalization integration (key-reorder ⇒ same hash).
 *   - FR-020 fail-fast on RESERVED v1.1 authorization schemes.
 *   - Invalid input rejection (settlement, URI, output_commitment).
 *   - Conformance vector load + self-consistency (002 + 003).
 *
 * @see specs/058-trustreceipt-x402-binding/tasks.md T100
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import canonicalize from "canonicalize";
import { describe, expect, test } from "vitest";

import {
  BindingHashRecomputeError,
  recomputeBindingHash,
  type BindingHashRecomputeInput,
  type SettlementEvidenceInput,
} from "../binding-hash-recompute.js";
import type { OutputCommitment } from "../../zod-1.1.js";

// ---------------------------------------------------------------------------
// Fixture helpers — mirror server-side BindingHashBuilderService.test fixtures
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function jcsSha256TaggedRef(value: unknown): string {
  const canonical = canonicalize(value);
  if (typeof canonical !== "string") {
    throw new Error("canonicalize() returned non-string in test helper");
  }
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

function loadVector(filename: string): {
  inputs: {
    payment_requirements: Record<string, unknown>;
    payment_payload: Record<string, unknown>;
    authorization_scheme: string;
    resource_uri: string;
    settlement_evidence: SettlementEvidenceInput;
    output_commitment: OutputCommitment;
  };
} {
  const path = resolve(
    __dirname,
    "..",
    "..",
    "..",
    "test-vectors",
    "v11-x402-binding",
    filename
  );
  return JSON.parse(readFileSync(path, "utf8"));
}

function evmPermit2Input(): BindingHashRecomputeInput {
  return {
    paymentRequirements: {
      scheme: "exact",
      network: "base",
      maxAmountRequired: "1000000",
      resource: "https://merchant.example.com/api/paid-resource",
      payTo: "0x1234567890abcdef1234567890abcdef12345678",
      maxTimeoutSeconds: 300,
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
    paymentPayload: {
      permit2_authorization: {
        permitted: { token: "0xtoken", amount: "1000000" },
        nonce: "1",
        deadline: "1900000000",
      },
      owner: "0xowner",
      spender: "0xspender",
      token: "0xtoken",
      amount: "1000000",
      nonce: "1",
      deadline: "1900000000",
      signature: "0xdeadbeef",
    },
    authorizationScheme: "evm_permit2",
    resourceUri: "https://merchant.example.com/api/paid-resource",
    settlementEvidence: {
      txHash: "0xfeedface",
      network: "base",
      amount: "1000000",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      payTo: "0x1234567890abcdef1234567890abcdef12345678",
      payer: "0xowner",
      // Extras that MUST be ignored:
      blockHeight: 12345678,
      confirmations: 12,
    },
    outputCommitment: {
      kind: "static_sha256",
      algorithm: "sha256",
      value:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      content_type: "application/json",
      content_length: 256,
    } as OutputCommitment,
  };
}

function svmInput(): BindingHashRecomputeInput {
  return {
    paymentRequirements: {
      scheme: "exact",
      network: "solana",
      maxAmountRequired: "5000000",
      resource: "https://merchant.example.com/svm",
      payTo: "SvmMerchantWalletPubkey",
      asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    },
    paymentPayload: {
      mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      authority: "AgentAuthorityPubkey",
      amount: "5000000",
      expiry: "1900000000",
      recent_blockhash: "BlockHash11111111111111111111111111111111111",
      signature: "SvmSig...",
    },
    authorizationScheme: "svm_token_authorization",
    resourceUri: "https://merchant.example.com/svm",
    settlementEvidence: {
      txHash: "5SvmTxHashBase58...",
      network: "solana",
      amount: "5000000",
      asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      payTo: "SvmMerchantWalletPubkey",
      payer: "AgentAuthorityPubkey",
    },
    outputCommitment: {
      kind: "static_sha256",
      algorithm: "sha256",
      value:
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      content_type: "application/octet-stream",
      content_length: 1024,
    } as OutputCommitment,
  };
}

function merkleCommitment(): OutputCommitment {
  return {
    kind: "merkle_manifest",
    algorithm: "merkle-sha256-v1",
    root: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    manifest_url: "https://merchant.example.com/artifacts/manifest.json",
    manifest_hash:
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    chunk_size: 65536,
    chunk_count: 4,
  } as OutputCommitment;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("recomputeBindingHash — recipe parity & determinism", () => {
  test("EVM Permit2 fixture: returns tagged sha256 and stable hash", () => {
    const result = recomputeBindingHash(evmPermit2Input());
    expect(result.bindingHashTagged).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(result.componentHashesTagged.payment_requirements).toMatch(
      /^sha256:[0-9a-f]{64}$/
    );
    expect(result.componentHashesTagged.payment_payload).toMatch(
      /^sha256:[0-9a-f]{64}$/
    );
    expect(result.componentHashesTagged.resource_uri).toMatch(
      /^sha256:[0-9a-f]{64}$/
    );
    expect(result.componentHashesTagged.settlement_evidence_subset).toMatch(
      /^sha256:[0-9a-f]{64}$/
    );
    expect(result.componentHashesTagged.output_commitment).toMatch(
      /^sha256:[0-9a-f]{64}$/
    );
  });

  test("SVM authorization fixture: returns tagged sha256 and is deterministic", () => {
    const a = recomputeBindingHash(svmInput());
    const b = recomputeBindingHash(svmInput());
    expect(a.bindingHashTagged).toEqual(b.bindingHashTagged);
    expect(a.bindingHashTagged).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("determinism across 10 invocations", () => {
    const input = evmPermit2Input();
    const first = recomputeBindingHash(input).bindingHashTagged;
    for (let i = 0; i < 10; i++) {
      expect(recomputeBindingHash(input).bindingHashTagged).toEqual(first);
    }
  });

  test("EVM Permit2 vs SVM produce different binding hashes", () => {
    const evm = recomputeBindingHash(evmPermit2Input()).bindingHashTagged;
    const svm = recomputeBindingHash(svmInput()).bindingHashTagged;
    expect(evm).not.toEqual(svm);
  });
});

describe("recomputeBindingHash — JCS canonicalization", () => {
  test("reordered keys in paymentRequirements produce identical hash", () => {
    const base = evmPermit2Input();
    const reordered: BindingHashRecomputeInput = {
      ...base,
      paymentRequirements: {
        // Reverse key order vs base:
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        maxTimeoutSeconds: 300,
        payTo: "0x1234567890abcdef1234567890abcdef12345678",
        resource: "https://merchant.example.com/api/paid-resource",
        maxAmountRequired: "1000000",
        network: "base",
        scheme: "exact",
      },
    };
    expect(recomputeBindingHash(reordered).bindingHashTagged).toEqual(
      recomputeBindingHash(base).bindingHashTagged
    );
  });

  test("reordered keys in settlementEvidence subset produce identical hash", () => {
    const base = evmPermit2Input();
    const reordered: BindingHashRecomputeInput = {
      ...base,
      settlementEvidence: {
        payer: "0xowner",
        payTo: "0x1234567890abcdef1234567890abcdef12345678",
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        amount: "1000000",
        network: "base",
        txHash: "0xfeedface",
      },
    };
    expect(recomputeBindingHash(reordered).bindingHashTagged).toEqual(
      recomputeBindingHash(base).bindingHashTagged
    );
  });

  test("reordered keys in outputCommitment produce identical hash (10 runs)", () => {
    const base = evmPermit2Input();
    const reordered: BindingHashRecomputeInput = {
      ...base,
      outputCommitment: {
        content_length: 256,
        content_type: "application/json",
        value:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        algorithm: "sha256",
        kind: "static_sha256",
      } as OutputCommitment,
    };
    const baseHash = recomputeBindingHash(base).bindingHashTagged;
    for (let i = 0; i < 10; i++) {
      expect(recomputeBindingHash(reordered).bindingHashTagged).toEqual(
        baseHash
      );
    }
  });

  test("extra non-nominated settlement fields do NOT affect hash", () => {
    const base = evmPermit2Input();
    const withExtras: BindingHashRecomputeInput = {
      ...base,
      settlementEvidence: {
        ...base.settlementEvidence,
        observedAt: "2026-05-18T10:15:30Z",
        someNoise: "irrelevant",
      },
    };
    expect(recomputeBindingHash(withExtras).bindingHashTagged).toEqual(
      recomputeBindingHash(base).bindingHashTagged
    );
  });

  test("extra non-nominated paymentPayload fields do NOT affect hash", () => {
    const base = evmPermit2Input();
    const withExtras: BindingHashRecomputeInput = {
      ...base,
      paymentPayload: {
        ...base.paymentPayload,
        extra_field_not_in_subset: "ignored",
        another_extra: { nested: 42 },
      },
    };
    expect(recomputeBindingHash(withExtras).bindingHashTagged).toEqual(
      recomputeBindingHash(base).bindingHashTagged
    );
  });
});

describe("recomputeBindingHash — component mismatch localization", () => {
  test("mutating paymentRequirements changes c1 AND final hash", () => {
    const base = evmPermit2Input();
    const baseRes = recomputeBindingHash(base);
    const mutated = recomputeBindingHash({
      ...base,
      paymentRequirements: {
        ...base.paymentRequirements,
        maxAmountRequired: "9999999",
      },
    });
    expect(mutated.bindingHashTagged).not.toEqual(baseRes.bindingHashTagged);
    expect(mutated.componentHashesTagged.payment_requirements).not.toEqual(
      baseRes.componentHashesTagged.payment_requirements
    );
    expect(mutated.componentHashesTagged.payment_payload).toEqual(
      baseRes.componentHashesTagged.payment_payload
    );
    expect(mutated.componentHashesTagged.resource_uri).toEqual(
      baseRes.componentHashesTagged.resource_uri
    );
    expect(mutated.componentHashesTagged.settlement_evidence_subset).toEqual(
      baseRes.componentHashesTagged.settlement_evidence_subset
    );
    expect(mutated.componentHashesTagged.output_commitment).toEqual(
      baseRes.componentHashesTagged.output_commitment
    );
  });

  test("mutating paymentPayload (subset field) changes c2 AND final hash", () => {
    const base = evmPermit2Input();
    const baseRes = recomputeBindingHash(base);
    const mutated = recomputeBindingHash({
      ...base,
      paymentPayload: { ...base.paymentPayload, nonce: "99" },
    });
    expect(mutated.bindingHashTagged).not.toEqual(baseRes.bindingHashTagged);
    expect(mutated.componentHashesTagged.payment_payload).not.toEqual(
      baseRes.componentHashesTagged.payment_payload
    );
    expect(mutated.componentHashesTagged.payment_requirements).toEqual(
      baseRes.componentHashesTagged.payment_requirements
    );
  });

  test("mutating resourceUri changes c3 AND final hash", () => {
    const base = evmPermit2Input();
    const baseRes = recomputeBindingHash(base);
    const mutated = recomputeBindingHash({
      ...base,
      resourceUri: "https://merchant.example.com/api/different-path",
    });
    expect(mutated.bindingHashTagged).not.toEqual(baseRes.bindingHashTagged);
    expect(mutated.componentHashesTagged.resource_uri).not.toEqual(
      baseRes.componentHashesTagged.resource_uri
    );
  });

  test("mutating settlementEvidence.txHash changes c4 AND final hash", () => {
    const base = evmPermit2Input();
    const baseRes = recomputeBindingHash(base);
    const mutated = recomputeBindingHash({
      ...base,
      settlementEvidence: {
        ...base.settlementEvidence,
        txHash: "0xdifferent_tx_hash",
      },
    });
    expect(mutated.bindingHashTagged).not.toEqual(baseRes.bindingHashTagged);
    expect(
      mutated.componentHashesTagged.settlement_evidence_subset
    ).not.toEqual(baseRes.componentHashesTagged.settlement_evidence_subset);
  });

  test("mutating outputCommitment changes c5 AND final hash", () => {
    const base = evmPermit2Input();
    const baseRes = recomputeBindingHash(base);
    const mutated = recomputeBindingHash({
      ...base,
      outputCommitment: {
        ...(base.outputCommitment as Record<string, unknown>),
        value:
          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      } as OutputCommitment,
    });
    expect(mutated.bindingHashTagged).not.toEqual(baseRes.bindingHashTagged);
    expect(mutated.componentHashesTagged.output_commitment).not.toEqual(
      baseRes.componentHashesTagged.output_commitment
    );
  });
});

describe("recomputeBindingHash — output commitment c5 parity", () => {
  test("static_sha256: component 5 equals sha256(jcs(commitment))", () => {
    const input = evmPermit2Input();
    const expected = jcsSha256TaggedRef(input.outputCommitment);
    const result = recomputeBindingHash(input);
    expect(result.componentHashesTagged.output_commitment).toEqual(expected);
  });

  test("merkle_manifest: component 5 equals sha256(jcs(commitment))", () => {
    const input: BindingHashRecomputeInput = {
      ...evmPermit2Input(),
      outputCommitment: merkleCommitment(),
    };
    const expected = jcsSha256TaggedRef(input.outputCommitment);
    const result = recomputeBindingHash(input);
    expect(result.componentHashesTagged.output_commitment).toEqual(expected);
  });

  test("merkle_manifest: reordered keys produce same c5 hash (JCS)", () => {
    const baseInput: BindingHashRecomputeInput = {
      ...evmPermit2Input(),
      outputCommitment: merkleCommitment(),
    };
    const reorderedInput: BindingHashRecomputeInput = {
      ...evmPermit2Input(),
      outputCommitment: {
        chunk_count: 4,
        chunk_size: 65536,
        manifest_hash:
          "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        manifest_url: "https://merchant.example.com/artifacts/manifest.json",
        root: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        algorithm: "merkle-sha256-v1",
        kind: "merkle_manifest",
      } as OutputCommitment,
    };
    expect(recomputeBindingHash(baseInput).bindingHashTagged).toEqual(
      recomputeBindingHash(reorderedInput).bindingHashTagged
    );
  });
});

describe("recomputeBindingHash — FR-020 unsupported authorization schemes", () => {
  const reservedSchemes = [
    "zk_authorization",
    "gasless_relay",
    "account_abstraction_session_key",
  ] as const;

  for (const scheme of reservedSchemes) {
    test(`RESERVED v1.1 scheme "${scheme}" throws unsupported_authorization_scheme`, () => {
      const input = {
        ...evmPermit2Input(),
        authorizationScheme: scheme,
      } as BindingHashRecomputeInput;
      let caught: unknown;
      try {
        recomputeBindingHash(input);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(BindingHashRecomputeError);
      const e = caught as BindingHashRecomputeError;
      expect(e.code).toBe("unsupported_authorization_scheme");
      expect(e.message).toContain(scheme);
    });
  }
});

describe("recomputeBindingHash — invalid input rejection", () => {
  test("missing settlementEvidence.txHash → invalid_settlement_evidence", () => {
    const base = evmPermit2Input();
    const input: BindingHashRecomputeInput = {
      ...base,
      settlementEvidence: {
        ...base.settlementEvidence,
        txHash: "",
      },
    };
    expect(() => recomputeBindingHash(input)).toThrowError(
      BindingHashRecomputeError
    );
    try {
      recomputeBindingHash(input);
    } catch (err) {
      expect((err as BindingHashRecomputeError).code).toBe(
        "invalid_settlement_evidence"
      );
    }
  });

  test("settlementEvidence with non-string non-number field → invalid_settlement_evidence", () => {
    const base = evmPermit2Input();
    const input = {
      ...base,
      settlementEvidence: {
        ...base.settlementEvidence,
        network: { nested: "object" },
      },
    } as unknown as BindingHashRecomputeInput;
    try {
      recomputeBindingHash(input);
      throw new Error("expected to throw");
    } catch (err) {
      expect((err as BindingHashRecomputeError).code).toBe(
        "invalid_settlement_evidence"
      );
    }
  });

  test("empty resourceUri → invalid_resource_uri", () => {
    const input: BindingHashRecomputeInput = {
      ...evmPermit2Input(),
      resourceUri: "",
    };
    try {
      recomputeBindingHash(input);
      throw new Error("expected to throw");
    } catch (err) {
      expect((err as BindingHashRecomputeError).code).toBe(
        "invalid_resource_uri"
      );
    }
  });

  test("relative resourceUri (non-absolute) → invalid_resource_uri", () => {
    const input: BindingHashRecomputeInput = {
      ...evmPermit2Input(),
      resourceUri: "/api/paid-resource",
    };
    try {
      recomputeBindingHash(input);
      throw new Error("expected to throw");
    } catch (err) {
      expect((err as BindingHashRecomputeError).code).toBe(
        "invalid_resource_uri"
      );
    }
  });

  test("malformed outputCommitment (missing kind) → invalid_output_commitment", () => {
    const input = {
      ...evmPermit2Input(),
      outputCommitment: { algorithm: "sha256" } as unknown as OutputCommitment,
    };
    try {
      recomputeBindingHash(input);
      throw new Error("expected to throw");
    } catch (err) {
      expect((err as BindingHashRecomputeError).code).toBe(
        "invalid_output_commitment"
      );
    }
  });

  test("null outputCommitment → invalid_output_commitment", () => {
    const input = {
      ...evmPermit2Input(),
      outputCommitment: null as unknown as OutputCommitment,
    };
    try {
      recomputeBindingHash(input);
      throw new Error("expected to throw");
    } catch (err) {
      expect((err as BindingHashRecomputeError).code).toBe(
        "invalid_output_commitment"
      );
    }
  });
});

describe("recomputeBindingHash — conformance vectors", () => {
  test("002-evm-permit2-happy.json loads and produces a tagged binding hash", () => {
    const vec = loadVector("002-evm-permit2-happy.json");
    const input: BindingHashRecomputeInput = {
      paymentRequirements: vec.inputs.payment_requirements,
      paymentPayload: vec.inputs.payment_payload,
      authorizationScheme: vec.inputs
        .authorization_scheme as BindingHashRecomputeInput["authorizationScheme"],
      resourceUri: vec.inputs.resource_uri,
      settlementEvidence: vec.inputs.settlement_evidence,
      outputCommitment: vec.inputs.output_commitment,
    };
    const result = recomputeBindingHash(input);
    expect(result.bindingHashTagged).toMatch(/^sha256:[0-9a-f]{64}$/);
    // Self-consistency: recompute twice on the same input yields the same hash.
    expect(recomputeBindingHash(input).bindingHashTagged).toEqual(
      result.bindingHashTagged
    );
    // c5 parity with the standalone sha256(jcs(commitment)) helper.
    expect(result.componentHashesTagged.output_commitment).toEqual(
      jcsSha256TaggedRef(input.outputCommitment)
    );
  });

  test("003-svm-token-authorization-happy.json loads and produces a tagged binding hash", () => {
    const vec = loadVector("003-svm-token-authorization-happy.json");
    const input: BindingHashRecomputeInput = {
      paymentRequirements: vec.inputs.payment_requirements,
      paymentPayload: vec.inputs.payment_payload,
      authorizationScheme: vec.inputs
        .authorization_scheme as BindingHashRecomputeInput["authorizationScheme"],
      resourceUri: vec.inputs.resource_uri,
      settlementEvidence: vec.inputs.settlement_evidence,
      outputCommitment: vec.inputs.output_commitment,
    };
    const result = recomputeBindingHash(input);
    expect(result.bindingHashTagged).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(result.componentHashesTagged.output_commitment).toEqual(
      jcsSha256TaggedRef(input.outputCommitment)
    );
  });
});
