/**
 * Spec 054 T075 — Unit tests for the portable Delegation Validator (FR-008a).
 *
 * Covers the full decision tree of `validateDelegation`:
 *
 *   - Branch A: direct issuer with `kid_uses: ["receipt-issuance"]`.
 *   - Branch B: delegated issuer with Ed25519 `authorization_signature`
 *     bound to {kid, role, valid_from, valid_until, merchant_root_kid}.
 *   - All typed failure outcomes.
 *   - Cross-merchant replay defense (tampering merchant_root_kid breaks sig).
 *
 * @see specs/058-trustreceipt-x402-binding/tasks.md T074 T075
 */

import { describe, expect, test } from "vitest";
import {
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import canonicalize from "canonicalize";
import {
  validateDelegation,
  type AuthorizedDelegate,
  type JwksKey,
  type MerchantJwksDocument,
} from "../delegation-validator.js";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

interface Ed25519KeyPair {
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
  privateKey: KeyObject;
}

function generateEd25519(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
  };
  return { publicJwk: jwk, privateKey };
}

function jwksKey(
  kid: string,
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string },
  opts: { kid_uses?: readonly string[]; use?: "sig" } = {}
): JwksKey {
  return {
    kty: "OKP",
    crv: "Ed25519",
    kid,
    use: opts.use ?? "sig",
    x: publicJwk.x,
    ...(opts.kid_uses ? { kid_uses: opts.kid_uses } : {}),
  };
}

interface DelegationFixture {
  kid: string;
  role: string;
  valid_from: string;
  valid_until: string;
  merchant_root_kid: string;
}

function signDelegation(
  fixture: DelegationFixture,
  signerPrivateKey: KeyObject
): AuthorizedDelegate {
  const canonical = canonicalize({
    kid: fixture.kid,
    role: fixture.role,
    valid_from: fixture.valid_from,
    valid_until: fixture.valid_until,
    merchant_root_kid: fixture.merchant_root_kid,
  });
  if (typeof canonical !== "string") {
    throw new Error("canonicalize returned undefined in test fixture");
  }
  // Ed25519 uses one-shot crypto.sign(null, data, key) — mirrors crypto.verify().
  const sigBuf = cryptoSign(
    null,
    Buffer.from(canonical, "utf8"),
    signerPrivateKey
  );
  return {
    kid: fixture.kid,
    role: fixture.role,
    valid_from: fixture.valid_from,
    valid_until: fixture.valid_until,
    merchant_root_kid: fixture.merchant_root_kid,
    authorization_signature: sigBuf.toString("base64url"),
  };
}

// Default timestamps used across tests.
const VALID_FROM = "2026-01-01T00:00:00Z";
const VALID_UNTIL = "2026-12-31T23:59:59Z";
const ISSUED_AT_INSIDE = "2026-06-15T12:00:00Z";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("validateDelegation — Branch A (direct issuer)", () => {
  test("accepts kid present in keys[] with receipt-issuance marker", () => {
    const merchantRoot = generateEd25519();
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-direct-1", merchantRoot.publicJwk, {
          kid_uses: ["receipt-issuance"],
        }),
      ],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-direct-1",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("accepted_direct");
    expect(result.branch).toBe("direct");
    expect(result.publicKeyJwk?.kid).toBe("kid-direct-1");
  });

  test("falls through when kid present but kid_uses lacks marker", () => {
    const kp = generateEd25519();
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-no-marker", kp.publicJwk, { kid_uses: ["other-purpose"] }),
      ],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-no-marker",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("unknown_kid");
  });

  test("falls through when kid present but use !== 'sig'", () => {
    const kp = generateEd25519();
    // Build a key with use=enc — directly construct since helper hard-codes 'sig'.
    const encKey = {
      kty: "OKP" as const,
      crv: "Ed25519" as const,
      kid: "kid-enc",
      use: "enc" as unknown as "sig",
      x: kp.publicJwk.x,
      kid_uses: ["receipt-issuance"],
    };
    const jwks: MerchantJwksDocument = { keys: [encKey] };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-enc",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("unknown_kid");
  });
});

describe("validateDelegation — Branch B (delegated issuer)", () => {
  test("accepts well-formed delegation within window", () => {
    const merchantRoot = generateEd25519();
    const delegate = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-delegate-1",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root",
      },
      merchantRoot.privateKey
    );
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-root", merchantRoot.publicJwk),
        jwksKey("kid-delegate-1", delegate.publicJwk),
      ],
      authorized_delegates: [entry],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-delegate-1",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("accepted_delegated");
    expect(result.branch).toBe("delegated");
    expect(result.delegateRole).toBe("issuer-primary");
    expect(result.merchantRootKid).toBe("kid-root");
    expect(result.publicKeyJwk?.kid).toBe("kid-delegate-1");
    expect(result.publicKeyJwk?.x).toBe(delegate.publicJwk.x);
  });

  test("rejects when role is tampered (signature mismatch)", () => {
    const merchantRoot = generateEd25519();
    const delegate = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-d",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root",
      },
      merchantRoot.privateKey
    );
    const tampered: AuthorizedDelegate = { ...entry, role: "issuer-backup" };
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-root", merchantRoot.publicJwk),
        jwksKey("kid-d", delegate.publicJwk),
      ],
      authorized_delegates: [tampered],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-d",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("delegation_signature_invalid");
  });

  test("rejects when valid_from is tampered (signature mismatch)", () => {
    const merchantRoot = generateEd25519();
    const delegate = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-d",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root",
      },
      merchantRoot.privateKey
    );
    const tampered: AuthorizedDelegate = {
      ...entry,
      valid_from: "2025-01-01T00:00:00Z",
    };
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-root", merchantRoot.publicJwk),
        jwksKey("kid-d", delegate.publicJwk),
      ],
      authorized_delegates: [tampered],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-d",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("delegation_signature_invalid");
  });

  test("rejects when receiptIssuedAt < valid_from", () => {
    const merchantRoot = generateEd25519();
    const delegate = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-d",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root",
      },
      merchantRoot.privateKey
    );
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-root", merchantRoot.publicJwk),
        jwksKey("kid-d", delegate.publicJwk),
      ],
      authorized_delegates: [entry],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-d",
      receiptIssuedAt: "2025-12-31T23:59:59Z",
    });
    expect(result.outcome).toBe("delegation_out_of_window");
  });

  test("rejects when receiptIssuedAt > valid_until", () => {
    const merchantRoot = generateEd25519();
    const delegate = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-d",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root",
      },
      merchantRoot.privateKey
    );
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-root", merchantRoot.publicJwk),
        jwksKey("kid-d", delegate.publicJwk),
      ],
      authorized_delegates: [entry],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-d",
      receiptIssuedAt: "2027-01-01T00:00:00Z",
    });
    expect(result.outcome).toBe("delegation_out_of_window");
  });

  test("accepts inclusive lower bound (issuedAt === valid_from)", () => {
    const merchantRoot = generateEd25519();
    const delegate = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-d",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root",
      },
      merchantRoot.privateKey
    );
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-root", merchantRoot.publicJwk),
        jwksKey("kid-d", delegate.publicJwk),
      ],
      authorized_delegates: [entry],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-d",
      receiptIssuedAt: VALID_FROM,
    });
    expect(result.outcome).toBe("accepted_delegated");
  });

  test("accepts inclusive upper bound (issuedAt === valid_until)", () => {
    const merchantRoot = generateEd25519();
    const delegate = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-d",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root",
      },
      merchantRoot.privateKey
    );
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-root", merchantRoot.publicJwk),
        jwksKey("kid-d", delegate.publicJwk),
      ],
      authorized_delegates: [entry],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-d",
      receiptIssuedAt: VALID_UNTIL,
    });
    expect(result.outcome).toBe("accepted_delegated");
  });

  test("rejects when merchant_root_kid is not present in keys[]", () => {
    const merchantRoot = generateEd25519();
    const delegate = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-d",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root-missing",
      },
      merchantRoot.privateKey
    );
    const jwks: MerchantJwksDocument = {
      keys: [jwksKey("kid-d", delegate.publicJwk)],
      authorized_delegates: [entry],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-d",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("delegate_merchant_root_kid_missing");
    expect(result.reason).toContain("kid-root-missing");
  });

  test("rejects when delegate kid is missing from keys[] (no downstream verify)", () => {
    const merchantRoot = generateEd25519();
    const entry = signDelegation(
      {
        kid: "kid-d-orphan",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root",
      },
      merchantRoot.privateKey
    );
    const jwks: MerchantJwksDocument = {
      keys: [jwksKey("kid-root", merchantRoot.publicJwk)],
      authorized_delegates: [entry],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-d-orphan",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("delegate_merchant_root_kid_missing");
    expect(result.reason).toContain("kid-d-orphan");
  });
});

describe("validateDelegation — fallthrough outcomes", () => {
  test("returns unknown_kid when kid matches neither keys[] nor delegates[]", () => {
    const merchantRoot = generateEd25519();
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-other", merchantRoot.publicJwk, {
          kid_uses: ["receipt-issuance"],
        }),
      ],
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-nope",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("unknown_kid");
  });

  test("returns jwks_invalid_shape when keys[] is not an array", () => {
    const result = validateDelegation({
      jwks: { keys: undefined as unknown as JwksKey[] },
      receiptKid: "kid-anything",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("jwks_invalid_shape");
  });

  test("handles JWKS without authorized_delegates array gracefully", () => {
    const merchantRoot = generateEd25519();
    const jwks: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-direct", merchantRoot.publicJwk, {
          kid_uses: ["receipt-issuance"],
        }),
      ],
      // authorized_delegates intentionally omitted
    };
    const result = validateDelegation({
      jwks,
      receiptKid: "kid-direct",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("accepted_direct");
  });
});

describe("validateDelegation — cross-merchant replay defense", () => {
  test("signature valid for merchant A cannot be replayed under merchant B's root", () => {
    // Merchant A: builds and signs a legitimate delegation for kid-d.
    const merchantA = generateEd25519();
    const delegate = generateEd25519();
    const entryA = signDelegation(
      {
        kid: "kid-d",
        role: "issuer-primary",
        valid_from: VALID_FROM,
        valid_until: VALID_UNTIL,
        merchant_root_kid: "kid-root-A",
      },
      merchantA.privateKey
    );

    // Merchant B publishes a JWKS that lists the SAME authorization_signature
    // bytes but rewrites merchant_root_kid to point at merchant B's root.
    // This MUST fail: the canonical signing input includes merchant_root_kid,
    // so the tamper invalidates the signature.
    const merchantB = generateEd25519();
    const replayedEntry: AuthorizedDelegate = {
      ...entryA,
      merchant_root_kid: "kid-root-B",
    };
    const jwksB: MerchantJwksDocument = {
      keys: [
        jwksKey("kid-root-B", merchantB.publicJwk),
        jwksKey("kid-d", delegate.publicJwk),
      ],
      authorized_delegates: [replayedEntry],
    };

    const result = validateDelegation({
      jwks: jwksB,
      receiptKid: "kid-d",
      receiptIssuedAt: ISSUED_AT_INSIDE,
    });
    expect(result.outcome).toBe("delegation_signature_invalid");
  });
});
