# TrustReceipt Conformance Test Vectors

## What are these?

TrustReceipt is an open standard for cross-protocol agentic commerce evidence receipts. A TrustReceipt is a JWS-signed JSON document that captures cryptographic evidence of an AI agent transaction across payment protocols (x402, AP2, ACP, MCP, UCP, MCAP).

These test vectors are the **current conformance corpus** for the TrustReceipt v1.0 wire format implemented by this reference verifier (the shape validated by `schema/trust-receipt-v1.schema.json`). Any verifier that claims TrustReceipt v1.0 conformance must produce the exact expected outcome for all 10 vectors. The evolving, normative field-level specification lives in [SPEC.md](../SPEC.md) and [`schema/trust-receipt-v1.0-final.schema.json`](../schema/trust-receipt-v1.0-final.schema.json) — see [`schema/README.md`](../schema/README.md) for how the two relate and why this corpus does not yet validate against the normative schema.

> **Note:** All company names, provider names, merchant IDs, transaction IDs, and reference numbers appearing in these test vectors are entirely fictional and used for illustrative purposes only. No real transaction data is included. Named providers (Mastercard, ClearSale, Skyfire, Stripe, etc.) do not endorse or participate in TrustReceipt.

---

## Directory layout

```
test-vectors/
├── README.md           — this file
├── vectors.json        — manifest: all 10 vectors with expected outcomes and failure codes
├── valid/
│   ├── TC-001-mcap-allow.json          — MCAP, allow, 2 trust providers, EU GDPR
│   ├── TC-002-x402-allow.json          — x402, allow, Stripe Radar, permit2 artifact
│   ├── TC-003-ap2-multi-provider.json  — AP2, allow, 3 trust providers, hash chain
│   ├── TC-004-mcp-privacy-eu.json      — MCP, review, PII, EU jurisdiction, GDPR
│   └── TC-005-acp-hash-chain.json      — ACP, allow, Skyfire KYAPay, attachment
└── invalid/
    ├── TC-006-tampered-payload.json    — schema_invalid: empty intent hash + unknown version
    ├── TC-007-expired-receipt.json     — expired: timestamps in Nov 2023
    ├── TC-008-wrong-kid.json           — unknown_kid: key ID not in JWKS
    ├── TC-009-missing-intent-hash.json — schema_invalid: required fields absent
    └── TC-010-wrong-protocol-value.json — schema_invalid: bad enum values
```

---

## Vector file format

Each vector file contains the raw TrustReceipt payload as a JSON object. The files do not contain pre-signed JWS tokens. Your test suite is responsible for wrapping the payload in a JWS at test time using a generated Ed25519 key pair.

Invalid vectors TC-006, TC-007, TC-008, TC-009, and TC-010 include a `_test_hint` field. This field is for human readers only — it must be stripped before signing, or ignored by the verifier if present (verifiers should reject unknown top-level fields via strict schema validation, so TC-006/TC-009/TC-010 would be rejected for schema reasons anyway).

---

## How to use the vectors

### Step 1 — Generate a test Ed25519 key pair

```typescript
import { generateKeyPair, exportJWK } from "jose";

const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
  crv: "Ed25519",
  extractable: true,
});

const privateJwk = await exportJWK(privateKey);
const publicJwk = await exportJWK(publicKey);

// Assign the kid that the valid vectors reference
const KID = "tr-ed25519-2026-04-29-demo";
privateJwk.kid = KID;
publicJwk.kid = KID;
```

### Step 2 — Build a test JWKS

```typescript
const testJwks = { keys: [publicJwk] };
```

### Step 3 — Load a vector payload and sign it

```typescript
import { readFileSync } from "fs";
import { CompactSign, importJWK } from "jose";

const payload = JSON.parse(
  readFileSync("valid/TC-001-mcap-allow.json", "utf8")
) as Record<string, unknown>;

// For valid vectors, refresh timestamps so they don't expire between test runs
const now = Math.floor(Date.now() / 1000);
const payloadToSign = {
  ...payload,
  issued_at: now,
  expires_at: now + 3600,
};

const privKey = await importJWK(privateJwk, "EdDSA");
const jws = await new CompactSign(
  new TextEncoder().encode(JSON.stringify(payloadToSign))
)
  .setProtectedHeader({ alg: "EdDSA", kid: KID })
  .sign(privKey);
```

> **Note on timestamps**: the vector files carry static `issued_at` and `expires_at` values (the date the vector was created). For the valid vectors (TC-001 to TC-005), refresh the timestamps to the current time before signing, or the verifier will return `expired`. The invalid vectors (TC-006 to TC-010) must be used with their original timestamps — TC-007 in particular needs `expires_at` in the past to exercise the `expired` path.

### Step 4 — Call the verifier

```typescript
import { verifyTrustReceipt } from "@agenticmcpstores/trust-receipt-verifier";

const result = await verifyTrustReceipt(jws, { jwks: testJwks });
```

### Step 5 — Assert the outcome matches vectors.json

```typescript
import vectors from "../test-vectors/vectors.json";

const vector = vectors.vectors.find((v) => v.id === "TC-001");
expect(result.valid).toBe(vector.expected === "valid");
```

---

## Special handling per invalid vector

### TC-006, TC-009, TC-010 — schema_invalid

Sign the malformed payload as-is (after stripping `_test_hint`). The verifier must detect the schema violation before or independently of the signature check. Expected result: `{ valid: false, error: 'schema_invalid' }`.

### TC-007 — expired

Sign the payload with the normal test key (kid matches). The verifier must first pass the signature check, then check `expires_at` against the current clock. Expected result: `{ valid: false, error: 'expired' }`.

### TC-008 — unknown_kid

Sign the payload with any real test private key whose `kid` is not present in the test JWKS (i.e., do not add the signing key's public key to `testJwks`). Set `kid: 'nonexistent-key-id-abc123'` in the JWS protected header. The verifier fails at step 2 (key lookup), before signature verification is attempted. Expected result: `{ valid: false, error: 'unknown_kid' }`.

---

## Conformance badge criteria

A verifier earns the **TrustReceipt Conformant** badge when it passes all 10 vectors with the following guarantees:

| Requirement                             | Detail                                                |
| --------------------------------------- | ----------------------------------------------------- |
| All 5 valid vectors accepted            | `result.valid === true` for TC-001 through TC-005     |
| TC-006 rejected as `schema_invalid`     | Empty intent hash and unknown schema_version detected |
| TC-007 rejected as `expired`            | Signature valid but timestamp check fails             |
| TC-008 rejected as `unknown_kid`        | Key lookup failure on JWKS                            |
| TC-009 rejected as `schema_invalid`     | Missing required fields detected                      |
| TC-010 rejected as `schema_invalid`     | Bad enum values rejected                              |
| Schema validation after signature check | Step 4 after Step 3 for TC-006, TC-009, TC-010        |
| Expiry check follows signature check    | For TC-007                                            |
| No partial acceptance                   | A receipt is either fully valid or fully rejected     |
| alg header must be "EdDSA"              | Non-EdDSA alg in header rejected as invalid_jws       |

---

## Supported protocols

The `protocol` field must be one of: `x402`, `AP2`, `ACP`, `MCP`, `UCP`, `MCAP`.

These map to the following agentic commerce payment protocols:

- **x402** — HTTP 402-based micropayments with permit2 ERC-20 authorizations
- **AP2** — Agent Payment Protocol v2 (Mastercard)
- **ACP** — Agent Commerce Protocol (Skyfire KYAPay and similar)
- **MCP** — Model Context Protocol (Anthropic)
- **UCP** — Universal Commerce Protocol
- **MCAP** — Mastercard Agent Pay

---

## Schema version

The current schema version is `1.0`. Verifiers must reject receipts with any other `schema_version` value as `schema_invalid`. Future versions will be introduced via a new string literal (e.g. `"1.1"`, `"2.0"`); verifiers should not accept forward-unknown versions.

---

## Contributing new vectors

To propose additional vectors:

1. Open a PR to this repository targeting `test-vectors/`.
2. Add the payload JSON in the correct subdirectory (`valid/` or `invalid/`).
3. Add an entry to `vectors.json` with a new sequential TC-0xx id, expected outcome, and failure code if invalid.
4. At least 3 maintainers must approve before a vector is merged — merged vectors become part of the normative conformance suite.

---

> **Script integrado**: en lugar de implementar los pasos anteriores manualmente, ejecuta `npx tsx scripts/validate-vectors.ts` desde la raíz del paquete. El script genera un keypair fresco, refresca los timestamps de vectores válidos, firma todos los vectores, llama `verifyTrustReceipt` y reporta pass/fail por vector.
