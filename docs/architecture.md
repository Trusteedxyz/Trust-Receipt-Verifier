# TrustReceipt — Architecture

**Spec version**: v1.0 (v1.1 eIDAS hardening in progress)
**Last updated**: 2026-05-15

---

## Overview

This document describes the architecture of TrustReceipt: the signing envelope format, the key resolution model, the canonicalization scheme, the verification algorithm, and the conformance system.

For the complete field-level specification, see [SPEC.md](../SPEC.md).
For JSON Schema validation, see [schema/trust-receipt-v1.schema.json](../schema/trust-receipt-v1.schema.json).
For conformance test vectors, see [test-vectors/](../test-vectors/).

---

## 1. Repository structure

```
Trust-Receipt-Verifier/
├── SPEC.md                              — Formal specification (authoritative)
├── README.md                            — Quick start and field reference
├── CONTRIBUTING.md                      — How to contribute vectors, ports, schemas
├── LICENSE                              — MIT
├── TRADEMARKS.md                        — Third-party trademark notices
├── schema/
│   └── trust-receipt-v1.schema.json     — JSON Schema (v1.0)
├── test-vectors/
│   ├── vectors.json                     — Conformance vector manifest
│   ├── README.md                        — How to run the vectors
│   ├── valid/                           — TC-001 through TC-005
│   └── invalid/                         — TC-006 through TC-010
├── verifier/
│   └── README.md                        — npm package usage + CLI reference
└── docs/
    └── architecture.md                  — This document
```

---

## 2. Signing envelope — why JWS Compact

Two formats were considered during design: **JWS Compact** (RFC 7515) and **COSE Sign1** (RFC 8152 / CBOR).

| Dimension            | JWS Compact                           | COSE Sign1                       |
| -------------------- | ------------------------------------- | -------------------------------- |
| Human-readable       | Yes (Base64url, inspectable in tools) | No (binary CBOR)                 |
| Existing tooling     | Wide JWT/JWS ecosystem                | Growing (SD-JWT / mdoc focus)    |
| Typical receipt size | ~350–600 bytes                        | ~280–450 bytes (smaller)         |
| Language support     | Every major language                  | More limited                     |
| Wallet ecosystem     | Universal JWT support                 | Emerging                         |

**Decision**: JWS Compact. COSE deferred until a partner wallet or SDK requires it, or payload-size benchmarks justify the added dependency.

### Compact serialization

A TrustReceipt is a three-segment string:

```
BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
```

Protected header (always):

```json
{ "alg": "EdDSA", "kid": "<key-id>", "typ": "JWT" }
```

The signing algorithm is always `EdDSA` over curve `Ed25519`. No other algorithm is accepted by a conformant verifier.

---

## 3. Canonicalization — RFC 8785

Before signing, the receipt payload is serialized with **RFC 8785 (JSON Canonicalization Scheme)**:

- Object keys sorted alphabetically (recursive, at every nesting level)
- No extra whitespace
- Unicode characters escaped consistently

This guarantees that `SHA-256(canonical(payload))` is identical in any conformant implementation across any language — which is what makes the `hash_chain_prev` audit chain cross-language verifiable.

Reference implementation (TypeScript, no external dependency):

```typescript
function canonicalizeJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalizeJson).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const sorted = Object.keys(obj)
    .sort()
    .map((k) => JSON.stringify(k) + ":" + canonicalizeJson(obj[k]));
  return "{" + sorted.join(",") + "}";
}
```

Port this function when implementing TrustReceipt in another language. It must produce byte-identical output for the same input.

---

## 4. Key resolution model

### 4.1 kid pinning

Every receipt carries a `kid` field in both the JWS protected header and the payload body. The verifier:

1. Extracts `kid` from the JWS header (base64url-decode the first segment).
2. Resolves the matching public key from the JWKS — by remote URL or inline JWK set.
3. Verifies the signature using that key only. No fallback to other keys in the set.

If no key with the matching `kid` is found: `{ valid: false, reason: "unknown_kid" }`.

### 4.2 Remote JWKS

When a `jwksUrl` is provided, the verifier fetches the key set from `/.well-known/jwks.json` on the issuer domain. Implementations should cache this response (recommended TTL: 1 hour) and handle key rotation by re-fetching on a `kid` miss.

### 4.3 Inline JWK set

When an inline array of public JWKs is provided, no network request is made. This is the recommended approach for:
- Offline or air-gapped verification environments
- CI/CD pipelines running the conformance suite
- Audit tools that pin a specific key snapshot

### 4.4 Trust anchor (v1.1+)

In v1.1, an issuer root certificate is embedded at compile time inside the verifier package. External verifiers can validate that a JWKS bundle was signed by a key chaining back to this root — preventing forged JWKS bundles even if the live endpoint were compromised. Rolling the root requires a SemVer MAJOR bump, giving downstream consumers explicit, auditable control.

---

## 5. Verification algorithm

A conformant verifier executes these steps in order and stops at the first failure:

```
Step 1 — Parse JWS structure
  Split on ".". Require exactly 3 segments.
  Base64url-decode segment 0 → JSON → extract "kid" and "alg".
  Fail → "invalid_jws" if malformed, missing alg/kid, or wrong segment count.

Step 2 — Resolve public key
  Look up kid in JWKS (remote or inline).
  Fail → "unknown_kid" if not found.
  Fail → "jwks_fetch_failed" if remote JWKS is unreachable (remote mode only).

Step 3 — Verify signature
  Run EdDSA/Ed25519 signature verification over segment0.segment1.
  Fail → "tampered_signature" if verification fails.

Step 4 — Decode payload
  Base64url-decode segment 1 → JSON.parse → object.
  Fail → "invalid_jws" if decode or parse fails.

Step 5 — Schema validation
  Validate the decoded object against the TrustReceipt v1.0 schema.
  Fail → "schema_invalid" if any required field is absent or wrong type.
  Fail → "schema_invalid" if schema_version !== "1.0".

Step 6 — Expiry check
  now = current Unix time (seconds).
  Fail → "expired"       if now > expires_at + clockTolerance.
  Fail → "not_yet_valid" if now < issued_at − clockTolerance.

Step 7 — Return
  { valid: true, receipt: <decoded payload> }
```

**Clock tolerance**: implementors should default to ±30 seconds to account for clock skew between issuer and verifier systems.

---

## 6. Issuance algorithm

A conformant issuer executes these steps:

```
Step 1 — Build payload
  Start from caller-supplied fields.
  Auto-populate: receipt_id (UUID v4), schema_version ("1.0"),
    issued_at (current Unix seconds), expires_at (issued_at + validity).

Step 2 — Canonicalize
  Apply RFC 8785 to the full payload object (§3 above).

Step 3 — Sign
  Sign the canonical bytes with Ed25519.
  Encode result as JWS Compact Serialization.
  Protected header: { "alg": "EdDSA", "kid": "<kid>", "typ": "JWT" }.

Step 4 — Return compact JWS string
```

Default validity window: 3600 seconds (1 hour). Issuers MAY use longer windows for archival receipts; verifiers MUST respect `expires_at` regardless.

---

## 7. Schema

The machine-readable schema lives at [`schema/trust-receipt-v1.schema.json`](../schema/trust-receipt-v1.schema.json). It is the normative reference for:

- Required vs optional fields
- Type constraints (UUID v4, Unix seconds, SHA-256 hex, enum values)
- Nested object shapes (`trust_provider_assertions`, `protocol_artifacts`, `verification_methods`, …)

Any implementation claiming TrustReceipt conformance MUST validate receipts against this schema (or a byte-equivalent implementation) before accepting them as valid.

---

## 8. Conformance system

The conformance suite defines correct verifier behavior through 10 test vectors in [`test-vectors/`](../test-vectors/):

| Vector | Expected | Scenario |
| --- | --- | --- |
| TC-001 | valid   | MCAP receipt, two trust providers (ClearSale + Mastercard AP), EU GDPR classification |
| TC-002 | valid   | x402 receipt, Stripe payment reference, single Stripe Radar assertion |
| TC-003 | valid   | AP2 receipt, three trust providers, `hash_chain_prev` linking |
| TC-004 | valid   | MCP receipt, `policy_decision=review`, PII flag, EU jurisdiction |
| TC-005 | valid   | ACP receipt, Skyfire KYAPay assertion, PDF attachment |
| TC-006 | invalid | `schema_invalid` — payload field tampered after signing |
| TC-007 | invalid | `expired` — `expires_at` is in the past |
| TC-008 | invalid | `unknown_kid` — `kid` in header does not match any key in JWKS |
| TC-009 | invalid | `schema_invalid` — `user_intent_hash` missing (required field) |
| TC-010 | invalid | `schema_invalid` — `schema_version` is an unknown value |

A verifier claims **TrustReceipt v1.0 Conformant** if and only if it produces the exact expected outcome for all 10 vectors. See [`test-vectors/README.md`](../test-vectors/README.md) for how to run them.

---

## 9. Audit chain

Receipts can be linked in a tamper-evident per-merchant chain via `hash_chain_prev`:

```
receipt_N.hash_chain_prev = SHA-256(canonical(receipt_{N-1}))
```

Because canonicalization (§3) is deterministic, any party can independently compute the expected hash and verify chain continuity — with no access to the original raw payloads and no connection to the issuer.

---

## 10. Security properties

| Property | Mechanism |
| --- | --- |
| **Signature integrity** | Ed25519 — 64-byte signature, no custom crypto |
| **Payload integrity** | RFC 8785 canonicalization — deterministic across all languages |
| **Key rotation** | `kid` pinning — old receipts remain verifiable after key rotation |
| **Expiry** | `expires_at` enforced by every conformant verifier |
| **No raw PII** | `user_intent_hash`, `cart_hash`, `order_hash` are SHA-256 hashes only |
| **Offline verifiable** | JWKS URL is public and cacheable; no call back to issuer required |
| **Audit chain** | `hash_chain_prev` — tamper-evident linkage, RFC 8785 deterministic |
| **Protocol neutral** | `protocol_artifacts` array — extensible without schema changes |

---

## 11. Schema evolution (v1.0 → v1.1)

v1.1 introduces eIDAS and ESIGN hardening without breaking v1.0 receipts:

| Area | v1.0 | v1.1 |
| --- | --- | --- |
| Receipt envelope | Single compact JWS | JSON envelope: `receipt` (JWS) + `timestamp_evidence` sidecar |
| Timestamp | None | RFC 3161 TST — independent timestamp authority |
| Legal posture | None | `legal_posture` field tracking eIDAS AdES candidate progression |
| Consent evidence | Optional `consent_context` | Mandatory for buyer-agent receipts; `esign_disclosure_hash` added |
| Protocol artifacts | Rail-specific fields | `payment_authorization_hash` + `authorization_scheme` |
| Trust anchor | JWKS URL only | Embedded issuer root cert (compile-time pinned in verifier) |
| Media type | `application/jose` | `application/vnd.trusteed.receipt-envelope+json` |

v1.0 receipts remain verifiable; conformant implementations dispatch on `schema_version`.

---

## 12. npm package

The reference implementation is published at:

```bash
npm install @agenticmcpstores/trust-receipt-verifier
```

See [`verifier/README.md`](../verifier/README.md) for usage, CLI reference, and porting instructions.

---

## 13. Porting to other languages

To port the verifier to Go, Python, Java, Rust, or another language:

1. Implement the RFC 8785 canonicalizer (§3) — test it against the vectors.
2. Implement the verification algorithm (§5) step-by-step.
3. Run all 10 conformance vectors — your implementation must produce exact expected outcomes.
4. Open a PR to [CONTRIBUTING.md](../CONTRIBUTING.md) to list your port.
