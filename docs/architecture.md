# TrustReceipt: Architecture

**Spec version**: v1.1 (eIDAS hardening code-complete; v1.0 verification fully preserved)
**Last updated**: 2026-05-18

---

## Overview

This document covers how TrustReceipt works: the signing envelope, key resolution, canonicalization, the verification algorithm and the conformance suite.

For the complete field-level specification, see [SPEC.md](../SPEC.md).
For JSON Schema validation, see [schema/trust-receipt-v1.0-final.schema.json](../schema/trust-receipt-v1.0-final.schema.json), the normative schema. See [schema/README.md](../schema/README.md) for why a second, superseded file also lives in that directory.
For conformance test vectors, see [test-vectors/](../test-vectors/).

---

## 1. Repository structure

```
Trust-Receipt-Verifier/
├── SPEC.md                              # Formal specification (authoritative)
├── README.md                            # Quick start, field reference, npm package usage and CLI reference
├── CONTRIBUTING.md                      # How to contribute vectors, ports, schemas
├── LICENSE                              # MIT
├── TRADEMARKS.md                        # Third-party trademark notices
├── schema/
│   ├── trust-receipt-v1.0-final.schema.json # JSON Schema (v1.0, NORMATIVE)
│   ├── trust-receipt-v1.schema.json     # SUPERSEDED draft, kept for link stability (see schema/README.md)
│   └── README.md                        # Explains which of the two is normative
├── test-vectors/
│   ├── vectors.json                     # Conformance vector manifest
│   ├── README.md                        # How to run the vectors
│   ├── valid/                           # TC-001 through TC-005
│   └── invalid/                         # TC-006 through TC-010
├── reference-verifier/
│   └── README.md                        # npm package usage + CLI reference
└── docs/
    └── architecture.md                  # This document
```

---

## 2. Signing envelope: why JWS Compact

Two formats were considered during design: **JWS Compact** (RFC 7515) and **COSE Sign1** (RFC 8152 / CBOR).

| Dimension            | JWS Compact                           | COSE Sign1                    |
| -------------------- | ------------------------------------- | ----------------------------- |
| Human-readable       | Yes (Base64url, inspectable in tools) | No (binary CBOR)              |
| Existing tooling     | Wide JWT/JWS ecosystem                | Growing (SD-JWT / mdoc focus) |
| Typical receipt size | ~350–600 bytes                        | ~280–450 bytes (smaller)      |
| Language support     | Every major language                  | More limited                  |
| Wallet ecosystem     | Universal JWT support                 | Emerging                      |

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

## 3. Canonicalization: RFC 8785

Before signing, the receipt payload is serialized with **RFC 8785 (JSON Canonicalization Scheme)**:

- Object keys sorted alphabetically (recursive, at every nesting level)
- No extra whitespace
- Unicode characters escaped consistently

This guarantees that `SHA-256(canonical(payload))` comes out identical in any conformant implementation, in any language. That is what lets the `hash_chain_prev` audit chain be verified across languages.

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
2. Resolves the matching public key from the JWKS, by remote URL or inline JWK set.
3. Verifies the signature using that key only. No fallback to other keys in the set.

If no key with the matching `kid` is found: `{ valid: false, reason: "unknown_kid" }`.

### 4.2 Remote JWKS

When a `jwksUrl` is provided, the verifier fetches the key set from that URL. For `trusteed.xyz` it is `https://trusteed.xyz/.well-known/jwks.json`. Implementations should cache this response (recommended TTL: 1 hour) and handle key rotation by re-fetching on a `kid` miss.

### 4.3 Inline JWK set

When an inline array of public JWKs is provided, no network request is made. This is the recommended approach for:

- Offline or air-gapped verification environments
- CI/CD pipelines running the conformance suite
- Audit tools that pin a specific key snapshot

### 4.4 Trust anchor (v1.1+)

v1.1 embeds an issuer root certificate in the verifier package at compile time. An external verifier can check that a JWKS bundle was signed by a key chaining back to that root, so a forged bundle is rejected even if the live endpoint is compromised. Replacing the root takes a SemVer MAJOR bump, so downstream consumers make an explicit, auditable decision.

The `VerifyOptions.trustAnchorPemSha256` field pins the expected root SHA-256. If `jwksHistory.signed_by_root_sha256` does not match any embedded anchor, the verifier hard-fails with `jwks_history_signature_invalid` by default. Staging and CI environments can turn this off with `allowStagingRoots: true`. Never set that flag in production.

---

## 5. Verification algorithm

A conformant verifier executes these steps in order and stops at the first failure:

```
Step 1: Parse JWS structure
  Split on ".". Require exactly 3 segments.
  Base64url-decode segment 0 → JSON → extract "kid" and "alg".
  Fail → "invalid_jws" if malformed, missing alg/kid, or wrong segment count.

Step 2: Resolve public key
  Look up kid in JWKS (remote or inline).
  Fail → "unknown_kid" if not found.
  Fail → "jwks_fetch_failed" if remote JWKS is unreachable (remote mode only).

Step 3: Verify signature
  Run EdDSA/Ed25519 signature verification over segment0.segment1.
  Fail → "tampered_signature" if verification fails.

Step 4: Decode payload
  Base64url-decode segment 1 → JSON.parse → object.
  Fail → "invalid_jws" if decode or parse fails.

Step 5: Schema validation
  Validate the decoded object against the TrustReceipt v1.0 schema.
  Fail → "schema_invalid" if any required field is absent or wrong type.
  Fail → "schema_invalid" if schema_version !== "1.0".

Step 6: Expiry check
  now = current Unix time (seconds).
  Fail → "not_yet_valid" if now < issued_at − clockTolerance.
  Report (NOT fatal, since 2026-07-28) → result.freshness.expired = true
    if now > expires_at + clockTolerance. A v1.0 receipt must keep verifying
    for the multi-year retention window FR-018 (spec-049) requires, so
    `verifyTrustReceipt` no longer fails on expiry alone; see the comment
    above `verifyLegacyCompact` in src/verifier.ts. NOT YET reconciled with
    test-vectors/vectors.json TC-007 (still `expected: "invalid"`, `expired`)
    See the note on the failure-code table in CONTRIBUTING.md.
    `verifyReceiptEnvelope` (v1.1) is unaffected: `receipt_expired` stays fatal
    there.

Step 7: Return
  { valid: true, receipt: <decoded payload> }
```

Implementors should default the clock tolerance to ±30 seconds, which absorbs skew between issuer and verifier systems. `VerifyOptions.toleranceSeconds` (default `30`) sets it.

### 5.1 v1.1 envelope verification (`verifyReceiptEnvelope`)

v1.1 adds a pre-flight JWKS history trust chain check before Steps 1–7:

```
Step 0: Validate JWKS history signature
  Parse jwksHistory.jws_compact (3 segments).
  Check header.alg === "EdDSA".
  Lookup signed_by_root_sha256 in embedded issuer root list.
    Not found + allowStagingRoots=false → "jwks_history_signature_invalid" (hard fail).
    Not found + allowStagingRoots=true  → structural-only parse, emit warning
                                          "jwks_history_signature_unverifiable_staging_root".
    Found → verify EdDSA signature against root public key.
  Parse payload → SignedJwksHistoryPayload (entries[]).
  Fail → "jwks_history_signature_invalid" if any check above fails.
```

Additional v1.1 error codes returned by `verifyReceiptEnvelope`:

| Error code                         | Condition                                                                     |
| ---------------------------------- | ----------------------------------------------------------------------------- |
| `jwks_history_signature_invalid`   | JWKS history JWS malformed, wrong alg, or root SHA not in embedded trust list |
| `unknown_kid`                      | Receipt `kid` not found in the resolved JWKS history entries                  |
| `receipt_expired`                  | `expires_at < now - toleranceSeconds`                                         |
| `receipt_not_yet_valid`            | `issued_at > now + toleranceSeconds`                                          |
| `missing_required_consent_context` | `receipt_subject = "buyer_agent"` but `consent_context` absent                |
| `receipt_subject_mismatch`         | `expectedSubject` option set but `receipt_subject` differs                    |
| `schema_invalid`                   | Zod schema parse failed (missing required field, wrong type, etc.)            |

v1.1 warnings (non-fatal, appended to `result.warnings`):

| Warning                                            | Meaning                                                                                      |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `jwks_history_signature_unverifiable_staging_root` | Root SHA not in embedded list, but `allowStagingRoots: true` was set                         |
| `unknown_trust_provider_present`                   | `trust_provider_assertions[]` contains a `provider` not in the known set                     |
| `tsa_unavailable`                                  | RFC 3161 timestamp evidence absent or fetch failed; posture falls to `ades_candidate_no_tsa` |

---

## 6. Issuance algorithm

A conformant issuer executes these steps:

```
Step 1: Build payload
  Start from caller-supplied fields.
  Auto-populate: receipt_id (UUID v4), schema_version ("1.0"),
    issued_at (current Unix seconds), expires_at (issued_at + validity).

Step 2: Canonicalize
  Apply RFC 8785 to the full payload object (§3 above).

Step 3: Sign
  Sign the canonical bytes with Ed25519.
  Encode result as JWS Compact Serialization.
  Protected header: { "alg": "EdDSA", "kid": "<kid>", "typ": "JWT" }.

Step 4: Return compact JWS string
```

Default validity window: 3600 seconds (1 hour). Issuers MAY use longer windows for archival receipts. Verifiers MUST respect `expires_at` regardless.

---

## 7. Schema

The machine-readable, normative schema lives at [`schema/trust-receipt-v1.0-final.schema.json`](../schema/trust-receipt-v1.0-final.schema.json). It is the normative reference for:

- Required vs optional fields
- Type constraints (UUID v4, Unix seconds, SHA-256 hex, enum values)
- Nested object shapes (`trust_provider_assertions`, `protocol_artifacts`, `verification_methods`, …)

Any implementation claiming TrustReceipt conformance MUST validate receipts against this schema (or a byte-equivalent implementation) before accepting them as valid.

A second file, [`schema/trust-receipt-v1.schema.json`](../schema/trust-receipt-v1.schema.json), also lives in that directory under a similar name. It is a **superseded historic draft**, kept only so existing links keep resolving. It MUST NOT be implemented against. See [`schema/README.md`](../schema/README.md) for the full explanation of why two files exist and how they differ.

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
| TC-006 | invalid | `schema_invalid`: `user_intent_hash` is an empty string and `schema_version` is `"2.0"` (unknown version) |
| TC-007 | invalid | `expired`: `expires_at` is in the past |
| TC-008 | invalid | `unknown_kid`: `kid` in header does not match any key in JWKS |
| TC-009 | invalid | `schema_invalid`: two required fields absent, `user_intent_hash` and `verification_methods` |
| TC-010 | invalid | `schema_invalid`: two enum violations, `protocol` is `INVALID_PROTOCOL` and `policy_decision` is `maybe` |

A verifier claims **TrustReceipt v1.0 Conformant** if and only if it produces the exact expected outcome for all 10 vectors. See [`test-vectors/README.md`](../test-vectors/README.md) for how to run them.

> ⚠️ **Known gap, as of 2026-09-16** ([issue #6](https://github.com/Trusteedxyz/Trust-Receipt-Verifier/issues/6)): running `npx tsx scripts/validate-vectors.ts` against the current reference verifier reports **9/10**, not 10/10. TC-007 now verifies `valid` (with `freshness.expired: true` reported, not fatal) because `verifyTrustReceipt`'s expiry check became informative-only on 2026-07-28 (§6 above), and this vector's `expected: "invalid"` entry has not yet been reconciled with that change. See the note on the failure-code table in `CONTRIBUTING.md`.

---

## 9. Audit chain

Receipts can be linked in a tamper-evident per-merchant chain via `hash_chain_prev`:

```
receipt_N.hash_chain_prev = SHA-256(canonical(receipt_{N-1}))
```

Because canonicalization (§3) is deterministic, any party can independently compute the expected hash and verify chain continuity, with no access to the original raw payloads and no connection to the issuer.

---

## 10. Security properties

| Property | Mechanism |
| --- | --- |
| **Signature integrity** | Ed25519, 64-byte signature, no custom crypto |
| **Payload integrity** | RFC 8785 canonicalization, deterministic across all languages |
| **Key rotation** | `kid` pinning, so old receipts remain verifiable after key rotation |
| **Expiry** | Fatal for `verifyReceiptEnvelope` (v1.1); reported but non-fatal for `verifyTrustReceipt` (v1.0) since 2026-07-28, see §6 and §8 above |
| **No raw PII** | `user_intent_hash`, `cart_hash`, `order_hash` are SHA-256 hashes only |
| **Offline verifiable** | JWKS URL is public and cacheable; no call back to issuer required |
| **Audit chain** | `hash_chain_prev`: tamper-evident linkage, RFC 8785 deterministic |
| **Protocol neutral** | `protocol_artifacts` array, extensible without schema changes |

---

## 11. Schema evolution (v1.0 → v1.1)

v1.1 introduces eIDAS and ESIGN hardening without breaking v1.0 receipts:

| Area | v1.0 | v1.1 |
| --- | --- | --- |
| Receipt envelope | Single compact JWS | JSON envelope: `receipt` (JWS) + `timestamp_evidence` sidecar |
| Timestamp | None | RFC 3161 TST from an independent timestamp authority |
| Legal posture | None | `legal_posture` field tracking eIDAS AdES candidate progression |
| Consent evidence | Optional `consent_context` | Mandatory for buyer-agent receipts; `esign_disclosure_hash` added |
| Protocol artifacts | Rail-specific fields | `payment_authorization_hash` + `authorization_scheme` |
| Trust anchor | JWKS URL only | Embedded issuer root cert (compile-time pinned in verifier) |
| Media type | `application/jose` | `application/vnd.trusteed.receipt-envelope+json` |

v1.0 receipts remain verifiable. Conformant implementations dispatch on `schema_version`.

---

## 12. npm package

The reference implementation is published at:

```bash
npm install trust-receipt-verifier
```

See [`reference-verifier/README.md`](../reference-verifier/README.md) for usage, CLI reference, and porting instructions.

---

## 13. Porting to other languages

To port the verifier to Go, Python, Java, Rust, or another language:

1. Implement the RFC 8785 canonicalizer (§3) and test it against the vectors.
2. Implement the verification algorithm (§5) step-by-step.
3. Run all 10 conformance vectors. Your implementation must produce the exact expected outcomes.
4. Open a PR to [CONTRIBUTING.md](../CONTRIBUTING.md) to list your port.
