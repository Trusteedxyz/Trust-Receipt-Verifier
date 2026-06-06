<!-- generated-by: gsd-doc-writer -->

# TrustReceipt Specification — Version 1.0

**Status:** Draft
**Date:** 2026-04-29
**Authors:** MCPWebStore (trusteed.xyz)
**Repository:** github.com/trust-receipt/spec
**License:** MIT

---

## Abstract

TrustReceipt is an open standard for cryptographically signed evidence receipts covering AI-agent-initiated commerce transactions across multiple payment protocols. It exists because no portable, verifiable evidence layer spans today's agentic commerce protocols — x402, AP2, ACP, MCP, UCP, and MCAP all operate without a common record format. TrustReceipt solves this by defining a signed receipt format that is verifiable offline against a public JWKS endpoint, protocol-neutral in its data model, and merchant-owned without ongoing issuer dependency.

---

## 1. Introduction

### Legal Disclaimer

> **Disclaimer**: TrustReceipt is cryptographically verifiable technical evidence. It does not by itself determine legal liability. Whether a given receipt is admissible or persuasive in a specific jurisdiction or proceeding depends on applicable local law, the consenting parties' agreements, and other facts beyond the scope of this record format.

_See [docs/legal/trust-receipt-claims-policy.md](../../docs/legal/trust-receipt-claims-policy.md) for the full claims policy._

### 1.1 Motivation

Agentic commerce — where AI agents autonomously execute purchases on behalf of users — is growing faster than the trust infrastructure that should accompany it. Several forces create the gap:

- An April 2026 survey found that 98% of websites cannot complete autonomous agent transactions end-to-end, in part due to absent identity and evidence standards.
- No portable evidence record spans today's major agentic commerce protocols. x402, AP2, ACP, MCP, UCP, and MCAP each define their own payment flow but none define a durable, cross-protocol signed receipt.
- Merchants, auditors, insurers, and regulators need verifiable records of agent-initiated transactions that can be inspected long after the original session ends, without calling back to the issuing platform.
- The EU AI Act (effective August 2026) requires that high-risk AI systems provide explainable records of consequential decisions, including commercial ones. TrustReceipt's `liability_context` and `privacy_classification` fields are designed to support Article 13 transparency requirements.

### 1.2 Design Goals

| Goal                       | Description                                                                                                                                                                                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Protocol-neutral**       | A single receipt format can represent evidence hashes from protocols such as x402, AP2, ACP, MCP, UCP, and MCAP. The `protocol` field identifies which protocol ran; `protocol_artifacts` carry protocol-specific evidence hashes. This does not imply certification or approval by any protocol owner. |
| **Verifier-neutral**       | Any implementation that passes all 10 conformance test vectors is conformant. The conformance suite is the authoritative definition of correct behaviour — no separate implementation is blessed.                                                                                                       |
| **Provider-neutral**       | `trust_provider_assertions` accepts assertions from any fraud, risk, or identity provider. ClearSale, Trulioo, Mastercard AP, Skyfire, and others are treated as peers.                                                                                                                                 |
| **Merchant-owned archive** | Receipts are self-contained JWS tokens. A merchant can export and verify them indefinitely without contacting the issuing platform.                                                                                                                                                                     |
| **Offline verifiable**     | JWS compact serialization with a resolvable JWKS endpoint means any party with the public key can verify any receipt, at any time, without network access to the issuer.                                                                                                                                |

### 1.3 Non-Goals

- TrustReceipt does **not** define payment protocols. It wraps their evidence hashes.
- TrustReceipt does **not** store raw payment data. It holds PSP references only; card numbers, tokens, and credentials are explicitly out of scope.
- TrustReceipt does **not** make legal liability determinations. `liability_context` records who made an assertion and its scope; legal interpretation is left to the assertor and applicable law.
- TrustReceipt does **not** require a specific key infrastructure. JWKS and DID are both supported via `verification_methods`.

### 1.4 Third-Party Protocols and Trademarks

TrustReceipt is not affiliated with, endorsed by, sponsored by, or approved by Mastercard, Anthropic, Skyfire, Coinbase, or any other named protocol owner or company referenced in this specification. Protocol names (AP2, MCAP, ACP, MCP, x402, UCP) are used descriptively to indicate interoperability targets only. All trademarks and registered marks are the property of their respective owners. See [TRADEMARKS.md](TRADEMARKS.md) for the full notice.

No claim of compliance with any third-party protocol is made unless separately certified by that protocol owner. Inclusion of a protocol name in this specification means only that TrustReceipt defines a hash-based evidence record format for use alongside that protocol — not that this specification has been reviewed, approved, or certified by the protocol owner.

---

## 2. Terminology

**Receipt** — A JWS compact serialization token whose payload conforms to the TrustReceipt 1.0 schema.

**Issuer** — The platform that creates and cryptographically signs a receipt. Identified by the `issuer` field (a domain string). Must publish a JWKS or DID document for key resolution.

**Merchant** — The e-commerce operator on whose behalf the agent acted. Identified by `merchant_id`.

**Agent** — The AI agent that performed the transaction. Identified by `agent_id`. May be a specific session, persona, or instance.

**Agent Provider** — The company or platform that runs the agent (e.g. `"anthropic"`, `"openai"`, `"google"`). Recorded in `agent_provider`.

**Trust Provider** — A third-party fraud, risk, or identity service that contributes a signed assertion to the receipt via `trust_provider_assertions` (e.g. ClearSale, Trulioo, Mastercard Agent Pay, Skyfire KYAPay).

**Protocol Artifact** — A SHA-256 hash of a protocol-specific data structure (permit2 authorization, AP2 mandate, ACP session, etc.) recorded in `protocol_artifacts`.

**Conformance Suite** — The set of 10 test vectors in `test-vectors/` that define correct verifier behaviour. A verifier is conformant if and only if it produces the exact expected outcome for every vector.

**JWKS** — JSON Web Key Set (RFC 7517). A JSON document containing one or more public keys used to verify JWS signatures.

**JWS** — JSON Web Signature (RFC 7515). TrustReceipt uses JWS Compact Serialization.

**kid** — Key Identifier. An opaque string that identifies which key in a JWKS was used to sign a particular receipt.

**Policy Decision** — The outcome recorded in `policy_decision`: one of `allow`, `deny`, `review`, or `challenge`. Records what action was taken at transaction time; does not prescribe downstream behaviour.

---

## 3. Receipt Format

### 3.1 Encoding

A TrustReceipt is a JSON object encoded as a JWS Compact Serialization (RFC 7515). The signing algorithm MUST be `EdDSA` with curve `Ed25519`. The JWS protected header MUST include:

```json
{
  "alg": "EdDSA",
  "kid": "<key-id>"
}
```

The JWS payload is the Base64url-encoded canonical JSON-encoded receipt object. Canonicalization follows RFC 8785 (JSON Canonicalization Scheme). The `kid` in the JWS header MUST match the `kid` field in the receipt payload.

### 3.2 Field Reference

All fields at the top level of the receipt payload. Fields marked **Required** MUST be present. Fields marked **Optional** MAY be absent.

#### Core

| Field            | Type                   | Required | Description                                                                           |
| ---------------- | ---------------------- | -------- | ------------------------------------------------------------------------------------- |
| `receipt_id`     | string (UUID v4)       | Required | Unique identifier for this receipt. Issuers MUST NOT reuse receipt IDs.               |
| `schema_version` | `"1.0"`                | Required | Literal string. Verifiers MUST reject any other value as `schema_invalid`.            |
| `issued_at`      | integer (Unix seconds) | Required | Timestamp when the receipt was created.                                               |
| `expires_at`     | integer (Unix seconds) | Required | Timestamp after which the receipt MUST be rejected. MUST be greater than `issued_at`. |
| `issuer`         | string                 | Required | Domain of the issuing platform (e.g. `"trusteed.xyz"`).                               |

#### Participants

| Field            | Type   | Required | Description                                                           |
| ---------------- | ------ | -------- | --------------------------------------------------------------------- |
| `merchant_id`    | string | Required | Opaque string identifying the merchant. Format is issuer-defined.     |
| `agent_id`       | string | Required | Opaque string identifying the agent session or instance.              |
| `agent_provider` | string | Required | Name of the AI provider (e.g. `"anthropic"`, `"openai"`, `"google"`). |

#### Transaction Evidence

| Field              | Type   | Required | Description                                                                                                                 |
| ------------------ | ------ | -------- | --------------------------------------------------------------------------------------------------------------------------- |
| `user_intent_hash` | string | Required | SHA-256 hex digest of the user's original intent text. MUST be non-empty. The original text MUST NOT appear in the receipt. |
| `cart_hash`        | string | Optional | SHA-256 of cart contents at the time of the agent's decision.                                                               |
| `order_hash`       | string | Optional | SHA-256 of the settled order object.                                                                                        |
| `transaction_id`   | string | Optional | Platform-specific transaction reference. Opaque to verifiers.                                                               |

#### Protocol

| Field                | Type                        | Required | Description                                                                                                                                                              |
| -------------------- | --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `protocol`           | enum                        | Required | The payment protocol used. One of: `x402`, `AP2`, `ACP`, `MCP`, `UCP`, `MCAP`.                                                                                           |
| `protocol_artifacts` | array of `ProtocolArtifact` | Required | Protocol-specific evidence hashes. May be empty (`[]`) if no artifact is available. Each element has `type` (string), `hash` (SHA-256 hex), and optional `ref` (string). |

#### Payment

| Field               | Type                         | Required | Description                                                                                                     |
| ------------------- | ---------------------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| `payment_reference` | `{psp: string, ref: string}` | Optional | PSP name and PSP-assigned reference. MUST NOT contain raw payment credentials, card numbers, or payment tokens. |

#### Risk and Trust

| Field                       | Type                              | Required                | Description                                                                                                                                                              |
| --------------------------- | --------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `risk_signals`              | array of `RiskSignal`             | Required (default `[]`) | Normalized risk indicators contributed by the issuer or providers. Each element has `signal_type` (string), `value` (string, number, or boolean), and `source` (string). |
| `trust_provider_assertions` | array of `TrustProviderAssertion` | Required (default `[]`) | Assertions from external trust providers. See §3.3.                                                                                                                      |

#### Decision

| Field             | Type | Required | Description                                                                  |
| ----------------- | ---- | -------- | ---------------------------------------------------------------------------- |
| `policy_decision` | enum | Required | Outcome at transaction time. One of: `allow`, `deny`, `review`, `challenge`. |

#### Compliance and Legal

| Field                    | Type                                                                       | Required | Description                                                                                                   |
| ------------------------ | -------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| `liability_context`      | `{assertor: string, scope: string}`                                        | Optional | Who made the policy assertion and in what commercial scope. Does NOT constitute a legal conclusion.           |
| `consent_context`        | `{consent_hash: string, scope: string, ts: integer}`                       | Optional | Reference to user consent. `consent_hash` is a SHA-256 of the consent record; `ts` is when consent was given. |
| `privacy_classification` | `{contains_pii: boolean, retention_days?: integer, jurisdiction?: string}` | Optional | PII flag and applicable retention/jurisdiction guidance.                                                      |

#### Verification and Key Management

| Field                  | Type                          | Required | Description                                                                                                                                              |
| ---------------------- | ----------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `verification_methods` | array of `VerificationMethod` | Required | How to locate the public key. Each element has `type` (`"jwks"`, `"did"`, or `"key_id"`) and `value` (URL or DID string). At least one element REQUIRED. |
| `kid`                  | string                        | Required | Key ID used to sign this receipt. MUST match the `kid` in the JWS header.                                                                                |

#### Audit Chain

| Field             | Type   | Required | Description                                                                                                                                                  |
| ----------------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `hash_chain_prev` | string | Optional | SHA-256 hex of the previous receipt in the merchant's audit stream. Enables ordered, tamper-evident receipt chains. `null` for the first receipt in a chain. |

#### Attachments

| Field         | Type                  | Required                | Description                                                                                                                                                                                                           |
| ------------- | --------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `attachments` | array of `Attachment` | Required (default `[]`) | Named, hashed file references. Each element has `name` (string), `content_type` (string), `hash` (SHA-256 hex), and optional `uri` (string). The URI points to the artifact; the hash enables integrity verification. |

### 3.3 Assertion Types

The `assertion_type` field in each `TrustProviderAssertion` element MUST be one of the following values:

| Value           | Description                                                                                                                                                                        |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kyc`           | Know Your Customer identity verification result from a regulated provider. `score` is optional; `confidence` is required.                                                          |
| `fraud_score`   | Fraud risk score from a fraud prevention provider. `score` is in `[0, 1]` where 1 is highest risk; `score_range` MAY override the default range (e.g. `"0-1000"` for legacy APIs). |
| `agent_trust`   | Trust signal from the agent's host platform asserting the reliability of this specific agent session.                                                                              |
| `payment_trust` | Trust assessment from a payment network or PSP covering the payment instrument or transaction pattern.                                                                             |
| `identity`      | Identity assertion from an identity provider, attesting attributes of the agent's principal.                                                                                       |

### 3.4 Protocol Artifacts

Expected `protocol_artifacts` entry types by protocol. All values are SHA-256 hex hashes of the referenced object:

| Protocol | Artifact type        | What it hashes                                      |
| -------- | -------------------- | --------------------------------------------------- |
| `x402`   | `permit2_hash`       | The Permit2 authorization struct signed by the user |
| `x402`   | `settlement_hash`    | The on-chain settlement transaction                 |
| `x402`   | `upto_envelope_hash` | The `upto` dispatch envelope (spend-limit variant)  |
| `AP2`    | `mandate_hash`       | The AP2 payment mandate object                      |
| `AP2`    | `ap2_consent_hash`   | The AP2 consumer consent record                     |
| `ACP`    | `acp_session_hash`   | The ACP checkout session object                     |
| `ACP`    | `acp_policy_hash`    | The ACP policy applied to the session               |
| `MCP`    | `mcp_call_hash`      | The MCP tool-call request and response envelope     |
| `MCP`    | `tool_call_hash`     | Individual tool call within an MCP session          |
| `UCP`    | `ucp_token_hash`     | The UCP bearer token or session identifier          |
| `MCAP`   | `mcap_consent_hash`  | The MCAP agent consent record                       |
| `MCAP`   | `mcap_nonce`         | The MCAP request nonce                              |

Other `type` values are permitted; unknown types MUST NOT cause a schema rejection. Verifiers MAY ignore unrecognised artifact types.

---

## 4. Verification Algorithm

A conformant verifier MUST implement the following steps in order. Any step failure returns `{ valid: false, reason: <code> }` immediately; subsequent steps MUST NOT run.

**Step 1 — Parse JWS token**

Split the compact JWS on `.`. Extract the Base64url-decoded protected header. Verify `alg` is `EdDSA`. Extract `kid` from the header. If the token is malformed or `kid` is absent, return `{ valid: false, reason: "invalid_jws" }`.

**Step 2 — Locate public key**

Resolve the public key using one of:

- The caller-provided inline JWKS (array of JWK objects): find the key whose `kid` matches.
- The caller-provided JWKS URL: fetch and parse the JWKS document; find the matching key.
- The receipt payload's `verification_methods` array (after Step 4 schema validation has confirmed the payload structure).

If no key matching `kid` is found in the resolved JWKS, return `{ valid: false, reason: "unknown_kid" }`.

Implementations MUST NOT block on JWKS fetch for longer than 5 seconds. If the fetch times out or fails, return `{ valid: false, reason: "jwks_fetch_failed" }`.

**Step 3 — Verify JWS signature**

Verify the JWS signature using the Ed25519 public key identified in Step 2. If the signature does not verify, return `{ valid: false, reason: "tampered_signature" }`.

**Step 4 — Validate payload schema**

Decode the JWS payload as UTF-8 JSON. Validate the resulting object against the TrustReceipt 1.0 schema:

- `schema_version` MUST equal `"1.0"`.
- All required fields MUST be present with correct types.
- `protocol` MUST be one of `x402`, `AP2`, `ACP`, `MCP`, `UCP`, `MCAP`.
- `policy_decision` MUST be one of `allow`, `deny`, `review`, `challenge`.
- `user_intent_hash` MUST be a non-empty string.
- `verification_methods` MUST be a non-empty array.

If any validation fails, return `{ valid: false, reason: "schema_invalid", errors: [...] }`.

**Step 5 — Check timestamp validity**

Let `now` be the current Unix timestamp in seconds. Allow a clock tolerance of up to 60 seconds.

- If `issued_at > now + tolerance`, return `{ valid: false, reason: "not_yet_valid" }`.
- If `expires_at < now - tolerance`, return `{ valid: false, reason: "expired" }`.

**Step 6 — Return success**

Return `{ valid: true, receipt: <parsed payload> }`.

---

## 5. Key Management

### 5.1 Algorithm

Ed25519 (`EdDSA` with `crv: "Ed25519"`) is the REQUIRED signing algorithm. Ed25519 keys are compact (32-byte public keys), fast to verify, and free from cofactor vulnerabilities present in some other elliptic curve algorithms. Implementations MUST NOT accept receipts signed with RSA, ECDSA, or HMAC algorithms.

### 5.2 Key Identification

Keys are identified by an opaque `kid` string that is unique per issuer. The same `kid` MUST appear in both the JWS protected header and the receipt payload `kid` field.

### 5.3 Key Rotation

When an issuer rotates its signing key:

1. Generate a new Ed25519 key pair with a new `kid`.
2. Publish the new public key in the JWKS endpoint alongside the retiring key.
3. Begin signing new receipts with the new key.
4. The retiring key MUST remain in the JWKS for **at least 30 days** after the last receipt signed with it. This grace period allows verifiers to verify receipts issued before the rotation.
5. After the grace period, the retiring key MAY be removed.

### 5.4 JWKS Endpoint

The recommended JWKS URL path is:

```
/.well-known/trust-receipt-jwks.json
```

The endpoint MUST be served over HTTPS. The response MUST be a valid JWK Set document (RFC 7517). Caching headers SHOULD allow clients to cache the JWKS for up to 1 hour.

Issuers MAY also use a DID document (`did:web:` or `did:key:`) in place of or alongside a JWKS URL, expressed as a `verification_methods` entry with `type: "did"`.

---

## 6. Privacy Considerations

**User intent hashing** — The `user_intent_hash` field is a SHA-256 digest of the original user intent text. The original text MUST NOT appear anywhere in the receipt. This protects conversational privacy while preserving the ability to verify a known intent against its hash.

**Payment data** — The `payment_reference` field MUST contain only a PSP name and a PSP-assigned reference string. Raw card numbers, payment tokens, bank account numbers, and cryptographic payment credentials MUST NOT appear in any receipt field. Receipts are not PCI DSS scoped as long as this constraint is respected.

**PII indicators** — When `privacy_classification.contains_pii` is `true`, the receipt signals that other receipt fields may reference or indirectly identify a natural person. Implementers SHOULD apply the retention limit in `retention_days` and respect the `jurisdiction` field when determining applicable law (e.g. GDPR for `"EU"` jurisdiction).

**Evidence hashes** — `protocol_artifacts`, `cart_hash`, `order_hash`, `consent_context.consent_hash`, and `trust_provider_assertions.evidence_hash` are all SHA-256 hashes of external objects. The external objects themselves are not embedded; only their digests appear. This design limits the privacy exposure surface of the receipt itself.

**Consent context** — `consent_context.consent_hash` links to a consent record without embedding it. The `scope` and `ts` fields provide audit trail entries; the full consent record is stored by the consent management system.

---

## 7. Conformance

### 7.1 Conformance Levels

**Level 1 — Verifier Conformance**

An implementation achieves Level 1 by passing all 10 test vectors in `test-vectors/vectors.json`. This confirms the implementation correctly handles valid receipts, schema rejections, expiry, and key resolution failures.

**Level 2 — Issuer Conformance**

An implementation achieves Level 2 by satisfying Level 1 and correctly issuing receipts such that all 5 valid vector payloads produce valid JWS tokens that pass Level 1 verification. This confirms the implementation can both produce and consume compliant receipts.

**Level 3 — Provider Conformance**

An implementation achieves Level 3 by satisfying Level 2 and co-authoring at least one `trust_provider_assertions` entry type definition with real assertion data contributed by an external trust, fraud, or identity provider. Provider conformance requires a minimum of 3 signing providers to co-author the assertion schema for that `assertion_type`.

### 7.1.1 Agent Identity Assertion Example

An issuer MAY include native RFC 9421 agent identity evidence as a provider
assertion. The provider value `rfc9421-native` denotes verification performed by
the issuer against the agent's HTTP Message Signature and public key discovery,
not a separate third-party trust provider.

```json
{
  "provider": "rfc9421-native",
  "assertion_type": "identity",
  "ts": 1745884800,
  "confidence": "high",
  "evidence_hash": "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
}
```

### 7.2 Test Vectors

The 10 conformance vectors are located in `test-vectors/` and catalogued in `test-vectors/vectors.json`.

| ID     | File                                       | Expected outcome | Failure code     | Notes                                      |
| ------ | ------------------------------------------ | ---------------- | ---------------- | ------------------------------------------ |
| TC-001 | `valid/TC-001-mcap-allow.json`             | valid            | —                | MCAP, 2 trust providers, EU jurisdiction   |
| TC-002 | `valid/TC-002-x402-allow.json`             | valid            | —                | x402, Stripe Radar, permit2 artifact       |
| TC-003 | `valid/TC-003-ap2-multi-provider.json`     | valid            | —                | AP2, 3 trust providers, hash chain         |
| TC-004 | `valid/TC-004-mcp-privacy-eu.json`         | valid            | —                | MCP, `review` decision, PII, GDPR          |
| TC-005 | `valid/TC-005-acp-hash-chain.json`         | valid            | —                | ACP, Skyfire, attachment                   |
| TC-006 | `invalid/TC-006-tampered-payload.json`     | invalid          | `schema_invalid` | Empty intent hash + unknown schema_version |
| TC-007 | `invalid/TC-007-expired-receipt.json`      | invalid          | `expired`        | Timestamps in Nov 2023                     |
| TC-008 | `invalid/TC-008-wrong-kid.json`            | invalid          | `unknown_kid`    | kid not in JWKS                            |
| TC-009 | `invalid/TC-009-missing-intent-hash.json`  | invalid          | `schema_invalid` | Missing required fields                    |
| TC-010 | `invalid/TC-010-wrong-protocol-value.json` | invalid          | `schema_invalid` | Bad enum values                            |

Vectors are unsigned JSON payload files. Test suites generate an ephemeral Ed25519 key pair, sign each payload, and run the verifier. See `test-vectors/README.md` for the step-by-step procedure.

### 7.3 Running the Conformance Suite

```bash
npm install @agenticmcpstores/trust-receipt-verifier
npx trust-receipt conformance
# or: pnpm test (from within the trust-receipt-verifier package)
```

All 10 vectors must pass with zero failures to claim conformance.

### 7.4 Conformance Badge

Implementations that pass all 10 vectors may include the following badge in their documentation:

```markdown
[![TrustReceipt Conformant](https://img.shields.io/badge/TrustReceipt-v1.0%20Conformant-blue)](https://github.com/trust-receipt/spec)
```

---

## 8. Security Considerations

**Clock skew** — Implementations MUST allow a tolerance of up to 60 seconds when evaluating `issued_at` and `expires_at`. Refusing to allow any tolerance creates false rejections due to NTP drift between issuer and verifier. Tolerances larger than 60 seconds open replay windows that are too permissive for commerce contexts.

**Key pinning** — Key pinning is not required by this specification but is RECOMMENDED for high-value or regulated contexts. Implementers may pin a specific `kid` and reject receipts signed with any other key, at the cost of requiring manual intervention on key rotation.

**Receipt tampering** — Because the receipt is a JWS token, any modification to any field in the payload invalidates the signature. Verifiers detect tampering at Step 3 of the verification algorithm. There is no partial integrity mechanism; a receipt is either fully valid or fully invalid.

**Replay attacks** — `receipt_id` uniqueness combined with `expires_at` provides replay resistance within the validity window. Verifiers that maintain a short-term cache of seen `receipt_id` values gain full replay protection. The recommended window for caching `receipt_id` values matches the maximum `expires_at` minus `issued_at` delta for the deployment.

**JWKS availability** — The security of the verification flow depends on the availability and integrity of the JWKS endpoint. Issuers SHOULD serve JWKS over HTTPS with valid TLS certificates, publish at a stable URL, and set `Cache-Control: max-age=3600`. Verifiers SHOULD cache JWKS responses for up to 1 hour and MUST NOT block the verification flow for more than 5 seconds waiting for a JWKS fetch.

**Assertion integrity** — `trust_provider_assertions` entries are embedded in the JWS payload and therefore covered by the issuer's signature. A provider assertion cannot be added, removed, or modified after signing. Providers who wish their assertions to be independently verifiable MAY include an `evidence_hash` pointing to a separately signed assertion document.

---

## 9. Relationship to Other Standards

| Standard                                                  | Specification                                                                                                                             | Relationship                                                                                                                                                                                   |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **x402** (HTTP 402 payment protocol)                      | [coinbase/x402](https://github.com/coinbase/x402)                                                                                         | TrustReceipt wraps x402 Permit2 and settlement artifacts as `protocol_artifacts`. TrustReceipt does not replace x402; it provides the durable evidence layer that x402 itself does not define. |
| **AP2** (Agent Payments Protocol, Google → FIDO Alliance) | [google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2)                                                             | TrustReceipt normalizes AP2 mandate and consent evidence. `agent_trust` assertions from Mastercard Agent Pay fit directly into `trust_provider_assertions`.                                    |
| **ACP** (Agentic Commerce Protocol, OpenAI + Stripe)      | [agentic-commerce-protocol](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol)                                       | TrustReceipt captures ACP session and policy hashes. Skyfire KYAPay assertions map to the `agent_trust` or `payment_trust` assertion types.                                                    |
| **MCP** (Model Context Protocol, Anthropic)               | [modelcontextprotocol.io](https://modelcontextprotocol.io)                                                                                | TrustReceipt records the MCP tool call hash, enabling audit of which tool calls were made during the transaction that produced the receipt.                                                    |
| **UCP** (Universal Commerce Protocol)                     | [Universal-Commerce-Protocol/ucp](https://github.com/Universal-Commerce-Protocol/ucp)                                                     | TrustReceipt captures the UCP bearer token hash as a protocol artifact.                                                                                                                        |
| **MCAP** (Mastercard Agent Pay)                           | [developer.mastercard.com — Agent Pay](https://developer.mastercard.com/mastercard-checkout-solutions/documentation/use-cases/agent-pay/) | TrustReceipt captures MCAP consent and nonce hashes. `mcap_consent_hash` is the primary artifact type.                                                                                         |
| **W3C Verifiable Credentials**                            | [w3.org/TR/vc-data-model](https://www.w3.org/TR/vc-data-model/)                                                                           | `verification_methods` supports `type: "did"` entries, enabling DID-based key resolution compatible with W3C VC infrastructure.                                                                |
| **EU AI Act (Regulation 2024/1689)**                      | [EUR-Lex 32024R1689](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689)                                              | `liability_context` supports Article 13 transparency requirements by recording the assertor and scope. `privacy_classification` supports Article 10 data governance requirements.              |
| **RFC 7515 (JWS)**                                        | [rfc-editor.org/rfc/rfc7515](https://www.rfc-editor.org/rfc/rfc7515)                                                                      | TrustReceipt uses JWS Compact Serialization for all receipts.                                                                                                                                  |
| **RFC 7517 (JWK / JWKS)**                                 | [rfc-editor.org/rfc/rfc7517](https://www.rfc-editor.org/rfc/rfc7517)                                                                      | TrustReceipt uses JWK Sets for key publication and resolution.                                                                                                                                 |
| **RFC 8785 (JCS)**                                        | [rfc-editor.org/rfc/rfc8785](https://www.rfc-editor.org/rfc/rfc8785)                                                                      | Canonical JSON serialization is used for the JWS payload to ensure deterministic hashing.                                                                                                      |

---

## 10. Changelog

| Version | Date       | Notes                                                                                |
| ------- | ---------- | ------------------------------------------------------------------------------------ |
| 1.0     | 2026-04-29 | Initial draft. 24 fields, 10 conformance vectors, 6 protocols, 3 conformance levels. |

---

## 11. TrustReceipt v1.1 Reference (eIDAS + ESIGN Hardening)

**Spec origin**: `specs/049-trust-receipt-eidas-hardening/`
**Architecture**: `docs/architecture/trust-receipt-eidas-hardening-architecture.md`
**Migration guide**: `docs/integrations/trust-receipt-v11-migration.md`

### 11.1 Legal disclaimer (FR-003)

> **Disclaimer**: TrustReceipt v1.1 is cryptographically verifiable technical evidence. It does not by itself determine legal liability. Whether a given receipt is admissible or persuasive in a specific jurisdiction or proceeding depends on applicable local law, the consenting parties' agreements, and other facts beyond the scope of this record format.

The v1.1 record is an **advanced electronic seal candidate (AdES candidate)** under eIDAS — it is NOT a QES and MUST NOT be marketed using QTSP/qualified-tier wording. See `docs/legal/trust-receipt-claims-policy.md` for the canonical permitted/prohibited wording list.

### 11.2 Wire format

A v1.1 receipt is a **JSON envelope** (NOT a single JWS). Media type: `application/vnd.trusteed.receipt-envelope+json`.

```jsonc
{
  "receipt": "<JWS Compact, signed body only>",
  "timestamp_evidence": {
    /* RFC 3161, see §11.4 */
  },
  "envelope_metadata": {
    "receipt_id": "<uuid>",
    "created_at": 1777593601,
    "legal_posture": "ades_candidate_timestamped",
    "legal_posture_warnings": [],
  },
  "protocol_artifact_sidecars": [],
}
```

### 11.3 New v1.1 fields (signed body)

| Field                                                 | Type                                                    | Required when               | Purpose                                                                                                                                                     |
| ----------------------------------------------------- | ------------------------------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_version`                                      | `"1.1"`                                                 | always                      | Wire dispatch.                                                                                                                                              |
| `receipt_subject`                                     | `"buyer_agent" \| "merchant_admin"`                     | always                      | Discriminator (FR-013).                                                                                                                                     |
| `privacy_classification`                              | `"pii_redacted" \| "pii_hashed_salted" \| "pii_absent"` | always                      | PII handling posture.                                                                                                                                       |
| `legal_posture` (signed hint)                         | enum                                                    | always                      | Verifier MUST recompute (FR-019f).                                                                                                                          |
| `buyer_agent_consent_context`                         | object                                                  | subject = buyer_agent       | `consent_type`, `consent_timestamp`, `consent_hash`, `consent_disclosure_version`, `agent_authorization_chain` (≥2 entries), `consent_withdrawal_uri_hash`. |
| `merchant_admin_authorization_context`                | object                                                  | subject = merchant_admin    | `admin_user_id_hash`, `admin_action_type`, `admin_authentication_method`, `mfa_evidence_hash`, `rbac_role_at_action_time`.                                  |
| `payment_authorization_hash` + `authorization_scheme` | string + enum                                           | subject = buyer_agent       | Rail-aware authorization (FR-019c). Replaces legacy `mandate_hash`, `permit2_authorization_hash`, `mcp_tool_invocation_hash`.                               |
| `esign_disclosure_version` + `esign_disclosure_hash`  | semver + sha256                                         | subject = buyer_agent       | 15 U.S.C. §7001(c).                                                                                                                                         |
| `consent_evidence_ref`                                | string                                                  | when consent recorded       | Pointer to signed evidence record.                                                                                                                          |
| `intent_hmac_key_version`                             | string                                                  | always                      | KMS HMAC key ARN (FR-016).                                                                                                                                  |
| `agent_authorization_chain`                           | array of `{actor, method, content_hash, ts}`            | embedded in consent_context | spec-045 RFC 9421 + user authorization (FR-012).                                                                                                            |

All hash-bearing fields use algorithm-tagged digest format `<algo>:<hex>` where `<algo> ∈ {sha256, sha512, hmac-sha256}` (FR-015).

### 11.4 timestamp_evidence (RFC 3161)

Lives at envelope level (NOT inside the signed body). Required fields per FR-020:

```jsonc
{
  "type": "RFC3161",
  "tsa_endpoint": "https://freetsa.org/tsr",
  "tsr": "<base64 of full TimeStampResp>",
  "tst": "<base64 of extracted TimeStampToken>",
  "issued_at_attested": 1777593605,
  "imprint_algo": "sha-256",
  "imprint_target": "jws_compact_bytes",
  "nonce": "<16-byte hex>",
  "policy_oid": "1.2.3.4.1",
  "tsa_cert_chain": ["-----BEGIN CERTIFICATE-----..."],
  "tsa_root_cert_sha256": "...",
  "revocation_evidence": { "kind": "ocsp", "data_b64": "..." },
}
```

Absence permitted ONLY via fail-open path of FR-024 → posture downgrades to `ades_candidate_no_tsa`.

### 11.5 New verifier error codes

In addition to the v1.0 codes:

| Code                               | Trigger                                                                          |
| ---------------------------------- | -------------------------------------------------------------------------------- | ------------------- | ----------------------------------- |
| `kid_outside_validity_window`      | Receipt `issued_at` outside `[valid_from, valid_to]` of resolved kid.            |
| `legal_posture_mismatch`           | Verifier-recomputed posture disagrees with `envelope_metadata.legal_posture`.    |
| `envelope_receipt_id_mismatch`     | `envelope_metadata.receipt_id` ≠ signed body `receipt_id`.                       |
| `sidecar_hash_mismatch`            | Sidecar payload hash ≠ corresponding `protocol_artifacts[].hash` in signed body. |
| `tsa_status_not_granted`           | RFC 3161 `PKIStatus` ≠ `granted`.                                                |
| `tsa_nonce_mismatch`               | TST nonce ≠ issuer-recorded nonce.                                               |
| `tsa_policy_oid_unauthorized`      | Policy OID outside issuer allowlist.                                             |
| `tsa_eku_missing`                  | TSA cert lacks `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8).                         |
| `tsa_chain_invalid`                | TSA cert chain does not validate to pinned root.                                 |
| `tsa_cert_revoked`                 | OCSP/CRL evidence shows TSA cert revoked at `genTime`.                           |
| `tsa_gen_time_out_of_tolerance`    | `                                                                                | genTime - issued_at | > 60s`after applying TSA`accuracy`. |
| `tsa_imprint_mismatch`             | TST imprint ≠ SHA-256(JWS Compact bytes).                                        |
| `missing_required_consent_context` | buyer_agent receipt without `buyer_agent_consent_context`.                       |
| `receipt_subject_mismatch`         | Subject does not match the verification context.                                 |
| `agent_identity_required_strict`   | buyer_agent receipt lacks verified spec-045 agent identity (default policy).     |
| `esign_disclosure_unverified`      | buyer*agent receipt missing `esign_disclosure*\*`.                               |
| `receipt_payload_too_large`        | Canonical body > 2900 bytes OR jws_signing_input > 4096 bytes.                   |

### 11.6 Conformance vectors (v1.1)

11 v1.1 vectors live under `test-vectors/v11/` and are catalogued alongside the legacy 10 v1.0 vectors:

| ID   | File                                             | Outcome          | Failure code                       | Notes                                                                         |
| ---- | ------------------------------------------------ | ---------------- | ---------------------------------- | ----------------------------------------------------------------------------- |
| 011  | `v11/011-buyer-agent-happy-path.json`            | valid            | —                                  | Full v1.1 envelope, AP2, agent identity verified, TST present.                |
| 012  | `v11/012-missing-consent-context.json`           | invalid          | `missing_required_consent_context` | buyer_agent without consent.                                                  |
| 013  | `v11/013-receipt-subject-mismatch.json`          | invalid          | `receipt_subject_mismatch`         | Subject vs verification context conflict.                                     |
| 014  | `v11/014-valid-timestamp-evidence.json`          | valid            | —                                  | Full RFC 3161 chain validates offline.                                        |
| 015  | `v11/015-timestamp-unavailable.json`             | valid (degraded) | —                                  | Posture `ades_candidate_no_tsa`, warning entry.                               |
| 016  | `v11/016-rotated-key-export-bundle.json`         | valid            | —                                  | kid rotated post-issuance, history slice resolves.                            |
| 017  | `v11/017-legacy-v10-receipt.json`                | valid (legacy)   | —                                  | v1.0 receipt accepted by v1.1 verifier, flagged `legacy_pre_eidas_hardening`. |
| 018  | `v11/018-pii-absent.json`                        | valid            | —                                  | privacy_classification=pii_absent.                                            |
| 019  | `v11/019-v11-x402-permit2-required.json`         | valid            | —                                  | x402 EVM Permit2 authorization.                                               |
| 019b | `v11/019b-v11-x402-missing-permit2.json`         | invalid          | `schema_invalid`                   | x402 buyer_agent without authorization.                                       |
| 020  | `v11/020-v11-mcp-tool-invocation-required.json`  | valid            | —                                  | MCP tool invocation authorization.                                            |
| 021  | `v11/021-v11-uk-jurisdiction-export-bundle.json` | valid            | —                                  | UK retention metadata + uk-diatf assertion.                                   |

Combined v1.0 + v1.1 conformance suite: 58/58 passing as of 2026-05-06.

### 11.7 Legacy v1.0 → v1.1 field migration

| v1.0 field                                  | v1.1 replacement                                                              |
| ------------------------------------------- | ----------------------------------------------------------------------------- |
| `mandate_hash`                              | `payment_authorization_hash` + `authorization_scheme = "ap2_mandate_jws"`     |
| `permit2_authorization_hash`                | `payment_authorization_hash` + `authorization_scheme = "evm_permit2"`         |
| `mcp_tool_invocation_hash`                  | `payment_authorization_hash` + `authorization_scheme = "mcp_tool_invocation"` |
| `consent_context.consent_hash`              | `buyer_agent_consent_context.consent_hash` (algorithm-tagged)                 |
| Salt-based `user_intent_hash`               | KMS-keyed HMAC-SHA-256 (`hmac-sha256:` prefix)                                |
| Embedded `timestamp_evidence` (signed body) | Envelope-level `timestamp_evidence` (NOT signed)                              |

See `docs/integrations/trust-receipt-v11-migration.md` for the full consumer-facing diff including breaking changes and migration steps.

### 11.8 Backward compatibility

A v1.1 verifier MUST accept v1.0 receipts (flagged `legacy_pre_eidas_hardening`) for at least 10 years past the issuance cutover (FR-018). v1.0 verifiers cannot consume v1.1 envelopes — content-type negotiation is the dispatch mechanism (see §11.2 media type).

---

## Appendix A: Example Receipt Payload (TC-001, JSON)

The following is the TC-001 MCAP receipt payload in human-readable form. This is the JWS **payload** before signing — not the full compact token.

```json
{
  "receipt_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "schema_version": "1.0",
  "issued_at": 1745884800,
  "expires_at": 1777420800,
  "issuer": "trusteed.xyz",
  "merchant_id": "merchant-shop-demo-01",
  "agent_id": "agent-claude-opus-4-7-session-xyz",
  "agent_provider": "anthropic",
  "user_intent_hash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "cart_hash": "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a15c",
  "order_hash": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9068",
  "transaction_id": "txn-mcap-2026-0429-001",
  "protocol": "MCAP",
  "protocol_artifacts": [
    {
      "type": "mcap_consent_hash",
      "hash": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
    },
    {
      "type": "mcap_nonce",
      "hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a8d"
    }
  ],
  "payment_reference": {
    "psp": "mastercard",
    "ref": "MC-2026-0429-DEMO001"
  },
  "risk_signals": [
    {
      "signal_type": "velocity_check",
      "value": "normal",
      "source": "clearsale"
    },
    {
      "signal_type": "device_fingerprint",
      "value": "verified",
      "source": "mastercard_ap"
    }
  ],
  "trust_provider_assertions": [
    {
      "provider": "clearsale",
      "assertion_type": "fraud_score",
      "score": 0.94,
      "score_range": "0-1",
      "ts": 1745884799,
      "confidence": "high",
      "evidence_hash": "abc123def456abc123def456abc123def456abc123def456abc123def456abcd12"
    },
    {
      "provider": "mastercard_agent_pay",
      "assertion_type": "agent_trust",
      "score": 0.88,
      "score_range": "0-1",
      "ts": 1745884797,
      "confidence": "high",
      "evidence_hash": "fe9a23bc11d047e2fe9a23bc11d047e2fe9a23bc11d047e2fe9a23bc11d047e2"
    }
  ],
  "policy_decision": "allow",
  "liability_context": {
    "assertor": "trusteed.xyz",
    "scope": "commerce_transaction"
  },
  "consent_context": {
    "consent_hash": "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
    "scope": "purchase_consent",
    "ts": 1745884700
  },
  "privacy_classification": {
    "contains_pii": false,
    "retention_days": 365,
    "jurisdiction": "EU"
  },
  "verification_methods": [
    { "type": "jwks", "value": "https://trusteed.xyz/.well-known/jwks.json" }
  ],
  "kid": "tr-ed25519-2026-04-29-demo",
  "hash_chain_prev": null,
  "attachments": []
}
```

---

## Appendix B: Verifier Reference Implementation

The reference verifier is published as an npm package:

```bash
npm install @agenticmcpstores/trust-receipt-verifier
```

Minimal verification in 5 lines:

```typescript
import { verifyTrustReceipt } from "@agenticmcpstores/trust-receipt-verifier";

const result = await verifyTrustReceipt(jwsToken, {
  jwksUrl: "https://trusteed.xyz/.well-known/jwks.json",
});

if (result.valid) {
  console.log(result.receipt.policy_decision); // "allow"
} else {
  console.error(result.reason, result.errors);
}
```

The reference implementation is written in TypeScript and uses `jose` for all JWS operations and `zod` for schema validation. It is the authoritative implementation of the verification algorithm in §4 and the normative reference for all Level 1 conformance claims.

Source: `packages/trust-receipt-verifier/src/verifier.ts`

---

## Appendix C: JSON Schema

A machine-readable JSON Schema (Draft 2020-12) for TrustReceipt 1.0 is located at:

```
packages/trust-receipt-verifier/src/schema/trust-receipt.schema.ts
```

A standalone `schema/trust-receipt-v1.schema.json` distribution file is generated as part of the build. Implementations targeting languages other than TypeScript SHOULD use the JSON Schema file as the schema validation source of truth rather than re-implementing the Zod schema directly.
