<!-- generated-by: gsd-doc-writer -->

# TrustReceipt

**Cross-protocol evidence receipts for agentic commerce**

[![Version](https://img.shields.io/badge/spec-v1.0-blue)](SPEC.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![npm](https://img.shields.io/npm/v/@agenticmcpstores/trust-receipt-verifier)](https://www.npmjs.com/package/@agenticmcpstores/trust-receipt-verifier)
[![TrustReceipt Conformant](https://img.shields.io/badge/TrustReceipt-v1.0%20Conformant-blue)](https://github.com/trust-receipt/spec)

---

## What it is

TrustReceipt is an open standard for JWS-signed JSON receipts that are verifiable offline against a public JWKS endpoint. A receipt can represent evidence hashes from protocols such as x402, AP2, ACP, MCP, UCP, and MCAP without modification to the receipt format itself. Each receipt proves who the agent was, which protocol ran, what trust providers vouched for the transaction, and what policy decision was reached — all in a single self-contained token that any party can verify without calling back to the issuer.

---

## Quick verify

```bash
npm install @agenticmcpstores/trust-receipt-verifier
```

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

---

## Receipt anatomy

A TrustReceipt payload contains 24 fields across five groups:

**Core**

| Field            | Type         | Description                  |
| ---------------- | ------------ | ---------------------------- |
| `receipt_id`     | UUID v4      | Unique receipt identifier    |
| `schema_version` | `"1.0"`      | Schema version literal       |
| `issued_at`      | Unix seconds | When the receipt was created |
| `expires_at`     | Unix seconds | When the receipt expires     |
| `issuer`         | string       | Issuing platform domain      |

**Participants**

| Field            | Type   | Description                                      |
| ---------------- | ------ | ------------------------------------------------ |
| `merchant_id`    | string | Merchant identifier                              |
| `agent_id`       | string | Agent session or instance identifier             |
| `agent_provider` | string | AI provider (`anthropic`, `openai`, `google`, …) |

**Transaction Evidence**

| Field                | Type               | Description                                                                           |
| -------------------- | ------------------ | ------------------------------------------------------------------------------------- |
| `user_intent_hash`   | string (non-empty) | Hash of the user's original intent text — must be non-empty (SHA-256 hex recommended) |
| `cart_hash`          | SHA-256 hex        | Hash of cart contents at decision time (optional)                                     |
| `order_hash`         | SHA-256 hex        | Hash of settled order object (optional)                                               |
| `transaction_id`     | string             | Platform transaction reference (optional)                                             |
| `protocol`           | enum               | `x402 \| AP2 \| ACP \| MCP \| UCP \| MCAP`                                            |
| `protocol_artifacts` | array              | Hashes of protocol-specific evidence objects                                          |
| `payment_reference`  | object             | PSP name + reference, no raw payment data (optional)                                  |

**Trust Assertions**

| Field                       | Type  | Description                                                 |
| --------------------------- | ----- | ----------------------------------------------------------- |
| `risk_signals`              | array | Normalized signals from issuer or providers                 |
| `trust_provider_assertions` | array | Scored assertions from ClearSale, Trulioo, Mastercard, etc. |
| `policy_decision`           | enum  | `allow \| deny \| review \| challenge`                      |

**Compliance**

| Field                    | Type        | Description                                                      |
| ------------------------ | ----------- | ---------------------------------------------------------------- |
| `liability_context`      | object      | Assertor and scope (optional)                                    |
| `consent_context`        | object      | Consent hash, scope, timestamp (optional)                        |
| `privacy_classification` | object      | PII flag, retention days, jurisdiction (optional)                |
| `verification_methods`   | array       | JWKS URL or DID for key resolution — at least one entry required |
| `kid`                    | string      | Key ID used to sign this receipt                                 |
| `hash_chain_prev`        | SHA-256 hex | Previous receipt in audit chain (optional)                       |
| `attachments`            | array       | Named, hashed file references (optional)                         |

---

## Protocol support

| Protocol                                                                                                  | Artifact mapping | Primary artifact types                                  |
| --------------------------------------------------------------------------------------------------------- | ---------------- | ------------------------------------------------------- |
| [MCAP](https://developer.mastercard.com/mastercard-checkout-solutions/documentation/use-cases/agent-pay/) | Defined          | `mcap_consent_hash`, `mcap_nonce`                       |
| [x402](https://github.com/coinbase/x402)                                                                  | Defined          | `permit2_hash`, `settlement_hash`, `upto_envelope_hash` |
| [AP2](https://github.com/google-agentic-commerce/AP2)                                                     | Defined          | `mandate_hash`, `ap2_consent_hash`                      |
| [MCP](https://modelcontextprotocol.io)                                                                    | Defined          | `mcp_call_hash`, `tool_call_hash`                       |
| [ACP](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol)                             | Defined          | `acp_session_hash`, `acp_policy_hash`                   |
| [UCP](https://github.com/Universal-Commerce-Protocol/ucp)                                                 | Defined          | `ucp_token_hash`                                        |

---

## Conformance

A verifier implementation must pass all 10 test vectors to claim TrustReceipt conformance. Three levels are defined:

| Level | Name     | Requirement                                                             |
| ----- | -------- | ----------------------------------------------------------------------- |
| 1     | Verifier | Passes all 10 test vectors                                              |
| 2     | Issuer   | Level 1 + correctly issues valid receipts                               |
| 3     | Provider | Level 2 + co-authors ≥1 `trust_provider_assertions` type with real data |

This reference implementation is Level 2 conformant. There are two ways to run the conformance suite:

**(a) Unit tests** — verifies all 10 vectors using pre-built test infrastructure (10 tests):

```bash
pnpm test
```

**(b) End-to-end JWS conformance** — generates a fresh keypair, signs all 10 vectors, calls `verifyTrustReceipt`, and reports pass/fail per vector:

```bash
# Via CLI (requires the package to be built first)
trust-receipt conformance

# Or directly with tsx (no build required)
npx tsx scripts/validate-vectors.ts
```

Add the badge to your project once all 10 pass:

```markdown
[![TrustReceipt Conformant](https://img.shields.io/badge/TrustReceipt-v1.0%20Conformant-blue)](https://github.com/trust-receipt/spec)
```

---

## Repo structure

```
packages/trust-receipt-verifier/
├── SPEC.md                          — formal specification (authoritative)
├── CONTRIBUTING.md                  — how to contribute vectors, ports, and provider schemas
├── LICENSE                          — MIT
├── src/
│   ├── index.ts                     — package exports
│   ├── verifier.ts                  — verifyTrustReceipt() + parseTrustReceiptUnsafe()
│   ├── issuer.ts                    — issueTrustReceipt()
│   └── schema/
│       └── trust-receipt.schema.ts  — Zod schema (source of truth for TypeScript)
├── test-vectors/
│   ├── README.md                    — how to use the vectors
│   ├── vectors.json                 — vector manifest with expected outcomes
│   ├── valid/                       — TC-001 through TC-005
│   └── invalid/                     — TC-006 through TC-010
├── bin/
│   └── trust-receipt.ts (source) → dist/bin/trust-receipt.js (compiled) — CLI: verify, inspect, generate-key, conformance
└── demo/                            — runnable demo scripts
```

---

## Issue a receipt

```typescript
import { issueTrustReceipt } from "@agenticmcpstores/trust-receipt-verifier";

const jws = await issueTrustReceipt({
  payload: {
    issuer: "trusteed.xyz",
    merchant_id: "merchant-001",
    agent_id: "agent-session-xyz",
    agent_provider: "anthropic",
    user_intent_hash: "<sha256-hex-of-user-intent>",
    protocol: "MCP",
    protocol_artifacts: [{ type: "mcp_call_hash", hash: "<sha256-hex>" }],
    policy_decision: "allow",
    verification_methods: [
      { type: "jwks", value: "https://trusteed.xyz/.well-known/jwks.json" },
    ],
    kid: "tr-ed25519-2026-04-29",
  },
  privateKeyJwk: myEd25519PrivateKey,
  kid: "tr-ed25519-2026-04-29",
});
```

> **Canonicalización**: el payload se serializa con RFC 8785 (claves ordenadas, sin whitespace) antes de firmar, garantizando que `SHA-256(payload)` sea idéntico en cualquier implementación conforme.

## CLI

```bash
# Generate an Ed25519 key pair
trust-receipt generate-key

# Verify a receipt file
trust-receipt verify receipt.jws --jwks-url https://trusteed.xyz/.well-known/jwks.json

# Inspect a receipt without verifying the signature
trust-receipt inspect receipt.jws

# Run full end-to-end conformance suite (signs + verifies all 10 vectors)
trust-receipt conformance
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add conformance vectors, port the verifier to another language, or co-author a `trust_provider_assertions` schema as a trust provider partner.

---

## Trademark Notice

TrustReceipt is not affiliated with, endorsed by, or officially supported by Mastercard, Anthropic, Skyfire, Coinbase, or any other named protocol owner or company referenced in this specification. Protocol names (AP2, MCAP, ACP, MCP, x402, UCP) are used descriptively to indicate interoperability targets only. All trademarks and registered marks are the property of their respective owners.

---

## License

MIT — see [LICENSE](LICENSE). Copyright MCPWebStore (trusteed.xyz), 2026.
