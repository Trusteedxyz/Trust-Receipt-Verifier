# Conformance Vectors — TrustReceipt-x402 Binding Profile (spec-054)

This directory contains conformance vectors for the v1.1 x402 binding profile.

Each vector is a JSON file with:

```json
{
  "vector_id": "NNN",
  "name": "human-readable-slug",
  "version": "1.0.0",
  "binding_profile_version": "1.0.0",
  "inputs": {
    "paymentRequirements": {...},
    "paymentPayload": {...},
    "resource_uri": "...",
    "settlement_evidence": {...},
    "output_body_or_manifest": {...}
  },
  "expected": {
    "receipt_envelope": {...},
    "binding_hash": "sha256:<hex>",
    "verifier_result": { "valid": true, "posture": "...", "warnings": [] }
  },
  "jwks_snapshot": { "keys": [...], "authorized_delegates": [...] }
}
```

## Required vectors (FR-024, post-Codex round 2)

- `001-discovery-happy.json` — capability advertisement in 402 response
- `002-evm-permit2-happy.json` — EVM Permit2 inline happy path
- `003-svm-token-authorization-happy.json` — Solana SVM async happy path
- `004a-direct-issuer-happy.json` — FR-008a Rama A (kid ∈ keys[])
- `004b-delegated-issuer-happy.json` — FR-008a Rama B (kid ∈ authorized_delegates[])
- `005a-binding-mismatch-resource.json` — resource URI mismatch
- `005b-binding-mismatch-payload.json` — paymentPayload mismatch
- `005c-binding-mismatch-settlement.json` — settlement evidence mismatch
- `005d-binding-mismatch-unknown-kid.json` — kid not in keys[] nor authorized_delegates[]
- `008-pii-filter.json` — HMAC PII filter (no literal strings)
- `009-pii-challenge-attestation.json` — challenge/attestation flow

Test runner: `pnpm --filter @trusteed/trust-receipt-verifier test:vectors:x402-binding`
