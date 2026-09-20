# JSON Schemas

## `trust-receipt-v1.0-final.schema.json` — NORMATIVE

The v1.0 schema. `$id` is `https://trusteed.xyz/spec/v1.0/trust-receipt.schema.json`,
sealed by the sibling `.sha256` file and embedded byte-identically into the
publishable verifiers. **Implementations in any language MUST validate against
this file.**

## `trust-receipt-v1.schema.json` — SUPERSEDED

A historic draft, formerly the only schema in this directory. Its shape is
**incompatible** with the normative document above: it is JSON Schema draft-07,
sets `additionalProperties: true`, and declares a different `required` set
(it requires `agent_id`, `risk_signals` and `kid`; it omits `legal_posture`,
`receipt_subject` and `privacy_classification`).

It is retained so that existing links keep resolving and historic artifacts stay
interpretable. It MUST NOT be implemented against. See SPEC.md Appendix C.
