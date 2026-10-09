# Threat model

## What this project does and where untrusted input enters
`trust-receipt-verifier` is a TypeScript library and CLI (`trust-receipt`, `verify-bundle`) that verifies TrustReceipt
evidence receipts for agentic commerce. A receipt is a signed JSON envelope (JWS, EdDSA/ES256) that records what an
agent did and what a merchant or platform attests. Verifiers run inside auditors' and counterparties' systems, so a
flaw in a "valid" verdict is the security bug that matters most.

Everything the verifier is handed is untrusted, because the party who produced it may be the party being checked:
- the receipt envelope and its payload (legacy compact and v1.1 JSON), including extension artifacts and sidecars;
- JWKS documents and JWKS history JWS, whether supplied by the caller or fetched by URL (`--manifest`, `jwksUrl`);
- export bundles (ZIP files unpacked in memory by `verify-export-bundle.ts`);
- RFC 3161 timestamp tokens, CMS structures, certificate chains and OCSP/CRL evidence (ASN.1 parsing);
- x402 / MPP binding inputs, mandate evidence, MIA and AGTP merchant identity objects;
- CLI arguments and file paths.

## Components that matter most / least
Most important:
- Signature and key resolution: `verifier.ts`, `verify-1.0.ts`, `verify-1.1.ts`, `verify-jwks-*.ts`, `issuer.ts`.
  Acceptance of `alg: none`, algorithm confusion, `kid` substitution, or a key that does not belong to the issuer
  is critical.
- Trust anchoring: `embedded-issuer-root.ts`, `verify-export-bundle.ts`. A bundle must never be able to supply its
  own trust anchor.
- Canonicalization and hashing (JCS via `canonicalize`, `binding_hash`, `payload_hash`): two different inputs that
  canonicalize to the same bytes, or a verdict that depends on non-canonical input, is high.
- Revocation, replay and expiry checks: `revocation.ts`, `x402-binding/`.
- ZIP and ASN.1 parsing of attacker-controlled data.
- Fail-closed behaviour: any error, missing field or unreachable lookup must yield a rejected or degraded verdict,
  never an accepted one.

Less important / out of scope:
- `dist/`, `dist-spec/`, `coverage/`, `node_modules/` (generated or third-party).
- `demo/` and `reference-verifier/` are examples. A bug there counts only if it teaches an insecure verification pattern.
- The vendored `vendor/trust-receipt-tsa-client` is in scope only as it is used by the verifier (timestamp evidence).
- `test-vectors/` and `conformance/` are test data, not code under attack.
- The issuing side (the Trusteed platform that signs receipts) is not in this repository.

## How to exercise it
- `pnpm test` runs the unit and conformance suites. `test-vectors/` holds the signed vectors, including negative ones.
- The CLI: `node dist/bin/trust-receipt.js` and `node dist/bin/verify-bundle.js <zip>` after `pnpm run build`.
- Library entry point: `dist/index.js`. The main call is `verifyReceiptEnvelope`.
- The scanner runs without Internet access, so network fetches (`--manifest`, `jwksUrl`) can only be tested with local
  fixtures or a local server.

## How you rate severity
- Critical: a forged, tampered or revoked receipt is reported `accepted` / `valid`, or a bundle imposes its own trust
  anchor.
- High: signature, `kid`, algorithm or canonicalization confusion that is not yet a full forgery; memory exhaustion or
  path traversal when unpacking a ZIP; SSRF through a caller-controlled URL that is fetched without the documented
  checks.
- Medium: denial of service from a small crafted input (ReDoS, unbounded allocation, parser hang); a degraded verdict
  reported as plain accepted.
- Low: information disclosure in error messages, hardening gaps with no demonstrated path to a wrong verdict.
- A wrong verdict on a conformance vector counts as a bug even without an attacker.

## Anything to leave alone
- Known open items already published in the README: RFC 3161 evidence depends on the vendored TSA client (issue #5)
  and the vector `TC-007 / expired` disagrees with the code (issue #6).
- Statements about legal status (eIDAS, ESIGN/UETA) in the docs are not security findings.
- Dependency version advisories with no reachable code path from this package.
