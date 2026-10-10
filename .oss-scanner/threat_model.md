# Threat model

## What this project does and where untrusted input enters
`trust-receipt-verifier` is a TypeScript library and CLI (`trust-receipt`, `verify-bundle`) that verifies
TrustReceipt evidence receipts for agentic commerce. A receipt is a signed JSON envelope (JWS, EdDSA) that records what
an agent did and what a merchant or platform attests. Verifiers run inside auditors' and counterparties' systems, so a
flaw in a "valid" / "accepted" verdict is the security bug that matters most.

Everything the verifier is handed is untrusted, because the party who produced it may be the party being checked:
- the receipt: legacy compact JWS and v1.1 JSON envelope, its payload, extension artifacts and
  `protocol_artifact_sidecars`;
- JWKS documents and JWKS history JWS, supplied inline, from a file, or fetched by URL (`--jwks-url`, `jwksUrl`);
- revocation status lists (`revocation.ts`), including the `signed` flag and `signature` they carry;
- export bundles (ZIP files unpacked in memory by `verify-export-bundle.ts` with the strict in-house reader in `zip-reader.ts`: no ZIP64, encryption or multi-disk; local and central names must agree; no duplicate or overlapping entries; inflation capped at the declared size; CRC-32 checked), including
  `trust-anchor.pem`, `jwks-history.jws`, `jwks-snapshot.json` and the optional external `manifest.jws`
  (`verify-bundle --manifest URL`);
- RFC 3161 timestamp responses, CMS structures, certificate chains and OCSP/CRL evidence (ASN.1 parsing in
  `verify-timestamp-evidence.ts` and `vendor/trust-receipt-tsa-client/`);
- x402 / MPP binding inputs, mandate evidence, MIA (`src/mia/`) and AGTP merchant identity objects
  (`src/agtp-merchant/`);
- CLI arguments and file paths.

## Components that matter most / least
Most important:
- Signature and key resolution: `verifier.ts`, `verify-1.0.ts`, `verify-1.1.ts`, `verify-jwks-history.ts`, `verify-jwks-snapshot.ts`, `issuer.ts`.
  Acceptance of `alg: none` or another algorithm, algorithm confusion, `kid` substitution, or a key that does not
  belong to the issuer is critical. Key material, or the location of key material, taken from the receipt being
  verified is not a trust source: the CLI refuses to verify without an explicit `--jwks-file` / `--jwks-url`.
- Trust anchoring: `embedded-issuer-root.ts`, `verify-export-bundle.ts`. A bundle must never be able to supply its own
  trust anchor; the trust root must be the one matched by the fingerprint of the bundle's `trust-anchor.pem`; the bundled
  `jwks-snapshot.json` must be bound to the signed receipt body or the root-signed history; `allowStagingRoots` must stay
  off by default.
- Canonicalization and hashing (JCS via `canonicalize`, `binding_hash`, payload and sidecar hashes): two different inputs
  that canonicalize to the same bytes, or a verdict that depends on non-canonical input, is high.
- Revocation, replay and expiry checks: `revocation.ts`, `x402-binding/`. A status list is accepted as
  authoritative only after `verifyStatusList` checks its JWS against trust anchors and its body against the signed
  `manifest_hash`; an unauthenticated list must yield `unknown`, never `not_revoked`.
- Sidecar binding: `verify-sidecars.ts`, called from `verify-1.1.ts` (each sidecar must match a signed
  `protocol_artifacts` entry on type, algorithm and digest; no duplicates, no orphans; `hmac-sha256` sidecars are rejected).
- ZIP, JSON and ASN.1 parsing of attacker-controlled data (`verify-export-bundle.ts`, `vendor/trust-receipt-tsa-client/`):
  traversal, decompression bombs, unbounded allocation, parser hangs. Bundles are unpacked under limits (compressed size,
  entry count, per-entry and total inflated size, compression ratio; `DEFAULT_BUNDLE_LIMITS`, verdict
  `bundle_limits_exceeded`), declared sizes are checked before inflating, and an entry whose real size differs from its
  declared size is rejected. A way around those limits is a finding.
- Network fetches of caller-supplied URLs (`fetchJwksAsHistory` in `verifier.ts`, `verify-extension-artifact.ts`,
  `src/cli/audit-command.ts`, `bin/verify-bundle.ts`) all go through `safe-fetch.ts`: `http`/`https` only, 5 s timeout,
  1 MiB cap enforced while the body is read, at most 3 redirects, no https to http downgrade. Which host a caller chooses to
  contact is the caller's decision (a verifier library does not filter private addresses); a URL taken from the artifact
  under verification would be a finding.
- Fail-closed behaviour: any error, missing field or unreachable lookup must yield a rejected or degraded verdict,
  never an accepted one.

Less important / out of scope:
- `dist/`, `coverage/`, `node_modules/` (generated or third-party).
- `demo/` and `reference-verifier/` are examples. A bug there counts only if it teaches an insecure verification pattern.
- `scripts/` generate vectors; `scripts/lib/keys.ts` and `demo/` use deterministic or throwaway test keys derived from a
  seed that is in the repository. Those keys are public test keys, not secrets.
- The vendored `vendor/trust-receipt-tsa-client` is in scope only as the verifier uses it (timestamp evidence).
- `test-vectors/` and `conformance/` are test data, not code under attack. They deliberately contain forged, tampered,
  expired and wrong-key receipts and the JWKS/key files that go with them.
- The issuing side (the Trusteed platform that signs receipts) is not in this repository.

## How to exercise it
- `pnpm install`, `pnpm run build`, then `pnpm test` (vitest, runs `src/**` unit and conformance suites; about 577 tests).
  The workspace file that links `vendor/trust-receipt-tsa-client` is written by the Dockerfile, not committed.
- `test-vectors/` and `conformance/` hold signed vectors, positive and negative; `npx tsx scripts/validate-vectors.ts`
  checks the legacy set.
- The CLI: `node dist/bin/trust-receipt.js verify <jws> --jwks-file <file>` and
  `node dist/bin/verify-bundle.js <zip> ...` after the build.
- Library entry point: `dist/index.js`; main calls are `verifyTrustReceipt`, `verifyReceiptEnvelope`,
  `verifyExportBundle`, `verifyStatusList` + `checkRevocation`.
- The scanner runs without Internet access, so network fetches (`--jwks-url`, `--manifest`, `jwksUrl`) can only be tested
  against a local server or fixtures.

## How you rate severity
- Critical: a forged, tampered, wrong-issuer or revoked receipt is reported `valid` / `accepted`, or a bundle or receipt
  imposes its own trust anchor or signing key.
- High: signature, `kid`, algorithm or canonicalization confusion that is not yet a full forgery; a revocation or sidecar
  check that can be satisfied by attacker-controlled data; memory exhaustion or path traversal when unpacking a ZIP;
  SSRF through a caller-controlled URL fetched without checks.
- Medium: denial of service from a small crafted input (ReDoS, decompression bomb, unbounded allocation, parser hang); a
  degraded or unverifiable verdict reported as plain accepted.
- Low: information disclosure in error messages, hardening gaps with no demonstrated path to a wrong verdict.
- A wrong verdict on a conformance vector counts as a bug even without an attacker.

## Anything to leave alone
- Known open items already published in the README: RFC 3161 evidence depends on the vendored TSA client (issue #5) and
  the vector `TC-007 / expired` disagrees with the code (issue #6, expiry is informative-only by design for retention).
- Invalid, forged or tampered receipts, and private-looking key material, inside `test-vectors/`, `conformance/`, `demo/`
  and `scripts/` are intentional test fixtures.
- Statements about legal status (eIDAS, ESIGN/UETA) in the docs are not security findings.
- Dependency version advisories with no reachable code path from this package, and findings in devDependencies.
