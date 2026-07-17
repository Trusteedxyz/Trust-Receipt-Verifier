# Changelog — `trust-receipt-verifier`

All notable changes to the verifier package are documented here.

## 0.2.0 — Agentic-protocol binding + key-rotation hardening (2026-07-17)

Additive sync from the reference implementation. Opt-in features; existing callers are unaffected except for the tightened `method` validation noted below.

### v1.0 verifier — windowed key-history validation (rotation-gap closure)

- **`VerifyOptions.jwksHistory?: JwksHistoryEntry[]`** added — windowed key entries using the same rotation model as the v1.1 envelope verifier. Resolution priority is `jwksHistory` > `jwksUrl` > inline `jwks`.
- **New error code `"kid_outside_validity_window"`** — a key retired before a receipt's `issued_at`/`iat` can no longer verify it, on both the canonical and `legacy_compact` paths. Closes the gap where a retired or compromised private key could keep forging fresh receipts.
- The `jwksUrl` path now fetches the JWKS and maps it to windowed entries (via `importJWK`) instead of `createRemoteJWKSet`. **Back-compat preserved**: plain RFC 7517 keys without `valid_from`/`valid_to` custom members are treated as always-valid.

### MPP binding extension — realm binding + method format

- **`MppBindingExtensionSchema.realm`** (optional) added — the protection space of the originating `WWW-Authenticate: Payment`, slot 0 of the MPP binding HMAC. Without it, two challenges of different realm with otherwise identical fields collided on the same `binding_hash`.
- **`method`** tightened from `min(1).max(64)` to `^[a-z]{1,64}$` per the draft MPP Method Identifier Format (lowercase ASCII only). **Breaking**: previously-accepted uppercase/mixed-case method identifiers are now rejected.

### x402 binding verifier — explicit expiry flag

- The success result exposes an explicit **`expired?: boolean`** so online callers can gate on `valid && !expired && binding_hash_match` without parsing the `warnings` array. The sync `verify()` path still accepts expired-but-signature-valid receipts (offline/CLI auditors need this).

## Unreleased — Codex Hardening (2026-05-18)

Security and correctness hardening from Codex round-2 audit. No wire-format changes; schema version stays `1.1`. Proposed SemVer bump on release: **1.2.0**.

### Build / export surface fixes

Three build-blocking gaps in `index.ts` re-exports — callers who imported the named exports below would get a runtime crash or TypeScript error:

- **`TSA_ROOT_NOT_TRUSTED_ERROR_CODE`** (`verify-timestamp-evidence.ts`) — constant was re-exported from `index.ts:55` but never defined in the source file. Added `export const TSA_ROOT_NOT_TRUSTED_ERROR_CODE = "tsa_root_not_trusted" as const`.
- **`validateChain` / `ValidateChainError` / `ValidateChainResult`** (`embedded-issuer-root.ts`) — all three were re-exported from `index.ts:89-92` but absent from the source. Added `ValidateChainError` interface, `ValidateChainResult` interface, and `validateChain(roots)` implementation. The function enforces: exactly one active root (`validTo === null`), strictly newest-first ordering, and `validTo ≥ validFrom` on every entry.
- **Package name mismatch** (`index.ts:72`) — `MerchantTsaPolicy` was imported from `@trusteed/trust-receipt-tsa-client` but `package.json` declares the dependency as `@agenticmcpstores/trust-receipt-tsa-client`. Fixed the import specifier.

### JWKS history — hard-fail on unknown roots

**Breaking behaviour change** (opt-out via new flag): previously, when `jwksHistory.signed_by_root_sha256` did not match any embedded trust anchor, the verifier silently fell back to structural-only parsing and emitted a warning. This meant any caller with an unsigned/unknown history would pass without cryptographic verification.

- **`allowStagingRoot?: boolean`** added to `VerifyOptions` (default `false`). When `false` (the new default), an unrecognised root SHA returns `rejected / jwks_history_signature_invalid` immediately. Set `allowStagingRoot: true` only in staging/test environments.
- The warning `jwks_history_signature_unverifiable_staging_root` is now emitted **only** when `allowStagingRoot: true` and the root is unrecognised.
- Conformance tests and signature tests updated to pass `allowStagingRoot: true` (they intentionally use the all-zeros staging SHA).

### Temporal validation for v1.1 receipts

`verifyReceiptEnvelope` now checks `issued_at` and `expires_at` against wall-clock time. Both checks apply a configurable `toleranceSeconds` grace period (default `30` seconds) to absorb minor clock skew.

- **New error code `"receipt_not_yet_valid"`** — returned when `issued_at > now + tolerance`. Indicates the receipt was issued in the future; likely a clock-skew issue or a replay of a pre-issued token.
- **New error code `"receipt_expired"`** — returned when `expires_at < now - tolerance`. Indicates the receipt validity window has elapsed.
- **`VerifyOptions.toleranceSeconds?: number`** added (default `30`). Operators with high clock-skew environments can raise this; production deployments should lower it.

Both new error codes are added to the `V11VerifyErrorCode` union.

### CLI — v1.1 envelope routing

The CLI `trust-receipt verify` command previously routed all receipt-shaped inputs through the v1.0 path. A v1.1 envelope (`receipt` + `envelope_metadata` top-level keys) is structurally different and must be verified with `verifyReceiptEnvelope`.

- **New `VerifyType` value `"receipt-v11"`** — distinct from `"receipt"` (v1.0 JWS compact).
- **`detectArtifactKind`** updated: a JSON object with both `receipt` and `envelope_metadata` keys now returns `"receipt-v11"` instead of `"receipt"`.
- **New `cmdVerifyReceiptV11()` function** — calls `verifyReceiptEnvelope` with options built from the new CLI flags below. Requires `--jwks-history-file` and `--trust-anchor-sha256`; exits with code `1` when either is missing.
- **New CLI flags** (all optional unless noted):
  - `--jwks-history-file <path>` — path to a `SignedJwksHistory` JSON file (required for `receipt-v11`).
  - `--trust-anchor-sha256 <hex>` — expected `trustAnchorPemSha256` for root pinning (required for `receipt-v11`).
  - `--policy-oid <oid>` — may be repeated; builds `policyOidAllowlist` passed to `verifyReceiptEnvelope`.
  - `--allow-staging-root` — passes `allowStagingRoot: true` (staging/CI use only).
- `cmdVerify()` dispatch switch now includes `case "receipt-v11"` routing to `cmdVerifyReceiptV11()`.

### Unknown trust-provider warning

`verifyReceiptEnvelope` now emits a warning when `trust_provider_assertions[]` contains an entry whose `provider` field is not one of the three known values (`"rfc9421-native"`, `"human"`, `"visa"`).

- **New warning `"unknown_trust_provider_present"`** — added to the warnings array before `recomputeLegalPosture()`. At most one instance is emitted per call regardless of how many unknown providers are present. Does **not** cause rejection — forward compatibility for future providers is preserved.

### Tests

- `src/__tests__/conformance-1.1.test.ts`: added `allowStagingRoot: true` and `currentTimeSeconds: vector.verify_options.currentTime` to the v1.1 dispatch path so conformance vectors with static timestamps continue to pass after their `expires_at` elapses.
- `src/__tests__/verify-1.1.signature.test.ts`: same additions to `makeOptions()`.
- `VerifyOptions.currentTimeSeconds?: number` — injectable clock for the `issued_at`/`expires_at` checks; defaults to `Math.floor(Date.now() / 1000)` in production. Conformance tests use this to pin time to the vector's `currentTime`, avoiding spurious `receipt_expired` failures as static vector timestamps age.

---

## Unreleased — Typed Trust-Provider Assertions

Adds typed interfaces and exported type predicates for the known `trust_provider_assertions[]` providers. No runtime behaviour changes; schema version stays `1.1`.

### New library API

- **`Rfc9421ProviderAssertion`** (`types-1.1.ts`) — typed shape for `provider: "rfc9421-native"` assertions. Fields: `verification_status` (`"verified" | "observed" | "spoofed" | "unverified"`), `kid?`, `signer_url?`, `tag?`, `evaluated_at?`.
- **`HumanProviderAssertion`** (`types-1.1.ts`) — typed shape for `provider: "human"` assertions. Fields: `human_verification_status` (`"verified" | "unverified" | "error"`), `human_transaction_id?`, `human_assurance_level?`, `evaluated_at?`.
- **`VisaTapProviderAssertion`** (`types-1.1.ts`) — typed shape for `provider: "visa"` assertions. Fields: `tag` (`"agent-browser-auth" | "agent-payer-auth"`), `verification_status` (`"verified" | "invalid"`), `kid?`, `evaluated_at?`.
- **`KnownTrustProviderAssertion`** (`types-1.1.ts`) — discriminated union of the three typed shapes above.
- **`isRfc9421ProviderAssertion(a)`** (`verify-1.1.ts`) — exported type predicate; narrows `TrustProviderAssertion` (= `Record<string, unknown>`) to `Rfc9421ProviderAssertion`.
- **`isHumanProviderAssertion(a)`** (`verify-1.1.ts`) — exported type predicate; narrows to `HumanProviderAssertion`.
- **`isVisaTapProviderAssertion(a)`** (`verify-1.1.ts`) — exported type predicate; narrows to `VisaTapProviderAssertion`.

### Usage

```ts
import { isRfc9421ProviderAssertion, isHumanProviderAssertion, isVisaTapProviderAssertion } from "trust-receipt-verifier";

const rfc9421 = receipt.trust_provider_assertions?.find(isRfc9421ProviderAssertion);
if (rfc9421?.verification_status === "verified") { /* RFC 9421 signature confirmed */ }

const human = receipt.trust_provider_assertions?.find(isHumanProviderAssertion);
if (human?.human_verification_status === "verified") { /* HUMAN AgenticTrust confirmed */ }

const visa = receipt.trust_provider_assertions?.find(isVisaTapProviderAssertion);
if (visa?.tag === "agent-payer-auth") { /* Visa TAP payer-auth confirmed */ }
```

### Non-goals

- No change to `recomputeLegalPosture` logic — any non-empty `trust_provider_assertions` array still counts as "some assertion present" for posture computation regardless of `provider`.
- `TrustProviderAssertion = Record<string, unknown>` is unchanged — unknown or future providers remain untyped and are accepted for forwards compatibility.

---

## Unreleased — Extension Artifact Verification

Adds verification for two new artifact families produced by the Trusteed Extension Marketplace ecosystem: **erasure receipts** (developer-signed proof of merchant-data destruction post-uninstall) and **extension manifests** (developer-signed declarations of scopes, endpoints, and lifecycle metadata). Also surfaces existing JWKS-history verification through the CLI. Schema version remains `1.1` (no receipt payload changes). Proposed SemVer bump on release: **1.2.0** (additive, non-breaking).

### New library API

- **`verifyExtensionArtifact(jws, options)`** in `src/verify-extension-artifact.ts`. Generic Ed25519 JWS verifier with kind-discriminated payload-shape gates:
  - `kind: "erasure"` — required fields: `install_id` (string), `deleted_at` (RFC 3339 string), `signed_by.kid` (string). Optional: `evidence_url`, `record_count_destroyed`.
  - `kind: "manifest"` — top-level required-field probe matching `extension-manifest.schema.json` v1 (16 fields incl. `schema_version`, `vendor`, `scopes_requested`, `endpoints`, `event_subscriptions`, `pricing_model`, `data_retention_days`, `risk_category`).
  - Failure reasons: `malformed_jws` | `unsupported_alg` | `missing_kid` | `jwks_unreachable` | `kid_not_found` | `signature_invalid` | `payload_not_json` | `shape_invalid`. All failures return a structured `{ valid: false, kind, reason, detail? }` — nothing throws.
- JWKS resolution honours either inline `jwks: PublicJwk[]` or remote `jwksUrl`. `PublicJwk` is re-exported as an alias of `jose.JWK` for caller convenience.

### CLI

- New `--type <kind>` flag on `trust-receipt verify`:
  - `auto` (default) — autodetects by content. JSON object with `jws_compact` → `jwks-history`; v1.1 envelope object with `receipt` + `envelope_metadata` → `receipt`; compact JWS whose payload has `scopes_requested` + `vendor` → `manifest`; payload with `install_id` + `deleted_at` → `erasure`; payload with `protocol` + `issuer` → `receipt`.
  - `receipt` — existing path (v1.0 JWS or v1.1 envelope).
  - `erasure` — invokes `verifyExtensionArtifact(_, { kind: "erasure" })`.
  - `manifest` — invokes `verifyExtensionArtifact(_, { kind: "manifest" })`.
  - `jwks-history` — parses the input as `SignedJwksHistory` and invokes `verifyJwksHistorySignature` against the active embedded issuer root (`getActiveIssuerRoot()`).
- `--help` text updated; CLI output for every verify branch tags results with `kind` so consumers can branch on it.
- **`bundle` (.zip) verification remains deferred** — pending ZIP-safety hardening (size cap, structural validation only, no user-controlled extraction). Targeted for v1.2 follow-up.

### Reference docs

- `README.md` capability matrix updated (Status: implemented vs candidate/experimental) and integration framing realigned around merchant-side evidence rather than "first-mover" claims.
- `README.md` new sections: **What a TrustReceipt does NOT prove** (settlement, delivery, KYC, QeSeal, liability, intent humano), **Threat model** (10 attack classes × defence × verifier reason), **Versioning policy** (SemVer × wire format, cross-version v1.0 ↔ v1.1 compatibility commitment ≥12 months).
- Tagline shifted from "cross-protocol evidence receipts" to "merchant-side evidence layer for agentic commerce — protocol-compatible, not protocol-competing".

### Tests

- `src/__tests__/verify-extension-artifact.test.ts`: 12 new tests using real Ed25519 keypairs (no mocks beyond JWKS being passed inline). Coverage: valid receipt, wrong-key, kid-not-found, shape violations (missing/typed-wrong required fields), malformed JWS, alg confusion (ES256 → reject), missing kid header, JWKS unreachable.
- Full verifier suite: **98/98 green** (12 new + 86 existing). `tsc --noEmit` clean for library + CLI.

### Non-goals (deliberate)

- No ZIP `verify-bundle` subcommand in this release. Will land once the size cap, structural-only inspection, and DEFLATE-bomb defences are reviewed.
- No code generation of receipts, manifests, or erasure payloads. Issuance remains the responsibility of `@trusteed/sdk-extension` and platform issuance services.
- No marketplace-state queries. The verifier never calls back to Trusteed; it consumes published JWKS + embedded trust anchors only.

### Related

- Sibling package: `@trusteed/developer-mcp` — the developer-facing
  documentation MCP server. See its CHANGELOG `Unreleased` entry for the
  matching IDE-time tools (`get_extension_manifest_schema`,
  `get_webhook_event_schema`, `get_extension_scopes`).

## 1.1.2 — 2026-05-10 — Audit Hardening

Operational hardening release. Schema version stays `1.1` (no payload-shape change). No verifier API breaking changes.

### Verification surfaces

- SD-JWT-VC verification now uses `@sd-jwt/sd-jwt-vc@^0.19.0` + `@sd-jwt/core@^0.19.0` end-to-end. mdoc CBOR remains explicitly out-of-scope (`mdoc_verification_not_implemented`).
- EU LOTL XML parsing now uses `fast-xml-parser@^5.7.0` with a 24h cache and a documented degraded-fallback path (`outcome: "degraded"`).
- RFC 3161 timestamp evidence verification gains trusted-root pinning via a new operator-controlled env var.

### New env vars (operators)

- `QTSA_ROOT_CERT_SHA256_ALLOWLIST` — CSV of trusted RFC 3161 TSA root certificate SHA-256 fingerprints. Operator-controlled, never sourced from the envelope.
- `EU_LOTL_URL` — EU List-of-Trusted-Lists XML endpoint, default `https://ec.europa.eu/tools/lotl/eu-lotl.xml`.
- `EMBEDDED_ISSUER_ROOTS` — PEM-concat input for the trust export bundle.

### Tests

- 134/134 green across verifier + TSA client + signer + export-bundle suites. `tsc --noEmit` clean.

## 1.1.1 — 2026-05-10 — Verifier API Hardening

Twelve hardening fixes. Schema version stays `1.1`; verifier API surface gains required options and new error codes.

### Breaking changes

- **`VerifyOptions.tsaRootCertSha256Allowlist`** is now required for TSA root pinning. Envelope-supplied `tsa_root_cert_sha256` is no longer trusted on its own.
- **`VerifyOptions.allowStagingRoots`** added (default `false`). Receipts whose issuer root is flagged staging fail with new error `root_not_in_trust_anchor` unless explicitly enabled.
- **`revocation_evidence.kind`** schema is now a `discriminatedUnion('ocsp' | 'crl' | 'unavailable')`. The `unavailable` branch carries `reason` (`ocsp_unreachable | crl_unreachable | fetch_timeout | synthetic_fixture`) and `attempted_at`.
- **Field rename**: `intent_salt_version` → `intent_hmac_key_version` end-to-end (4 callers updated).
- **Removed export**: `verifyTimestampEvidenceStub`. Use `verifyTimestampEvidence` instead.

### New error codes

- `root_not_in_trust_anchor`
- `tsa_root_not_trusted`
- `tsa_revocation_unavailable`

### Non-breaking hardening (issuance / signing pipeline)

- AWS KMS signing now uses `SigningAlgorithm: "ED25519_SHA_512"` against `ECC_NIST_EDWARDS25519` CMKs (was `ECDSA_SHA_256`, which was incompatible with the key type).
- Dual size cap: `MAX_RECEIPT_BODY_BYTES=2900` + `MAX_JWS_SIGNING_INPUT_BYTES=4096`.
- TSA default policy is `fail_open`; per-merchant `merchantTsaPolicy` is now plumbed from verifier through to the TSA client.
- DLP `high_entropy_secret` action default escalated `warn` → `block`. New `DlpScanContext { allowUuidShape, highEntropySeverity }` for opt-in relaxation.
- Claims-policy CI lint bypass now requires a `CLAIMS_POLICY_BYPASS_TOKEN` env var in addition to the commit trailer.
- Manifest signing wired to the KMS signing service end-to-end; secret-vault fallback removed (manifest signing now fails closed on KMS outage).
- Cloud audit `LookupEvents` query rewritten to a single-attribute filter, with secondary criteria filtered client-side.

### Tests

- Verifier: 86/86 green.
- TSA client: 25 pass + 2 todo.
- KMS signer: 12/12 green.
- `tsc --noEmit` clean across the verifier + sibling packages.

## 1.1 — 2026-05-10 — eIDAS + ESIGN Hardening

Receipt envelope split, RFC 3161 timestamp evidence, KMS-backed signing, mandatory consent + agent-authorization chain. 11 new conformance vectors. See SPEC.md §11.

## 1.0 — 2026-04-29 — Initial draft

24 fields, 10 conformance vectors, 6 protocols, 3 conformance levels. See SPEC.md §1-§10.
