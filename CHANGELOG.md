# Changelog — `trust-receipt-verifier`

All notable changes to the verifier package are documented here.

## Unreleased — v1.0 enriched-payload regime + declared trust-anchor degradation

Additive, non-breaking. Folded into the same **1.2.0** release proposed below.

### Emitter↔verifier coupling (BLOCKING — read before deploying)

The production issuer now stamps `schema_version: "1.0"` and `canon: "jcs"` onto
the signed compact payload and canonicalizes with RFC 8785 unconditionally. The
legacy-compact branch used to be gated on the payload NOT declaring a
`schema_version` at all, so **every newly issued receipt would have failed with
`schema_invalid`** — and `receipt-integrity.service.ts` re-verifies the whole
90-day corpus into the merchant-visible trust score, so the integrity signal
would have collapsed toward zero.

**Issuer and verifier are NOT independently deployable.** The minimum verifier
version compatible with the enriched issuer is **1.2.0**. `apps/api` resolves
this package through its built `dist/`, which is gitignored — so any deploy or
CI job that ships the new issuer MUST also rebuild this package. A stale `dist/`
reproduces the failure exactly.

### Changed

- `verifier.ts` — version guard replaced. `isLegacyCompatibleSchemaVersion()`
  admits the legacy-compact branch when `schema_version` is **absent** (historic
  corpus) or exactly **`"1.0"`** (enriched issuer). Any other declared value —
  `"1.1"`, `"v1.0-FINAL"`, a future version — is still never silently downgraded,
  which is the invariant the old guard existed to protect.
- `verify-1.1.ts` — `recomputeLegalPosture()` now evaluates the
  `trust_anchor_staging` floor FIRST, so it dominates the whole FR-019 truth
  table including `merchant_admin`. `merchant_admin_action` names a subject, not
  a strength level, and must not shadow an unverifiable anchor.

### Added

- `VerifyResult.canonicalization: "jcs" | "json-stringify-legacy"` — populated on
  the `legacy_compact` path. `variant` describes the payload SHAPE,
  `canonicalization` the SERIALIZATION; they are independent axes, so an
  enriched compact receipt is `variant: "legacy_compact"` +
  `canonicalization: "jcs"`. `variant` deliberately did NOT change value, so
  existing assertions over historic receipts keep holding.
- `V11VerifyResult.outcome` gains **`"accepted_degraded"`** — a receipt whose
  SIGNED body declares `trust_anchor_staging` verifies instead of being rejected
  for an unverifiable trust anchor. A deliberately NEW value: consumers that
  branch on `outcome === "accepted"` keep refusing it, so accepting the weaker
  guarantee is an opt-in. Scope limit: it attests internal consistency and
  issuer intent, **never issuer authenticity**.
- `"trust_anchor_staging"` added to the closed `LegalPostureWarning` reason enum
  (`zod-1.1.ts`, `types-1.1.ts`). Without it a degraded receipt failed as
  `envelope_schema_invalid`.
- `AivsProofBundle.chain_status` — honest, machine-readable declaration that the
  projected `audit_log` is a single unlinked entry. No issuer writes
  `hash_chain_prev` (zero write sites), so the previous "hash-chained audit log"
  wording was an overclaim.

### Explicitly NOT changed

- **`expires_at` is not enforced on the legacy-compact branch.** The issuer now
  stamps one (`iat + 86400`), but FR-018 requires v1.0 receipts to verify for
  ≥ 7 years and the rows are immutable — gating on it would mark essentially the
  entire corpus `expired`. Regression tests in all three verifier ports fail if
  anyone adds the check. The 24h TTL over 7-year evidence is a real open
  contradiction, pending a human decision; that is a further reason not to make
  it a validity gate yet.

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

- Sibling package: `@agenticmcpstores/developer-mcp` — the developer-facing
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
