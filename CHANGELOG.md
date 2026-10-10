# Changelog: `trust-receipt-verifier`

All notable changes to the verifier package are documented here.

## 0.7.0 (2026-10-10): Bounded input handling, no keys from the receipt under verification

### Security fixes

- **The `trust-receipt` CLI no longer takes a key location from the receipt it is verifying.**
  Without `--jwks-file` or `--jwks-url`, `verify` used to fetch the JWKS from the URL
  declared in the receipt's own `verification_methods`. A plain JWKS carries no signature that
  can be checked against a built-in trust anchor, so a forged receipt that pointed at its own
  JWKS verified as valid. `verify` now exits with code 2 and makes no network request when no
  key source is given; the URL declared in the receipt is printed for information only.
  **Behaviour change:** invocations that relied on the implicit fetch must pass `--jwks-file`
  or `--jwks-url` explicitly.
- **`verify-bundle` passed two options under names the library does not read.**
  `--trust-anchor-sha256` and `--policy-oid` reached `verifyExportBundle` as
  `trustAnchorSha256` and `expectedPolicyOids`, while the library reads
  `trustAnchorPemSha256` and `policyOidAllowlist`, so the pin and the allowlist were silently
  ignored. They are now passed under the names the library reads.
- **Export bundles are unpacked with limits** (`src/verify-export-bundle.ts`). Declared sizes
  are checked before anything is inflated, each entry is inflated with an output cap equal to
  its declared size, and an entry whose real size differs from the declared one is rejected,
  because `adm-zip` bounds its own inflation only when the header declares a size greater than
  zero. Encrypted entries and compression methods other than stored and deflate are rejected.
  New verdict `bundle_limits_exceeded`; defaults are exported as `DEFAULT_BUNDLE_LIMITS` and can
  be tightened or relaxed through `options.limits`: 16 MiB compressed bundle, 64 entries,
  8 MiB per entry, 32 MiB in total, and a 100:1 compression ratio for entries larger than 256 KiB.
  The `..` and `/` path filter is unchanged. The defaults are an estimate, not measured against a
  production bundle.
- **Remote documents are fetched through one bounded helper** (`src/safe-fetch.ts`, exported as
  `safeFetch`, `safeFetchText`, `safeFetchJson` and `SafeFetchError`). It is used for the JWKS
  history, extension artifacts, the audit command and the `--manifest` download. Only `http:`
  and `https:` URLs are accepted; there is a 5 s total timeout; the response size is capped at
  1 MiB while the body is read, with early rejection on `Content-Length`; at most 3 redirects
  are followed and an https to http downgrade is refused. Tune it with `jwksFetch` in
  `VerifyOptions` and in the extension verifier options. Fetching an extension artifact had no
  timeout before.

### Changed

- Internal references were removed from comments, test titles, documentation and a few runtime
  messages (error messages in `zod-1.1.ts` no longer cite decision records). The error codes are
  unchanged. The frozen v1.0-FINAL schema, its hash, the vectors and the vendored TSA client are
  untouched.
- The monorepo-internal export script `scripts/prepare-public-repo.sh` was removed; it only
  worked inside the private checkout.
- Added `SECURITY.md`.

### Tests

- 577 tests in 45 files (31 new: CLI network policy, bundle limits, bounded fetch).

## 0.6.0 (2026-10-10): Verifier hardening, settlement and platform-mandate evidence

### Security hardening

- **Sidecars are bound to what was signed** (`src/verify-sidecars.ts`). A v1.1
  envelope is not itself signed, so `protocol_artifact_sidecars` is
  attacker-controlled. Each sidecar must now match a signed
  `protocol_artifacts[]` entry on type, hash algorithm and digest; the digest is
  recomputed with the algorithm the tag declares; duplicates and orphan
  sidecars are rejected. `hmac-sha256` sidecars cannot be checked without a key
  the verifier does not hold, so they are rejected in both strict and compat
  mode (`protocol_artifact_sidecar_unverifiable`). New error codes:
  `protocol_artifact_sidecar_hash_mismatch`, `_duplicate`, `_unverifiable`.
- **Revocation status lists are authenticated** (`verifyStatusList` in
  `src/revocation.ts`). A fetched list used to count as authoritative if its own
  `signed` field said so. `verifyStatusList` now checks the list's JWS (EdDSA,
  `kid` among the supplied trust anchors, subject, issuer, `iat`/`exp` against an
  injected clock, `issued_at`) and that the signed `manifest_hash` matches the
  body actually received. `checkRevocation` answers `revoked` / `not_revoked`
  only for a list that passed; any other list yields `unknown`
  (`list_not_authenticated`). **Behaviour change:** passing a plain
  `TrustReceiptStatusList` to `checkRevocation` is still accepted by the type
  but now always returns `unknown`.
- **Export bundles: root by fingerprint, JWKS snapshot bound**
  (`src/verify-export-bundle.ts`, `src/verify-jwks-snapshot.ts`). The root used
  to check `jwks-history.jws` is the embedded root matching the fingerprint of
  the bundle's own `trust-anchor.pem`, not whichever root is active today.
  `jwks-snapshot.json` is no longer only required to exist: it must contain the
  `kid` the receipt names and either hash (JCS) to the signed `jwks_sha256` or
  match the root-signed history entry. New rejections: `jwks_snapshot_invalid`,
  `jwks_snapshot_mismatch`.
- New negative and positive conformance vectors under
  `test-vectors/v11-hardening/` (`H001`..`H007`, generated by
  `scripts/generate-hardening-vectors.ts`). Existing vectors and the frozen
  v1.0-FINAL schema are unchanged.

### Added

- **Settlement evidence** (`src/schema/settlement-evidence.ts`): optional
  receipt fields naming the rail reference, funds source and cart hash of the
  charge, so a third party can check the charge independently. Declared in the
  v1.1 body, the v1.0 payload schema and the legacy-compact schema.
- **Platform-issued mandate evidence**
  (`src/schema/platform-mandate-evidence.ts`): optional sibling fields to
  `mandate_verification` (issuer, `kid`, approval class, human-presence flag,
  cart hash). The verifier rejects incoherent combinations (for example human
  presence declared for a class that cannot carry it). Legacy-compact vector
  `L008-platform-mandate-evidence.json`.
- MPP binding: optional `header` and the `mpp-binding/1.1` profile, required
  together or not at all.
- `scripts/generate-legacy-compact-vectors.ts --only <name>` writes a single
  vector without regenerating (and re-signing) the others.
- New public exports: `verifyStatusList`, `STATUS_LIST_JWS_SUBJECT` and their
  types; the settlement and platform-mandate evidence schemas.

### Changed

- `verify-1.1.ts` split: types and pure helpers moved to
  `verify-1.1-types.ts` and `verify-1.1-helpers.ts`.
- Tests that needed the issuer's shared package now use a local test helper.
  The ATEP end-to-end test and the embedded-root cross-check test, which read
  files from the issuer's own code base, are not part of this repository.

## 0.5.0 (2026-09-16): Third-party identity verifiers + evidence field groups

### Added

- **MIA verifier** (`src/mia/`): verifies third-party Merchant Identity
  Assertions (`draft-anders-merchant-identity-assertions-01`), self-issued and
  DNS-authorized issuance. 30 conformance vectors under
  `conformance/mia-vectors/`.
- **AGTP merchant identity verifier** (`src/agtp-merchant/`): verifies the
  Agent Identity Document, Intent Assertion, and Cart-Digest defined by
  `draft-hood-agtp-merchant-identity-02`, exactly the surface the draft
  declares checkable without speaking the AGTP transport itself. No AGTP
  client ships in this package. 50 conformance vectors under
  `conformance/agtp-merchant-vectors/`.
- **Mandate & approval evidence** (`src/schema/mandate-evidence.ts`): optional
  receipt fields letting a third party recompute `mandate_claims_hash` and
  confirm a charged amount fell inside what was authorized, plus separate
  out-of-band human-approval evidence.
- **State Witness evidence** (`src/schema/state-witness-evidence.ts`):
  optional fields declaring what the issuer's state comparator resolved
  before money moved, and against which authoritative state.
- **Operation link** (`src/schema/operation-link.ts`): optional fields tying
  a corrected retry or a reconfirmed execution back to the receipt it
  supersedes. Deliberately distinct from `hash_chain_prev`, which only orders
  a merchant's receipts by issuance time.
- **ATEP passport reference verifier**
  (`reference-verifier/verify-atep-passport.mjs`): a zero-dependency script,
  Node built-ins only, that shows a merchant's portable trust attestation is
  verifiable offline without any Trusteed code.
- 7th `legacy-compact` conformance vector: `L007-signers-declaration.json`.

All new fields are additive with no `schema_version` bump. The frozen
v1.0-FINAL JSON Schema does not declare `additionalProperties` at the top
level.

### Fixed (documentation accuracy)

- SPEC.md §11.6 said "11 v1.1 vectors", but the table beneath it already listed
  12 (including `019b`). The summary line now matches.
- Disclosed a real, dated code/spec discrepancy rather than leaving it
  silent: `scripts/validate-vectors.ts` currently reports 9/10, not 10/10
  (`verifyTrustReceipt`'s expiry check became informative-only on
  2026-07-28, and TC-007's expected outcome was never reconciled with that
  change). See [issue #6](https://github.com/Trusteedxyz/Trust-Receipt-Verifier/issues/6).
- Documented that the RFC 3161 capability's dependency
  (`@agenticmcpstores/trust-receipt-tsa-client`) is Trusteed-internal and not
  published, so that path does not resolve for an external `npm install`
  today. See [issue #5](https://github.com/Trusteedxyz/Trust-Receipt-Verifier/issues/5).
- Retitled this file's two stale "Unreleased" headings (below) to the real
  version + date they actually shipped under (`0.3.0` / `0.2.0`), removed an
  internal Trusteed deployment-coupling paragraph and an unreachable
  sibling-package cross-reference that leaked in from the source monorepo,
  and added a note explaining the pre-launch `1.1.2`→`1.0` version counter
  below is a separate, older axis from this package's own `0.x` line.

## 0.3.0 (2026-07-30): v1.0 enriched-payload regime + declared trust-anchor degradation

Additive, non-breaking. This entry was retitled on 2026-09-16 from a stale
"Unreleased" heading. It shipped as `0.3.0`; the version and date were never
filled in here at the time.

### Emitter↔verifier coupling

An issuer emitting the enriched v1.0 compact payload now stamps
`schema_version: "1.0"` and `canon: "jcs"` on it and canonicalizes with RFC
8785 unconditionally. The legacy-compact branch used to be gated on the
payload NOT declaring a `schema_version` at all, so a verifier still on the
pre-`0.3.0` guard would have rejected every enriched receipt as
`schema_invalid`. An issuer and a verifier running this logic must agree on
which schema-version values route to the legacy-compact path.

### Changed

- `verifier.ts`: version guard replaced. `isLegacyCompatibleSchemaVersion()`
  admits the legacy-compact branch when `schema_version` is **absent** (historic
  corpus) or exactly **`"1.0"`** (enriched issuer). Any other declared value
  (`"1.1"`, `"v1.0-FINAL"`, a future version) is still never silently
  downgraded, which is the invariant the old guard existed to protect.
- `verify-1.1.ts`: `recomputeLegalPosture()` now evaluates the
  `trust_anchor_staging` floor FIRST, so it dominates the whole truth
  table including `merchant_admin`. `merchant_admin_action` names a subject, not
  a strength level, and must not shadow an unverifiable anchor.

### Added

- `VerifyResult.canonicalization: "jcs" | "json-stringify-legacy"`, populated on
  the `legacy_compact` path. `variant` describes the payload SHAPE,
  `canonicalization` the SERIALIZATION; they are independent axes, so an
  enriched compact receipt is `variant: "legacy_compact"` +
  `canonicalization: "jcs"`. `variant` deliberately did NOT change value, so
  existing assertions over historic receipts keep holding.
- `V11VerifyResult.outcome` gains **`"accepted_degraded"`**: a receipt whose
  SIGNED body declares `trust_anchor_staging` verifies instead of being rejected
  for an unverifiable trust anchor. A deliberately NEW value: consumers that
  branch on `outcome === "accepted"` keep refusing it, so accepting the weaker
  guarantee is an opt-in. Scope limit: it attests internal consistency and
  issuer intent, **never issuer authenticity**.
- `"trust_anchor_staging"` added to the closed `LegalPostureWarning` reason enum
  (`zod-1.1.ts`, `types-1.1.ts`). Without it a degraded receipt failed as
  `envelope_schema_invalid`.
- `AivsProofBundle.chain_status`: honest, machine-readable declaration that the
  projected `audit_log` is a single unlinked entry. No issuer writes
  `hash_chain_prev` (zero write sites), so the previous "hash-chained audit log"
  wording was an overclaim.

### Explicitly NOT changed

- **`expires_at` is not enforced on the legacy-compact branch.** The issuer now
  stamps one (`iat + 86400`), but the retention policy requires v1.0 receipts to verify for
  ≥ 7 years and the rows are immutable, so gating on it would mark essentially the
  entire corpus `expired`. Regression tests in all three verifier ports fail if
  anyone adds the check. The 24h TTL over 7-year evidence is a real open
  contradiction, pending a human decision; that is a further reason not to make
  it a validity gate yet.

## 0.2.0 (2026-05-16): Extension Artifact Verification

This entry was retitled on 2026-09-16 from a stale "Unreleased" heading that
carried a "Proposed SemVer bump on release: 1.2.0" line. `1.2.0` was the
private monorepo's own, separate version counter, not this public package's;
the feature shipped under this package's `0.2.0`.

Adds verification for two new artifact families produced by the Trusteed Extension Marketplace ecosystem: **erasure receipts** (developer-signed proof of merchant-data destruction post-uninstall) and **extension manifests** (developer-signed declarations of scopes, endpoints, and lifecycle metadata). Also surfaces existing JWKS-history verification through the CLI. Schema version remains `1.1` (no receipt payload changes). The change is additive and non-breaking.

### New library API

- **`verifyExtensionArtifact(jws, options)`** in `src/verify-extension-artifact.ts`. Generic Ed25519 JWS verifier with kind-discriminated payload-shape gates:
  - `kind: "erasure"`: required fields: `install_id` (string), `deleted_at` (RFC 3339 string), `signed_by.kid` (string). Optional: `evidence_url`, `record_count_destroyed`.
  - `kind: "manifest"`: top-level required-field probe matching `extension-manifest.schema.json` v1 (16 fields incl. `schema_version`, `vendor`, `scopes_requested`, `endpoints`, `event_subscriptions`, `pricing_model`, `data_retention_days`, `risk_category`).
  - Failure reasons: `malformed_jws` | `unsupported_alg` | `missing_kid` | `jwks_unreachable` | `kid_not_found` | `signature_invalid` | `payload_not_json` | `shape_invalid`. All failures return a structured `{ valid: false, kind, reason, detail? }`; nothing throws.
- JWKS resolution honours either inline `jwks: PublicJwk[]` or remote `jwksUrl`. `PublicJwk` is re-exported as an alias of `jose.JWK` for caller convenience.

### CLI

- New `--type <kind>` flag on `trust-receipt verify`:
  - `auto` (default): autodetects by content. JSON object with `jws_compact` → `jwks-history`; v1.1 envelope object with `receipt` + `envelope_metadata` → `receipt`; compact JWS whose payload has `scopes_requested` + `vendor` → `manifest`; payload with `install_id` + `deleted_at` → `erasure`; payload with `protocol` + `issuer` → `receipt`.
  - `receipt`: existing path (v1.0 JWS or v1.1 envelope).
  - `erasure`: invokes `verifyExtensionArtifact(_, { kind: "erasure" })`.
  - `manifest`: invokes `verifyExtensionArtifact(_, { kind: "manifest" })`.
  - `jwks-history`: parses the input as `SignedJwksHistory` and invokes `verifyJwksHistorySignature` against the active embedded issuer root (`getActiveIssuerRoot()`).
- `--help` text updated; CLI output for every verify branch tags results with `kind` so consumers can branch on it.
- **`bundle` (.zip) verification remains deferred.** It is pending ZIP-safety hardening (size cap, structural validation only, no user-controlled extraction) and targeted for a v1.2 follow-up.

### Reference docs

- `README.md` capability matrix updated (Status: implemented vs candidate/experimental) and integration framing realigned around merchant-side evidence rather than "first-mover" claims.
- `README.md` new sections: **What a TrustReceipt does NOT prove** (settlement, delivery, KYC, QeSeal, liability, human intent), **Threat model** (10 attack classes × defence × verifier reason), **Versioning policy** (SemVer × wire format, cross-version v1.0 ↔ v1.1 compatibility commitment ≥12 months).
- Tagline shifted from "cross-protocol evidence receipts" to "merchant-side evidence layer for agentic commerce — protocol-compatible, not protocol-competing".

### Tests

- `src/__tests__/verify-extension-artifact.test.ts`: 12 new tests using real Ed25519 keypairs (no mocks beyond JWKS being passed inline). Coverage: valid receipt, wrong-key, kid-not-found, shape violations (missing/typed-wrong required fields), malformed JWS, alg confusion (ES256 → reject), missing kid header, JWKS unreachable.
- Full verifier suite: **98/98 green** (12 new + 86 existing). `tsc --noEmit` clean for library + CLI.

### Non-goals (deliberate)

- No ZIP `verify-bundle` subcommand in this release. Will land once the size cap, structural-only inspection, and DEFLATE-bomb defences are reviewed.
- No code generation of receipts, manifests, or erasure payloads. Issuance remains the responsibility of `@trusteed/sdk-extension` and platform issuance services.
- No marketplace-state queries. The verifier never calls back to Trusteed; it consumes published JWKS + embedded trust anchors only.

### Related

- These artifact shapes are also consumed by Trusteed's own internal
  developer tooling, which is not part of this public package or repo.

> **Versioning note.** Entries below this point (`1.1.2` down to `1.0`) predate
> this repo's public launch and use a separate, older version counter from
> this package's own `0.x` line above. They are not out of order, and `0.x`
> did not "regress" from `1.1.2`. Kept for historical reference. SPEC.md's own
> version history (§10) is unaffected: it uses schema versions (`1.0`/`1.1`),
> not this package's release versions, which are a separate axis entirely.

## 1.1.2 (2026-05-10): Audit Hardening

Operational hardening release. Schema version stays `1.1` (no payload-shape change). No verifier API breaking changes.

### Verification surfaces

- SD-JWT-VC verification now uses `@sd-jwt/sd-jwt-vc@^0.19.0` + `@sd-jwt/core@^0.19.0` end-to-end. mdoc CBOR remains explicitly out-of-scope (`mdoc_verification_not_implemented`).
- EU LOTL XML parsing now uses `fast-xml-parser@^5.7.0` with a 24h cache and a documented degraded-fallback path (`outcome: "degraded"`).
- RFC 3161 timestamp evidence verification gains trusted-root pinning via a new operator-controlled env var.

### New env vars (operators)

- `QTSA_ROOT_CERT_SHA256_ALLOWLIST`: CSV of trusted RFC 3161 TSA root certificate SHA-256 fingerprints. Operator-controlled, never sourced from the envelope.
- `EU_LOTL_URL`: EU List-of-Trusted-Lists XML endpoint, default `https://ec.europa.eu/tools/lotl/eu-lotl.xml`.
- `EMBEDDED_ISSUER_ROOTS`: PEM-concat input for the trust export bundle.

### Tests

- 134/134 green across verifier + TSA client + signer + export-bundle suites. `tsc --noEmit` clean.

## 1.1.1 (2026-05-10): Verifier API Hardening

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

## 1.1 (2026-05-10): eIDAS + ESIGN Hardening

Receipt envelope split, RFC 3161 timestamp evidence, KMS-backed signing, mandatory consent + agent-authorization chain. 11 new conformance vectors. See SPEC.md §11.

## 1.0 (2026-04-29): Initial draft

24 fields, 10 conformance vectors, 6 protocols, 3 conformance levels. See SPEC.md §1-§10.
