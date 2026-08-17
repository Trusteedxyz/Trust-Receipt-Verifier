# Migrating from TrustReceipt v1.0 to v1.1

Consumer-facing migration guide for anyone who verifies TrustReceipts: what
breaks, what moves, and what you have to change.

This document is assembled from the released changelog entries (`1.1`, `1.1.1`,
`1.1.2` in [CHANGELOG.md](../../CHANGELOG.md)) and the normative reference in
[SPEC.md §11](../../SPEC.md). Where the two disagree, **SPEC.md wins** — it is
the normative document, this one is a reading aid.

> **Scope.** This covers the *verification* surface. Issuer-side changes (KMS
> signing algorithms, DLP scanning, manifest signing) are listed only where they
> alter what a verifier receives.

---

## 1. The one change you cannot skip: the wire format

A v1.0 receipt **is** a JWS. A v1.1 receipt **contains** one.

| | v1.0 | v1.1 |
| --- | --- | --- |
| Wire shape | JWS Compact — three dot-separated base64url segments | JSON object |
| Required keys | n/a (opaque string) | `receipt` (the JWS Compact string) + `envelope_metadata` (object) |
| Optional keys | n/a | `protocol_artifact_sidecars`, `timestamp_evidence` |
| Media type | `application/jose` | `application/vnd.trusteed.receipt-envelope+json` |
| Entry point | `verifyTrustReceipt()` / `verifyReceiptV10()` | `verifyReceiptEnvelope()` |

Consequences:

- **A v1.0 verifier cannot consume a v1.1 envelope.** It will see a JSON object
  where it expected a compact JWS. Dispatch on the media type, or use
  `detectReceiptFormat()` / `verifyReceiptAuto()` from this package.
- **A v1.1 verifier MUST keep accepting v1.0 receipts** for at least 10 years
  past the issuance cutover (SPEC.md §11.8, FR-018). Results carry the
  `legacy_pre_eidas_hardening` warning; that warning is a deprecation signal,
  not a failure.
- `envelope_metadata` is **not signed**. Anything you rely on for a trust
  decision must come from the verified body, never from the envelope mirror.
  This is the single most common porting mistake.

---

## 2. The verdict is three-valued, not boolean

`verifyReceiptEnvelope()` returns `accepted`, `accepted_degraded`, or
`rejected`. Treating the result as a boolean is a conformance failure in both
directions — it either reports a degraded receipt as fully verified, or discards
a valid one.

`accepted_degraded` means signature and structure verified while the receipt
*itself declares* its chain of trust unverifiable (a
`legal_posture_warnings[]` entry with `reason: "trust_anchor_staging"`). It
attests internal consistency and issuer intent, never issuer authenticity. A
receipt that stays *silent* about an unverifiable anchor is `rejected` — silence
is never read as consent. See SPEC.md §11.9 (NORMATIVE).

If your existing code branches on `outcome === "accepted"`, it keeps refusing
degraded receipts, which is the safe default. Accepting the weaker guarantee has
to be a conscious act.

---

## 3. Breaking changes to `VerifyOptions` (1.1.1)

| Change | What you must do |
| --- | --- |
| `tsaRootCertSha256Allowlist` is now **required** for RFC 3161 timestamp pinning | Supply the allowlist yourself. An envelope-supplied `tsa_root_cert_sha256` is no longer trusted on its own — trust anchors are operator-controlled, never envelope-controlled. |
| `allowStagingRoots` added, default `false` | Nothing, if you run in production. Receipts whose issuer root is flagged staging now fail with `root_not_in_trust_anchor` unless you explicitly opt in. Never opt in outside staging/CI. |
| `revocation_evidence.kind` is now a discriminated union `'ocsp' \| 'crl' \| 'unavailable'` | Handle the `unavailable` branch: it carries `reason` (`ocsp_unreachable`, `crl_unreachable`, `fetch_timeout`, `synthetic_fixture`) and `attempted_at`. |
| Field renamed: `intent_salt_version` → `intent_hmac_key_version` | Rename at your read sites. The old name is gone, not aliased. |
| Export removed: `verifyTimestampEvidenceStub` | Use `verifyTimestampEvidence`. |

### New failure codes

`root_not_in_trust_anchor`, `tsa_root_not_trusted`, `tsa_revocation_unavailable`
— in addition to the v1.1 envelope codes listed in
[CONTRIBUTING.md §3](../../CONTRIBUTING.md) (`jwks_history_signature_invalid`,
`receipt_expired`, `receipt_not_yet_valid`, `missing_required_consent_context`,
`receipt_subject_mismatch`).

Switch on these codes, never on message text.

---

## 4. Field-level mapping

Reproduced from SPEC.md §11.7, which is normative:

| v1.0 field | v1.1 replacement |
| --- | --- |
| `mandate_hash` | `payment_authorization_hash` + `authorization_scheme = "ap2_mandate_jws"` |
| `permit2_authorization_hash` | `payment_authorization_hash` + `authorization_scheme = "evm_permit2"` |
| `mcp_tool_invocation_hash` | `payment_authorization_hash` + `authorization_scheme = "mcp_tool_invocation"` |
| `consent_context.consent_hash` | `buyer_agent_consent_context.consent_hash` (algorithm-tagged) |
| Salt-based `user_intent_hash` | KMS-keyed HMAC-SHA-256, `hmac-sha256:` prefix |
| Embedded `timestamp_evidence` (inside the signed body) | Envelope-level `timestamp_evidence` (**NOT** signed) |

Two of these change meaning, not just location:

- **`payment_authorization_hash` is only interpretable together with
  `authorization_scheme`.** The same hash field now covers AP2 mandates, EVM
  Permit2 authorizations, MCP tool invocations, and more. Reading the hash
  without the scheme conflates protocols.
- **Algorithm-tagged hashes.** `consent_hash` and `user_intent_hash` carry an
  explicit algorithm prefix (e.g. `hmac-sha256:`). Do not assume bare SHA-256.

---

## 5. New required evidence for buyer-agent receipts

When `receipt_subject = "buyer_agent"`, `consent_context` is **mandatory**.
Absent it, verification fails with `missing_required_consent_context`. If you
also pass the `expectedSubject` option, a mismatch fails with
`receipt_subject_mismatch`.

---

## 6. Operator-side environment (1.1.2)

Relevant only if you run the verification stack yourself:

| Variable | Purpose |
| --- | --- |
| `QTSA_ROOT_CERT_SHA256_ALLOWLIST` | CSV of trusted RFC 3161 TSA root certificate SHA-256 fingerprints. Operator-controlled; never sourced from the envelope. |
| `EU_LOTL_URL` | EU List-of-Trusted-Lists XML endpoint. Default `https://ec.europa.eu/tools/lotl/eu-lotl.xml`. Parsed with a 24h cache and a documented degraded fallback (`outcome: "degraded"`). |
| `EMBEDDED_ISSUER_ROOTS` | PEM-concat input for the trust export bundle. |

mdoc CBOR verification remains explicitly out of scope
(`mdoc_verification_not_implemented`). SD-JWT-VC verification is implemented.

---

## 7. What v1.1 does *not* give you

- **It is not a Qualified Electronic Seal.** A v1.1 record is at best an
  *advanced* electronic seal candidate (AdES candidate) under eIDAS. Qualified
  seals require issuance by an EU-listed QTSP, which is outside this package.
  Do not market v1.1 with QTSP or qualified-tier wording.
- **The trust anchor shipped in this package is a staging stub.**
  `EMBEDDED_ISSUER_ROOTS` currently holds a structurally-valid but
  non-verifying placeholder whose subject CN is marked `(STAGING)`, and
  `validateChain()` fail-closes on it with `root_key_not_provisioned`. Pin your
  own `trustAnchorPemSha256` until the offline root-key ceremony has run.

---

## 8. Migration checklist

1. Dispatch on media type (or `detectReceiptFormat()`); keep the v1.0 path alive.
2. Replace boolean verdict checks with the three-valued `outcome`.
3. Supply `tsaRootCertSha256Allowlist`; confirm `allowStagingRoots` is `false`.
4. Handle `revocation_evidence.kind === "unavailable"`.
5. Rename `intent_salt_version` → `intent_hmac_key_version`.
6. Replace `verifyTimestampEvidenceStub` with `verifyTimestampEvidence`.
7. Read `payment_authorization_hash` **with** `authorization_scheme`.
8. Stop reading trust-relevant fields from `envelope_metadata`.
9. Add the new failure codes to your error handling.
10. Re-run the combined conformance suite (v1.0 + v1.1 vectors) against your port.
