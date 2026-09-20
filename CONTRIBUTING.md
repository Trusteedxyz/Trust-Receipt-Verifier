<!-- generated-by: gsd-doc-writer -->

# Contributing to TrustReceipt

There are four ways to contribute to TrustReceipt: adding conformance vectors, co-authoring as a trust provider, porting the verifier to a new language, and taking part in governance.

---

## 1. Adding Conformance Vectors

Conformance vectors define correct verifier behaviour. Every vector merged into `test-vectors/` becomes part of the normative standard.

**When to add a vector:**

- A new protocol adapter introduces artifact types not covered by existing vectors.
- An edge case (e.g. a specific expiry window, a multi-provider assertion combination) is not exercised by TC-001 through TC-010.
- A new `assertion_type` value is proposed and needs coverage.

**How to add a vector:**

1. Fork the repository and create a branch.
2. Place your payload JSON in `test-vectors/valid/` or `test-vectors/invalid/` with a sequential filename (`TC-011-*.json`, etc.).
3. Add an entry to `test-vectors/vectors.json` with:
   - `id`: next sequential TC-0xx
   - `file`: relative path to your JSON file
   - `expected`: `"valid"` or `"invalid"`
   - `failure_code`: one of `schema_invalid`, `expired`, `unknown_kid`, `tampered_signature` (invalid vectors only)
   - `protocol`: the protocol enum value covered
   - `description`: one sentence explaining what this vector tests
4. Run the full test suite locally (`pnpm test`) and confirm all vectors pass, including the new one.
5. Open a pull request. The PR description must explain why this vector is needed and which part of the specification it exercises.

**Merge requirement:** At least 3 maintainers must approve a new vector before it is merged. Merged vectors are normative and cannot be changed without a version bump.

---

## 2. Co-authoring as a Trust Provider

If you run a fraud prevention, identity, risk or payment network service (ClearSale, Trulioo, Mastercard Agent Pay, Skyfire KYAPay, NeuroID or a comparable one), you can co-author the schema for an `assertion_type` entry and have your provider name recognized in the standard.

**What co-authoring means:**

- You define or extend the schema for your `assertion_type` value in `src/schema/trust-receipt.schema.ts`.
- You sign 2 sample receipts using your production assertion data (or representative anonymized data) and submit them as Level 3 conformance test vectors.
- SPEC.md §7.1 sets the bar for a Level 3 claim: at least 3 signing providers must co-author the assertion schema for a given `assertion_type`. Your contribution counts toward that minimum and does not reach Level 3 on its own.
- Your provider name and assertion type are listed in SPEC.md §3.3.
- Your participation is recorded in the SPEC.md changelog.

**How to co-author:**

1. Open an issue titled `Provider: <your-company-name> — assertion_type: <type>`.
2. Describe the assertion schema you want to formalize: field names, types, value ranges, confidence semantics.
3. The maintainers will work with you to merge the schema addition and vector pair.
4. Co-authorship requires review and sign-off from at least 2 existing maintainers plus your own technical contact.

**Example provider identifiers used in conformance vectors** are illustrative only and are not endorsements or official participation: `example_fraud_provider`, `example_identity_provider`, `example_payment_network`, `example_agent_trust_provider`. Real provider names are accepted in production receipts as free-form strings. They become part of the normative standard only when that provider has co-authored and signed sample vectors per §2 of this document.

---

## 3. Porting the Verifier

The project wants verifier implementations in TypeScript, Python, Java, Go and Rust. The TypeScript implementation is the reference implementation, but it is not the standard. Every port must implement the verification algorithm defined in SPEC.md §4 and pass all 10 conformance test vectors. The vectors decide whether a port conforms.

**Steps to port:**

1. Read SPEC.md §4 (Verification Algorithm). It is the source of truth, not the TypeScript source.
2. Implement each of the 6 steps in order. The steps are:
   - Parse JWS and extract `kid`
   - Locate the public key via JWKS or DID
   - Verify the Ed25519 JWS signature
   - Validate the payload against the TrustReceipt 1.0 schema
   - Check `issued_at` and `expires_at` with ≤60s clock tolerance
   - Return `valid: true` with the receipt, or `valid: false` with a reason code
3. Use the test vectors in `test-vectors/` to validate your implementation. The `vectors.json` manifest specifies expected outcomes and failure codes for all 10 vectors.
4. Publish your port and open a PR that updates the "Reference ports (TS) / language ports" row of the "Capability status" table in `README.md`.

**Failure reason codes your port must return:**

_v1.0 (`verifyTrustReceipt`)_

| Code                 | Condition                                                  |
| -------------------- | ---------------------------------------------------------- |
| `invalid_jws`        | Malformed compact serialization or missing `kid` in header |
| `unknown_kid`        | `kid` not found in the resolved JWKS                       |
| `tampered_signature` | Signature verification failed                              |
| `schema_invalid`     | Payload does not conform to TrustReceipt 1.0 schema        |
| `not_yet_valid`      | `issued_at > now + tolerance`                              |
| `jwks_fetch_failed`  | JWKS URL unreachable or fetch timed out                    |

> ⚠️ **`expired` is NOT a rejection code for `verifyTrustReceipt` as of 2026-07-28.**
> This table listed it as fatal until this note; the current TypeScript reference
> implementation reports expiry via `result.freshness.expired` (informative)
> instead of failing verification, so that a v1.0 receipt keeps verifying for
> the multi-year retention window FR-018 (spec-049) requires — see the comment
> above `verifyLegacyCompact` in `src/verifier.ts`. **This has not yet been
> reconciled with `test-vectors/vectors.json` TC-007** (still declares
> `expected: "invalid"`, `expired`), so running `scripts/validate-vectors.ts`
> today reports 9/10, not 10/10 — tracked in
> [issue #6](https://github.com/Trusteedxyz/Trust-Receipt-Verifier/issues/6).
> Track that issue's resolution (either restore a fatal check for the
> conformance-suite shape specifically, or update the vector manifest + this
> table together, since it is the cross-language verifier ABI) before porting
> this behavior. `verifyReceiptEnvelope` (v1.1) is unaffected — `receipt_expired`
> below is still fatal there.

_v1.1 (`verifyReceiptEnvelope`) — additional codes_

| Code                               | Condition                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------- |
| `jwks_history_signature_invalid`   | JWKS history JWS malformed, wrong alg, or root SHA not in embedded trust anchor |
| `receipt_expired`                  | `expires_at < now - toleranceSeconds` (v1.1 envelope path)                      |
| `receipt_not_yet_valid`            | `issued_at > now + toleranceSeconds` (v1.1 envelope path)                       |
| `missing_required_consent_context` | `receipt_subject = "buyer_agent"` but `consent_context` absent                  |
| `receipt_subject_mismatch`         | `expectedSubject` option provided but `receipt_subject` in envelope differs     |

Non-fatal warnings emitted by `verifyReceiptEnvelope`:

| Warning                                            | Meaning                                                                            |
| -------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `jwks_history_signature_unverifiable_staging_root` | Unknown root SHA but `allowStagingRoots: true` was set (structural parse only)     |
| `unknown_trust_provider_present`                   | A `trust_provider_assertions[].provider` value is not in the known set             |
| `tsa_unavailable`                                  | RFC 3161 timestamp absent or unavailable; posture falls to `ades_candidate_no_tsa` |

---

## 4. Governance

**Spec versioning:**

- `1.x` patch releases (new optional fields, clarifying language, new conformance vectors): maintained by Trusteed with single-maintainer approval.
- `1.x` minor releases (new required fields, new `assertion_type` values, new protocol support): require at least 2 maintainer approvals and a 14-day comment period on the PR.
- `2.0` and major version changes: require named co-authors from at least 3 distinct categories: (1) a fraud or risk provider, (2) a payment network or PSP and (3) an agent platform provider. No major version is published without this multi-party authorship.

**Maintainers:**

Trusteed (trusteed.xyz) is the current sole maintainer of spec v1.x. Additional maintainers from partner organizations may be added following a co-authorship contribution (see §2).

**Backwards compatibility:**

Existing conformant verifiers must continue to pass all existing test vectors after any `1.x` change. Adding fields to `test-vectors/valid/` payloads requires verifiers to handle unknown optional fields gracefully. The schema design enforces this by allowing additional optional fields.

---

## 5. Code of Conduct

This project follows the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

In short: be respectful, assume good faith and keep disagreements on the technical substance. Escalate concerns to the maintainers by opening a [GitHub issue](https://github.com/Trusteedxyz/Trust-Receipt-Verifier/issues). Maintainers may close issues or PRs that do not meet these standards.

---

## Development Setup

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test

# Run tests with coverage
pnpm test:coverage

# Type check
pnpm typecheck

# Build
pnpm build
```

All PRs must pass `pnpm test` (all 10 conformance vectors green), `pnpm typecheck`, and `pnpm lint` before review.
