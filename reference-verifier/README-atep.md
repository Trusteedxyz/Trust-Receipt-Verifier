# ATEP Passport Reference Verifier (zero-dependency)

A **standalone** verifier for an ATEP passport (spec-062 SC-001). It proves the
ATEP thesis: **you can verify a merchant's portable trust attestation offline,
without contacting Trusteed and without trusting any Trusteed code.**

- **Zero external dependencies.** Uses only Node.js built-ins: `node:crypto`,
  `node:fs`, `node:url`. No `jose`, no monorepo-internal packages, no npm install.
- **Fully offline.** No network access. You need only the passport and the
  issuer's score public keys (JWKS).
- **Single file.** `verify-atep-passport.mjs`: copy it anywhere Node 18+ runs.

## Run it

```bash
node verify-atep-passport.mjs <passport.json> <jwks.json>
```

- `passport.json`: a fully-signed ATEP passport (the body fields + `issuer_sig`,
  with a nested `provenance` carrying the underlying `session_sig`).
- `jwks.json`: the issuer public keys, either a bare JWK array
  `[ { kid, kty:"OKP", crv:"Ed25519", x } ]` or a JWKS document `{ "keys": [ ... ] }`.
  Both the `issuer_sig.kid` and `provenance.kid` must resolve against it (they
  may be the same key or two distinct keys).

Prints the verdict as JSON to stdout and sets the exit code:

```json
{ "valid": true }
```

Exit `0` when valid, `1` when invalid, `2` on a usage/IO error.

You can also import the pure function:

```js
import { verifyAtepPassport } from "./verify-atep-passport.mjs";
const result = verifyAtepPassport(passport, jwks); // { valid, reason? }
```

## What it checks

The verifier reproduces, verdict-for-verdict, the internal `verifyAtepPassport`
(Trusteed's issuer-side implementation, not part of this package). A passport carries **two
independent EdDSA anchors**, checked in this exact order:

1. **`issuer_sig`**: a JWS Compact the issuer computes over the WHOLE canonical
   (JCS/RFC 8785) passport body (everything except `issuer_sig`). This attests
   the issuer-computed aggregates (`execution_count` / `success_rate` / `badges`)
   that are not present in the snapshot.
   - no `issuer_sig` / non-3-segment jws → `missing_issuer_sig`
   - no JWKS key matches `issuer_sig.kid` → `unknown_issuer_kid`
   - signature does not verify → `issuer_signature_invalid`
   - signed body ≠ `canonical(body)` → `issuer_projection_mismatch`
2. **`provenance.session_sig`**: the underlying signed StoreScoreSnapshot's own
   EdDSA JWS.
   - not a 3-segment JWS → `malformed_session_sig`
   - no JWKS key matches `provenance.kid` → `unknown_kid`
   - signature does not verify → `signature_invalid`
3. **Faithfulness**: the snapshot-attested subset (tier, score, cap,
   breakdown, …) re-projects EXACTLY from the signed snapshot body, so a tampered
   tier/score is caught even with a valid issuer signature.
   - subset diverges → `projection_mismatch`

Returns `{ valid: true }` iff all three pass. Same result object as the internal
verifier: `{ valid: boolean, reason?: string }`.

Defense-in-depth intuition: tampering any body field with a **stale**
`issuer_sig` is caught at check A (`issuer_projection_mismatch`); re-signing a
tampered body still fails check C (`projection_mismatch`) because the snapshot's
own signature independently attests the score/tier subset.

## What it does NOT prove

Scope limit recorded after the 2026-07-26 architecture audit (§F2). A passing
verdict means the passport is **internally consistent and issuer-signed**. It
does not mean the aggregates are independently reproducible:

- `execution_count`, `success_rate` and `badges` are **issuer-attested**, not
  recomputable out-of-band. Recomputation would require an append-only,
  hash-linked receipt corpus readable by the auditor; **neither exists today**:
  no issuer writes `hash_chain_prev` onto a TrustReceipt (zero write sites in
  the repository), and the corpus is not externally readable.
- The RFC 8785 prev-hash chain that IS productive in this codebase covers the
  OAuth audit log and the enforcement event log, **not** trust receipts.

So the honest claim is: _"the issuer signed these numbers and the passport has
not been tampered with"_, never _"any auditor can recompute these numbers"_.

## How zero-dependency EdDSA works

Ed25519 verification with only `node:crypto`:

- `crypto.createPublicKey({ key: jwk, format: "jwk" })` imports the OKP /
  Ed25519 public JWK: no `jose.importJWK`.
- `crypto.verify(null, signingInput, publicKey, signature)` verifies the raw
  64-byte Ed25519 signature (`null` algorithm = EdDSA), no `jose.compactVerify`.
- The JWS signing input is `ASCII("<header>.<payload>")` per RFC 7515; the
  verified payload is the base64url-decoded payload segment (what
  `jose.compactVerify(...).payload` returns).

## A note on canonicalization (RFC 8785 / JCS)

**Unlike the AIVS reference verifier**, which hashes the exact base64url-decoded
payload **bytes** and never re-canonicalizes: the ATEP `issuer_sig` signs over
the **JCS-canonicalized body**. So checks A and C must re-canonicalize JSON
byte-for-byte identically to Trusteed's internal `canonicalizeJSON`
(issuer-side, not part of this package), which the internal verifier
uses. This file therefore embeds a **verbatim** copy of that RFC 8785 JCS
implementation (object keys sorted by Unicode code point, no whitespace, numbers
via `JSON.stringify`). Any divergence would break parity on checks A and C.
