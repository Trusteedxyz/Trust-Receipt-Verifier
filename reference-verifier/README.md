# AIVS Reference Verifier (zero-dependency)

A **standalone** verifier for an AIVS proof bundle (spec-062 SC-001). It proves
the AIVS thesis: **you can verify a Trusteed AIVS proof bundle offline, without
contacting Trusteed and without trusting any Trusteed code.**

- **Zero external dependencies.** Uses only Node.js built-ins: `node:crypto`,
  `node:fs`, `node:url`. No `jose`, no `@agenticmcpstores/*`, no npm install.
- **Fully offline.** No network access. You need only the proof bundle and the
  issuer's public keys (JWKS).
- **Single file.** `verify-aivs-bundle.mjs` — copy it anywhere Node 18+ runs.

## Run it

```bash
node verify-aivs-bundle.mjs <bundle.json> <jwks.json>
```

- `bundle.json` — an AIVS proof bundle: `{ manifest_hash, session_sig, kid, alg, audit_log }`.
- `jwks.json` — the issuer public keys, either a bare JWK array `[ { kid, kty:"OKP", crv:"Ed25519", x } ]`
  or a JWKS document `{ "keys": [ ... ] }`.

Prints the verdict as JSON to stdout and sets the exit code:

```json
{ "valid": true }
```

Exit `0` when valid, `1` when invalid, `2` on a usage/IO error.

You can also import the pure function:

```js
import { verifyAivsBundle } from "./verify-aivs-bundle.mjs";
const result = verifyAivsBundle(bundle, jwks); // { valid, reason? }
```

## What it checks

The verifier reproduces, verdict-for-verdict, the internal
`verifyAivsProofBundle` (`src/aivs-export.ts`):

1. **`manifest_hash`** — recomputed as `sha256:<hex>` of the **exact signed
   payload bytes** recovered from the JWS (the base64url-decoded payload
   segment). Mismatch → `manifest_hash_mismatch`.
2. **`session_sig`** — the existing EdDSA (Ed25519) JWS Compact signature is
   verified against the issuer key resolved by `kid` from the JWKS:
   - not a 3-segment JWS → `malformed_session_sig`
   - no key matches `kid` → `unknown_kid`
   - signature does not verify → `signature_invalid`

Same result object as the internal verifier: `{ valid: boolean, reason?: string }`
with exactly those four failure reasons.

## How zero-dependency EdDSA works

Ed25519 verification with only `node:crypto`:

- `crypto.createPublicKey({ key: jwk, format: "jwk" })` imports the OKP /
  Ed25519 public JWK — no `jose.importJWK`.
- `crypto.verify(null, signingInput, publicKey, signature)` verifies the raw
  64-byte Ed25519 signature (`null` algorithm = EdDSA) — no `jose.compactVerify`.
- The JWS signing input is `ASCII("<header>.<payload>")` per RFC 7515.

## A note on canonicalization (RFC 8785 / JCS)

The `manifest_hash` is the SHA-256 of the **raw signed payload bytes**, not of a
re-canonicalized JSON object. This is deliberate and stronger: the bytes that
were signed are already the canonical, immutable form, so **no JCS
canonicalization is required to verify the bundle.** Re-canonicalizing could
diverge from the exact signed bytes and is therefore avoided. (If a future AIVS
profile hashes a canonicalized envelope instead of the signed payload segment,
any RFC 8785-conformant JCS implementation may be substituted for that step.)
