# TrustReceipt Reference Verifier

The reference verifier is published as an npm package:

```bash
npm install @agenticmcpstores/trust-receipt-verifier
```

## Library usage

```typescript
import { verifyTrustReceipt } from "@agenticmcpstores/trust-receipt-verifier";

const result = await verifyTrustReceipt(jwsToken, {
  jwksUrl: "https://trusteed.xyz/.well-known/jwks.json",
});

if (result.valid) {
  console.log(result.receipt.policy_decision); // "allow"
} else {
  console.log(result.reason); // "expired" | "tampered_signature" | ...
}
```

## CLI usage

```bash
npx trust-receipt verify receipt.jws --jwks-url https://trusteed.xyz/.well-known/jwks.json
npx trust-receipt inspect receipt.jws
npx trust-receipt generate-key
```

## Conformance test

Clone this repo and run:

```bash
cd test-vectors
# See test-vectors/README.md for step-by-step instructions
```

## Porting to other languages

Follow the verification algorithm in [SPEC.md §4](../SPEC.md). Any implementation passing all 10 conformance vectors is conformant. Open a PR to add your port to the [Known Implementations](#) list.
