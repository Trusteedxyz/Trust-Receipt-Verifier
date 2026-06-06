#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$PKG_DIR/dist-spec"

echo "Preparing TrustReceipt public repo → $OUT_DIR"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/schema" "$OUT_DIR/test-vectors/valid" "$OUT_DIR/test-vectors/invalid" "$OUT_DIR/verifier" "$OUT_DIR/docs"

# Core docs
cp "$PKG_DIR/SPEC.md" "$OUT_DIR/"
cp "$PKG_DIR/README.md" "$OUT_DIR/"
cp "$PKG_DIR/CONTRIBUTING.md" "$OUT_DIR/"
cp "$PKG_DIR/LICENSE" "$OUT_DIR/"
cp "$PKG_DIR/TRADEMARKS.md" "$OUT_DIR/"

# Architecture doc
cp "$PKG_DIR/docs/architecture.md" "$OUT_DIR/docs/"

# Schema
cp "$PKG_DIR/schema/trust-receipt-v1.schema.json" "$OUT_DIR/schema/"

# Conformance test vectors
cp "$PKG_DIR/test-vectors/vectors.json" "$OUT_DIR/test-vectors/"
cp "$PKG_DIR/test-vectors/README.md" "$OUT_DIR/test-vectors/"
cp "$PKG_DIR/test-vectors/valid/"*.json "$OUT_DIR/test-vectors/valid/"
cp "$PKG_DIR/test-vectors/invalid/"*.json "$OUT_DIR/test-vectors/invalid/"

# Verifier reference
cat > "$OUT_DIR/verifier/README.md" << 'EOF'
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

# Run full end-to-end conformance suite (signs + verifies all 10 vectors)
npx trust-receipt conformance
```

## Conformance test

Clone this repo and run:

```bash
cd test-vectors
# See test-vectors/README.md for step-by-step instructions
```

## Porting to other languages

Follow the verification algorithm in [SPEC.md §4](../SPEC.md). Any implementation passing all 10 conformance vectors is conformant. Open a PR to add your port to the [Known Implementations](#) list.
EOF

echo ""
echo "dist-spec/ assembled:"
find "$OUT_DIR" -type f | sort
echo ""
echo "Ready to push to github.com/trust-receipt/spec"
echo "  cd dist-spec && git init && git remote add origin git@github.com:trust-receipt/spec.git"
echo "  git add . && git commit -m 'feat: TrustReceipt v1.0 initial draft'"
echo "  git push -u origin main"
