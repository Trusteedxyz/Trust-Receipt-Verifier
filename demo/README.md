# TrustReceipt Demo Receipts

This demo shows TrustReceipt working across three protocols.

> ⚠️ **The committed `.jws` files under `receipts/` are almost certainly
> expired.** They are generated with a **one-hour** lifetime
> (`expires_at = issued_at + 3600`) and then committed as-is, so verifying them
> returns `{ valid: false, reason: "expired" }` at any point after that hour.
> That is the demo working correctly — expiry is checked before anything else
> useful can be said about a receipt. Regenerate before demoing, and read a
> failed verification of a stale file as a clock check, not a signature problem.

## Generate demo receipts

Regenerating rewrites all three receipts **and** `receipts/jwks.json` with a
freshly minted keypair, so always regenerate the set together — a new receipt
will not verify against the old `jwks.json`:

```bash
npx tsx demo/generate-demo-receipts.ts
```

## Verify a receipt

```bash
npx trust-receipt verify demo/receipts/demo-receipt-mcap.jws \
  --jwks-file demo/receipts/jwks.json
```

## Receipt protocols demonstrated

| File                  | Protocol                    | Agent Provider   | Decision |
| --------------------- | --------------------------- | ---------------- | -------- |
| demo-receipt-mcap.jws | MCAP (Mastercard Agent Pay) | Anthropic Claude | allow    |
| demo-receipt-x402.jws | x402 (crypto payment)       | OpenAI GPT-4o    | allow    |
| demo-receipt-mcp.jws  | MCP (AI agent query)        | Google Gemini    | allow    |

## About TrustReceipt

TrustReceipt is an open standard for cross-protocol agentic commerce evidence receipts.
Each receipt is a JWS-signed JSON document containing:

- Who the AI agent was (provider, ID)
- What the user intended (intent hash)
- What protocol was used (x402/AP2/ACP/MCP/UCP/MCAP)
- Trust assertions from fraud/risk providers
- Policy decision (allow/deny/review/challenge)

Receipts are verifiable offline against the JWKS published at the issuer domain.
