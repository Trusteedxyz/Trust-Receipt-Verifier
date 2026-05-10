/**
 * TrustReceipt Demo Receipt Generator
 *
 * Generates three signed demo receipts covering MCAP, x402, and MCP protocols.
 * Uses a freshly generated Ed25519 keypair — the matching public JWKS is written
 * alongside the receipts so the demo verifier can run offline.
 *
 * Usage:
 *   npx tsx demo/generate-demo-receipts.ts
 */

import { generateKeyPair, exportJWK, CompactSign } from "jose";
import { createHash, randomUUID } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { TrustReceiptPayload } from "../src/schema/trust-receipt.schema.js";

const DEMO_DIR = new URL("./receipts/", import.meta.url).pathname;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  mkdirSync(DEMO_DIR, { recursive: true });

  const now = Math.floor(Date.now() / 1000);
  const kid = `tr-ed25519-demo-${new Date().toISOString().slice(0, 10)}`;

  // Generate a fresh Ed25519 keypair — private key stays in memory only
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
  });
  const publicJwk = await exportJWK(publicKey);

  async function signReceipt(payload: TrustReceiptPayload): Promise<string> {
    const encoder = new TextEncoder();
    return new CompactSign(encoder.encode(JSON.stringify(payload)))
      .setProtectedHeader({ alg: "EdDSA", kid })
      .sign(privateKey);
  }

  // ─── Receipt 1: MCAP (Mastercard Agent Pay) ──────────────────────────────

  const mcapReceipt: TrustReceiptPayload = {
    receipt_id: randomUUID(),
    schema_version: "1.0",
    issued_at: now,
    expires_at: now + 3600,
    issuer: "trusteed.xyz",
    merchant_id: "merchant-demo-shop-001",
    agent_id: `agent-claude-opus-4-7-${randomUUID().slice(0, 8)}`,
    agent_provider: "anthropic",
    user_intent_hash: sha256("I want to buy the blue sneakers size 42"),
    cart_hash: sha256("cart:item-sneakers-blue-42:qty-1"),
    order_hash: sha256("order:demo-001:total-79.99:EUR"),
    transaction_id: `mcap-${now}-demo`,
    protocol: "MCAP",
    protocol_artifacts: [
      {
        type: "mcap_consent_hash",
        hash: sha256("consent:merchant-demo:agent-claude:scope-purchase"),
      },
      {
        type: "mcap_nonce",
        hash: sha256(`nonce:${now}`),
      },
    ],
    payment_reference: { psp: "mastercard", ref: `MC-DEMO-${now}` },
    risk_signals: [
      {
        signal_type: "velocity_check",
        value: "normal",
        source: "clearsale",
      },
    ],
    trust_provider_assertions: [
      {
        provider: "clearsale",
        assertion_type: "fraud_score",
        score: 0.95,
        ts: now - 5,
        confidence: "high",
      },
    ],
    policy_decision: "allow",
    liability_context: {
      assertor: "trusteed.xyz",
      scope: "commerce_transaction",
    },
    privacy_classification: {
      contains_pii: false,
      retention_days: 365,
      jurisdiction: "EU",
    },
    verification_methods: [
      {
        type: "jwks",
        value: "https://trusteed.xyz/.well-known/jwks.json",
      },
    ],
    kid,
    attachments: [],
  };

  // ─── Receipt 2: x402 (crypto payment) ────────────────────────────────────

  const x402Receipt: TrustReceiptPayload = {
    receipt_id: randomUUID(),
    schema_version: "1.0",
    issued_at: now,
    expires_at: now + 3600,
    issuer: "trusteed.xyz",
    merchant_id: "merchant-demo-shop-001",
    agent_id: `agent-gpt-4o-${randomUUID().slice(0, 8)}`,
    agent_provider: "openai",
    user_intent_hash: sha256("Purchase API credits for 10 USDC"),
    transaction_id: `x402-${now}-demo`,
    protocol: "x402",
    protocol_artifacts: [
      {
        type: "permit2_hash",
        hash: sha256(`permit2:${now}:10000000:USDC`),
      },
      {
        type: "settlement_hash",
        hash: sha256(`settled:${now}`),
      },
    ],
    payment_reference: { psp: "x402_upto", ref: `X402-DEMO-${now}` },
    risk_signals: [
      {
        signal_type: "fraud_score",
        value: 0.02,
        source: "stripe_radar",
      },
    ],
    trust_provider_assertions: [
      {
        provider: "stripe",
        assertion_type: "payment_trust",
        score: 0.98,
        ts: now - 3,
        confidence: "high",
      },
    ],
    policy_decision: "allow",
    privacy_classification: { contains_pii: false },
    verification_methods: [
      {
        type: "jwks",
        value: "https://trusteed.xyz/.well-known/jwks.json",
      },
    ],
    kid,
    attachments: [],
  };

  // ─── Receipt 3: MCP (standard AI agent call) ─────────────────────────────

  const mcpReceipt: TrustReceiptPayload = {
    receipt_id: randomUUID(),
    schema_version: "1.0",
    issued_at: now,
    expires_at: now + 3600,
    issuer: "trusteed.xyz",
    merchant_id: "merchant-demo-shop-001",
    agent_id: `agent-gemini-2.0-${randomUUID().slice(0, 8)}`,
    agent_provider: "google",
    user_intent_hash: sha256("Check availability of product SKU-12345"),
    protocol: "MCP",
    protocol_artifacts: [
      {
        type: "mcp_call_hash",
        hash: sha256(`mcp:get_product:SKU-12345:${now}`),
      },
    ],
    risk_signals: [],
    trust_provider_assertions: [],
    policy_decision: "allow",
    privacy_classification: { contains_pii: false },
    verification_methods: [
      {
        type: "jwks",
        value: "https://trusteed.xyz/.well-known/jwks.json",
      },
    ],
    kid,
    attachments: [],
  };

  // ─── Sign all three in parallel ──────────────────────────────────────────

  const [mcapJws, x402Jws, mcpJws] = await Promise.all([
    signReceipt(mcapReceipt),
    signReceipt(x402Receipt),
    signReceipt(mcpReceipt),
  ]);

  // ─── Write output files ───────────────────────────────────────────────────

  writeFileSync(join(DEMO_DIR, "demo-receipt-mcap.jws"), mcapJws);
  writeFileSync(join(DEMO_DIR, "demo-receipt-x402.jws"), x402Jws);
  writeFileSync(join(DEMO_DIR, "demo-receipt-mcp.jws"), mcpJws);

  const jwks = {
    keys: [{ ...publicJwk, kid, use: "sig", alg: "EdDSA" }],
  };
  writeFileSync(join(DEMO_DIR, "jwks.json"), JSON.stringify(jwks, null, 2));

  process.stdout.write(`
TrustReceipt Demo Receipts Generated
=====================================
Output: ${DEMO_DIR}

Files:
  demo-receipt-mcap.jws  — MCAP protocol (Mastercard Agent Pay)
  demo-receipt-x402.jws  — x402 protocol (crypto payment)
  demo-receipt-mcp.jws   — MCP protocol (standard AI agent call)
  jwks.json              — Public verification keys

Verify with:
  npx trust-receipt verify demo/receipts/demo-receipt-mcap.jws --jwks-file demo/receipts/jwks.json
`);
}

main().catch((err: unknown) => {
  process.stderr.write(String(err) + "\n");
  process.exit(1);
});
