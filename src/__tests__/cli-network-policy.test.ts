/**
 * CLI-level network policy.
 *
 *  1. `trust-receipt verify` must NEVER take a key location from the receipt
 *     under verification. With no --jwks-* option it refuses (exit 2) and
 *     contacts nobody; the declared URL is printed only as information.
 *  2. `verify-bundle --manifest` reads are bounded.
 *
 * These spawn the real CLI entry points through tsx against a local server.
 */
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import AdmZip from "adm-zip";

import { issueTrustReceipt } from "../issuer.js";

const PKG = resolve(import.meta.dirname, "..", "..");
const TSX = join(PKG, "node_modules", ".bin", "tsx");
const KID = "attacker-key-1";

let server: Server;
let base: string;
let hits: string[] = [];
let tmp: string;
let jwksBody: string;
let receiptFile: string;
let jwksFile: string;

function run(
  script: string,
  args: string[],
  timeoutMs = 20000
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = spawn(TSX, [join(PKG, script), ...args], { cwd: PKG });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += String(d)));
    child.stderr.on("data", (d) => (stderr += String(d)));
    const killer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("close", (code) => {
      clearTimeout(killer);
      done({ code, stdout, stderr });
    });
  });
}

beforeAll(async () => {
  server = createServer((req, res) => {
    hits.push(req.url ?? "");
    if (req.url === "/.well-known/jwks.json") {
      res.setHeader("content-type", "application/json");
      res.end(jwksBody);
    } else if (req.url === "/manifest-forever") {
      res.write("a.b");
      const t = setInterval(() => {
        if (res.destroyed) return clearInterval(t);
        res.write(Buffer.alloc(64 * 1024, 0x41));
      }, 1);
      res.on("close", () => clearInterval(t));
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  // A receipt FORGED by whoever runs the server: signed with their own key,
  // and pointing verification_methods at their own JWKS.
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const publicJwk = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };
  jwksBody = JSON.stringify({ keys: [publicJwk] });
  const jws = await issueTrustReceipt({
    payload: {
      issuer: "trusteed.xyz",
      merchant_id: "merchant-001",
      agent_id: "agent-claude-001",
      agent_provider: "anthropic",
      user_intent_hash: "a".repeat(64),
      protocol: "MCP",
      protocol_artifacts: [{ type: "mcp_tool_call", hash: "b".repeat(64) }],
      policy_decision: "allow",
      verification_methods: [
        { type: "jwks", value: `${base}/.well-known/jwks.json` },
      ],
    },
    privateKeyJwk: await exportJWK(privateKey),
    kid: KID,
    validitySeconds: 3600,
  });
  tmp = await mkdtemp(join(tmpdir(), "trv-cli-"));
  receiptFile = join(tmp, "receipt.jws");
  jwksFile = join(tmp, "jwks.json");
  await writeFile(receiptFile, jws);
  await writeFile(jwksFile, jwksBody);
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

describe("trust-receipt verify: key source must be explicit", () => {
  it("refuses to guess the JWKS from the receipt and contacts NOBODY", async () => {
    hits = [];
    const r = await run("bin/trust-receipt.ts", ["verify", receiptFile]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("--jwks-file");
    expect(r.stderr).toContain("--jwks-url");
    // The declared location is shown as information only.
    expect(r.stderr).toContain(`${base}/.well-known/jwks.json`);
    expect(r.stdout).not.toContain('"valid": true');
    expect(hits).toHaveLength(0);
  }, 30000);

  it("still verifies when the caller supplies --jwks-file (no network)", async () => {
    hits = [];
    const r = await run("bin/trust-receipt.ts", [
      "verify",
      receiptFile,
      "--jwks-file",
      jwksFile,
    ]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('"valid": true');
    expect(hits).toHaveLength(0);
  }, 30000);

  it("still fetches when the caller explicitly passes --jwks-url", async () => {
    hits = [];
    const r = await run("bin/trust-receipt.ts", [
      "verify",
      receiptFile,
      "--jwks-url",
      `${base}/.well-known/jwks.json`,
    ]);
    expect(r.code).toBe(0);
    expect(hits).toEqual(["/.well-known/jwks.json"]);
  }, 30000);

  it("--help documents that the JWKS source is mandatory", async () => {
    const r = await run("bin/trust-receipt.ts", ["--help"]);
    expect(r.stdout).toMatch(/never fetches keys from a URL/);
  }, 30000);
});

describe("verify-bundle --manifest is bounded", () => {
  it("gives up on a manifest that streams forever and reports a warning", async () => {
    const zip = new AdmZip();
    zip.addFile("receipt-envelope.json", Buffer.from("{}"));
    const zipFile = join(tmp, "b.zip");
    await writeFile(zipFile, zip.toBuffer());
    const started = Date.now();
    const r = await run("bin/verify-bundle.ts", [
      zipFile,
      "--trust-anchor-sha256",
      "a".repeat(64),
      "--manifest",
      `${base}/manifest-forever`,
    ]);
    expect(r.stderr).toContain("manifest fetch incomplete");
    expect(r.stderr).toMatch(/manifest_fetch_failed/);
    expect(Date.now() - started).toBeLessThan(15000);
  }, 30000);
});
