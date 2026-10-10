/**
 * Every remote read of an untrusted document (JWKS for receipts, JWKS for
 * extension artifacts, JWKS for the x402 audit CLI) must be bounded: a host
 * that streams forever or answers with a huge body must not exhaust the
 * verifier. The server below never stops sending; the call must give up
 * quickly, and the server must have been cut off well below the volume an
 * unbounded read would have pulled.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { verifyTrustReceipt } from "../verifier.js";
import { verifyExtensionArtifact } from "../verify-extension-artifact.js";
import { runCli } from "../cli/audit-command.js";

const MIB = 1024 * 1024;

let server: Server;
let base: string;
let bytesSent = 0;

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.url === "/jwks-forever") {
      res.setHeader("content-type", "application/json");
      res.write('{"keys":[');
      const timer = setInterval(() => {
        if (res.destroyed) return clearInterval(timer);
        const chunk = Buffer.alloc(64 * 1024, 0x20);
        bytesSent += chunk.length;
        res.write(chunk);
      }, 1);
      res.on("close", () => clearInterval(timer));
    } else if (req.url === "/jwks-declared-huge") {
      res.setHeader("content-length", String(100 * MIB));
      res.setHeader("content-type", "application/json");
      res.write('{"keys":[');
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = `${b64({ alg: "EdDSA", kid: "k1" })}.${b64({ a: 1 })}.c2ln`;

describe("remote JWKS reads are bounded", () => {
  it("verifyTrustReceipt: a JWKS that streams forever is cut off", async () => {
    bytesSent = 0;
    const started = Date.now();
    const r = await verifyTrustReceipt(fakeJws, {
      jwksUrl: `${base}/jwks-forever`,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toBe("jwks_fetch_failed");
    expect(Date.now() - started).toBeLessThan(3000);
    expect(bytesSent).toBeLessThan(8 * MIB);
  });

  it("verifyTrustReceipt: a declared-huge JWKS is refused", async () => {
    const started = Date.now();
    const r = await verifyTrustReceipt(fakeJws, {
      jwksUrl: `${base}/jwks-declared-huge`,
    });
    expect(r.valid).toBe(false);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("verifyTrustReceipt: refuses non-http(s) JWKS URLs", async () => {
    const r = await verifyTrustReceipt(fakeJws, {
      jwksUrl: "file:///etc/passwd",
    });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toBe("jwks_fetch_failed");
  });

  it("verifyExtensionArtifact: a JWKS that streams forever is cut off", async () => {
    bytesSent = 0;
    const started = Date.now();
    const r = await verifyExtensionArtifact(fakeJws, {
      kind: "erasure",
      jwksUrl: `${base}/jwks-forever`,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toBe("jwks_unreachable");
    expect(Date.now() - started).toBeLessThan(3000);
    expect(bytesSent).toBeLessThan(8 * MIB);
  });

  it("audit-command: a JWKS that streams forever is cut off", async () => {
    bytesSent = 0;
    const dir = await mkdtemp(join(tmpdir(), "trv-audit-"));
    const envelope = join(dir, "envelope.json");
    await writeFile(envelope, "{}");
    const started = Date.now();
    const r = await runCli([
      "--envelope",
      envelope,
      "--jwks-url",
      `${base}/jwks-forever`,
    ]);
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("failed to load JWKS");
    expect(Date.now() - started).toBeLessThan(3000);
    expect(bytesSent).toBeLessThan(8 * MIB);
  });
});
