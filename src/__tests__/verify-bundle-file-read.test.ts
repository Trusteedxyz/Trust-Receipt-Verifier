/**
 * How `verify-bundle` reads the ZIP from disk: one open handle, size checked on
 * that handle, never a stat-then-read by path.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const PKG = resolve(import.meta.dirname, "..", "..");
const TSX = join(PKG, "node_modules", ".bin", "tsx");
const MAX_BUNDLE_FILE_BYTES = 16 * 1024 * 1024;

let tmp: string;

function runCli(
  args: string[]
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = spawn(TSX, [join(PKG, "bin/verify-bundle.ts"), ...args], { cwd: PKG });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += String(d)));
    child.stderr.on("data", (d) => (stderr += String(d)));
    const killer = setTimeout(() => child.kill("SIGKILL"), 20000);
    child.on("close", (code) => {
      clearTimeout(killer);
      done({ code, stdout, stderr });
    });
  });
}

beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "vb-file-read-"));
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("verify-bundle reading the ZIP from disk", () => {
  it("refuses a file one byte over the size ceiling without loading it", async () => {
    const big = join(tmp, "big.zip");
    writeFileSync(big, "");
    truncateSync(big, MAX_BUNDLE_FILE_BYTES + 1); // sparse: no disk used
    const r = await runCli([big]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("limit is");
  });

  it("reports a missing file with a clear message and exit code 2", async () => {
    const r = await runCli([join(tmp, "does-not-exist.zip")]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("cannot read ZIP");
  });

  it("reports a directory instead of a file with exit code 2", async () => {
    const r = await runCli([tmp]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("not a regular file");
  });

  it("still hands a normal-sized file to the verifier (rejected as not a ZIP, not as unreadable)", async () => {
    const f = join(tmp, "not-a-zip.zip");
    writeFileSync(f, "this is not a zip archive");
    const r = await runCli([f, "--json"]);
    expect(r.stdout).toContain("bundle_zip_invalid");
  });
});
