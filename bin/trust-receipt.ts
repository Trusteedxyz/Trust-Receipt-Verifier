#!/usr/bin/env node
/**
 * trust-receipt CLI
 *
 * Commands:
 *   verify <file>        Verify a .jws file
 *     --jwks-url <url>   JWKS URL (default: from receipt's verification_methods)
 *     --jwks-file <path> Local JWKS JSON file
 *   inspect <file>       Decode without verifying (show receipt fields)
 *   generate-key         Generate an Ed25519 keypair in JWK format
 *   conformance          Run all 10 conformance test vectors end-to-end
 *   --help               Show help
 *   --version            Show version
 *
 * Exit codes: 0 = valid/success, 1 = invalid, 2 = error
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, exportJWK, CompactSign, importJWK } from "jose";
import {
  verifyTrustReceipt,
  parseTrustReceiptUnsafe,
} from "../src/verifier.js";
import type { PublicJwk, VerifyFailureReason } from "../src/verifier.js";
import {
  verifyExtensionArtifact,
  type ExtensionArtifactKind,
} from "../src/verify-extension-artifact.js";
import { verifyJwksHistorySignature } from "../src/verify-jwks-history.js";
import { getActiveIssuerRoot } from "../src/embedded-issuer-root.js";
import type { SignedJwksHistory } from "../src/types-1.1.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

// ─── Version ──────────────────────────────────────────────────────────────────

const VERSION = "0.1.0";

// ─── Output helpers (no console.log per coding-style rules) ──────────────────

function print(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj, null, 2) + "\n");
}

function printError(message: string): void {
  process.stderr.write(`[trust-receipt] Error: ${message}\n`);
}

function help(): void {
  process.stdout.write(
    [
      `trust-receipt v${VERSION}`,
      "",
      "Usage:",
      "  trust-receipt verify <file> [--type <kind>] [--jwks-url <url>] [--jwks-file <path>]",
      "  trust-receipt inspect <file>",
      "  trust-receipt generate-key",
      "  trust-receipt conformance",
      "  trust-receipt --help",
      "  trust-receipt --version",
      "",
      "Commands:",
      "  verify       Verify a signed artifact. Exit 0 = valid, 1 = invalid.",
      "  inspect      Decode JWS without verifying (inspection only).",
      "  generate-key Generate Ed25519 keypair in JWK format.",
      "  conformance  Run all 10 conformance test vectors end-to-end.",
      "",
      "Options for verify:",
      "  --type <kind>       auto (default) | receipt | erasure | manifest | jwks-history",
      "                      Bundle (.zip) verification is deferred to v1.2.",
      "  --jwks-url <url>    Remote JWKS URL (used by receipt | erasure | manifest)",
      "  --jwks-file <path>  Path to local JWKS JSON file",
      "",
      "Notes:",
      "  - `receipt` validates Trusteed trust receipts (v1.0 JWS or v1.1 envelope).",
      "  - `erasure` validates Trusteed extension erasure receipts (Ed25519 JWS, developer-signed).",
      "  - `manifest` validates Trusteed extension manifests (Ed25519 JWS, shape gate only).",
      "  - `jwks-history` validates Trusteed jwks-history.jws against the embedded issuer root.",
      "",
    ].join("\n")
  );
}

// ─── Arg parser ───────────────────────────────────────────────────────────────

type VerifyType = "auto" | "receipt" | "erasure" | "manifest" | "jwks-history";

interface ParsedArgs {
  command: string | null;
  file: string | null;
  jwksUrl: string | null;
  jwksFile: string | null;
  verifyType: VerifyType;
  showHelp: boolean;
  showVersion: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2); // strip node + script path
  const result: ParsedArgs = {
    command: null,
    file: null,
    jwksUrl: null,
    jwksFile: null,
    verifyType: "auto",
    showHelp: false,
    showVersion: false,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    if (arg === "--help" || arg === "-h") {
      result.showHelp = true;
    } else if (arg === "--version" || arg === "-v") {
      result.showVersion = true;
    } else if (arg === "--jwks-url" && args[i + 1]) {
      result.jwksUrl = args[i + 1] ?? null;
      i++;
    } else if (arg === "--jwks-file" && args[i + 1]) {
      result.jwksFile = args[i + 1] ?? null;
      i++;
    } else if (arg === "--type" && args[i + 1]) {
      const next = args[i + 1];
      if (
        next === "auto" ||
        next === "receipt" ||
        next === "erasure" ||
        next === "manifest" ||
        next === "jwks-history"
      ) {
        result.verifyType = next;
      }
      i++;
    } else if (!result.command) {
      result.command = arg ?? null;
    } else if (!result.file) {
      result.file = arg ?? null;
    }
    i++;
  }

  return result;
}

// ─── Autodetect ───────────────────────────────────────────────────────────────

function detectArtifactKind(blob: string): VerifyType {
  const trimmed = blob.trim();
  // JWKS history is a JSON object containing `jws_compact`.
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      if (typeof parsed.jws_compact === "string") return "jwks-history";
      if (
        typeof parsed.receipt === "string" &&
        typeof parsed.envelope_metadata === "object"
      ) {
        return "receipt"; // v1.1 envelope
      }
    } catch {
      /* fall through */
    }
    return "auto";
  }
  // Compact JWS — try to peek at the payload's `schema_version` / fields.
  const segments = trimmed.split(".");
  if (segments.length !== 3) return "auto";
  try {
    const payloadSeg = segments[1] ?? "";
    const padded = payloadSeg + "=".repeat((4 - (payloadSeg.length % 4)) % 4);
    const decoded = Buffer.from(
      padded.replace(/-/g, "+").replace(/_/g, "/"),
      "base64"
    ).toString("utf8");
    const obj = JSON.parse(decoded) as Record<string, unknown>;
    if (typeof obj.schema_version === "string") {
      // Manifests carry `scopes_requested` + `vendor`; receipts carry `protocol`.
      if ("scopes_requested" in obj && "vendor" in obj) return "manifest";
      if ("protocol" in obj && "issuer" in obj) return "receipt";
    }
    if ("install_id" in obj && "deleted_at" in obj) return "erasure";
    if ("protocol" in obj && "issuer" in obj) return "receipt";
  } catch {
    /* fall through */
  }
  return "auto";
}

// ─── Commands ─────────────────────────────────────────────────────────────────

function loadJwksFile(jwksFile: string): PublicJwk[] | null {
  try {
    const raw = readFileSync(jwksFile, "utf8");
    const parsed = JSON.parse(raw) as { keys?: PublicJwk[] };
    return parsed.keys ?? [];
  } catch {
    return null;
  }
}

async function cmdVerifyReceipt(
  jws: string,
  jwksUrl: string | null,
  jwksFile: string | null
): Promise<number> {
  let resolvedJwksUrl: string | undefined;
  let inlineJwks: PublicJwk[] | undefined;

  if (jwksFile) {
    const keys = loadJwksFile(jwksFile);
    if (!keys) {
      printError(`Cannot read JWKS file: ${jwksFile}`);
      return 2;
    }
    inlineJwks = keys;
  } else if (jwksUrl) {
    resolvedJwksUrl = jwksUrl;
  } else {
    const unsafe = await parseTrustReceiptUnsafe(jws);
    if (unsafe) {
      const jwksMethod = unsafe.verification_methods.find(
        (m) => m.type === "jwks"
      );
      if (jwksMethod) {
        resolvedJwksUrl = jwksMethod.value;
      }
    }
    if (!resolvedJwksUrl) {
      printError(
        "No JWKS source. Provide --jwks-url or --jwks-file, or embed verification_methods[type=jwks] in the receipt."
      );
      return 2;
    }
  }

  const result = await verifyTrustReceipt(jws, {
    jwksUrl: resolvedJwksUrl,
    jwks: inlineJwks,
  });
  print({ kind: "receipt", ...result });
  return result.valid ? 0 : 1;
}

async function cmdVerifyExtensionArtifact(
  jws: string,
  kind: ExtensionArtifactKind,
  jwksUrl: string | null,
  jwksFile: string | null
): Promise<number> {
  let inlineJwks: PublicJwk[] | undefined;
  let resolvedJwksUrl: string | undefined;

  if (jwksFile) {
    const keys = loadJwksFile(jwksFile);
    if (!keys) {
      printError(`Cannot read JWKS file: ${jwksFile}`);
      return 2;
    }
    inlineJwks = keys;
  } else if (jwksUrl) {
    resolvedJwksUrl = jwksUrl;
  } else {
    printError(
      `No JWKS source. Provide --jwks-url or --jwks-file for --type ${kind}.`
    );
    return 2;
  }

  const result = await verifyExtensionArtifact(jws, {
    kind,
    ...(inlineJwks ? { jwks: inlineJwks } : {}),
    ...(resolvedJwksUrl ? { jwksUrl: resolvedJwksUrl } : {}),
  });
  print(result);
  return result.valid ? 0 : 1;
}

async function cmdVerifyJwksHistory(blob: string): Promise<number> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(blob);
  } catch {
    print({
      valid: false,
      kind: "jwks-history",
      reason: "malformed_input",
      detail: "input is not valid JSON",
    });
    return 1;
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    typeof (parsed as Record<string, unknown>).jws_compact !== "string"
  ) {
    print({
      valid: false,
      kind: "jwks-history",
      reason: "malformed_input",
      detail: "missing jws_compact field",
    });
    return 1;
  }

  const root = getActiveIssuerRoot();
  const result = await verifyJwksHistorySignature(
    parsed as SignedJwksHistory,
    root
  );
  print({ kind: "jwks-history", ...result });
  return result.valid ? 0 : 1;
}

async function cmdVerify(
  file: string,
  verifyType: VerifyType,
  jwksUrl: string | null,
  jwksFile: string | null
): Promise<number> {
  let blob: string;
  try {
    blob = readFileSync(file, "utf8").trim();
  } catch {
    printError(`Cannot read file: ${file}`);
    return 2;
  }

  const effective: VerifyType =
    verifyType === "auto" ? detectArtifactKind(blob) : verifyType;

  if (effective === "auto") {
    printError(
      "Unable to autodetect artifact type. Pass --type receipt|erasure|manifest|jwks-history explicitly."
    );
    return 2;
  }

  switch (effective) {
    case "receipt":
      return cmdVerifyReceipt(blob, jwksUrl, jwksFile);
    case "erasure":
      return cmdVerifyExtensionArtifact(blob, "erasure", jwksUrl, jwksFile);
    case "manifest":
      return cmdVerifyExtensionArtifact(blob, "manifest", jwksUrl, jwksFile);
    case "jwks-history":
      return cmdVerifyJwksHistory(blob);
  }
}

async function cmdInspect(file: string): Promise<number> {
  let jws: string;
  try {
    jws = readFileSync(file, "utf8").trim();
  } catch {
    printError(`Cannot read file: ${file}`);
    return 2;
  }

  const receipt = await parseTrustReceiptUnsafe(jws);
  if (!receipt) {
    print({ error: "Malformed JWS or payload is not a valid TrustReceipt" });
    return 1;
  }

  print({ warning: "Signature NOT verified", receipt });
  return 0;
}

async function cmdConformance(): Promise<number> {
  const TEST_KID = "tr-ed25519-2026-04-29-demo";
  // __dirname is dist/bin/ when compiled; go up two levels to package root
  const PKG_DIR = join(__dirname, "..", "..");

  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const publicJwk = {
    ...(await exportJWK(publicKey)),
    kid: TEST_KID,
    alg: "EdDSA",
  };
  const privateJwkRaw = await exportJWK(privateKey);

  const { privateKey: wrongKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const wrongPrivateJwkRaw = await exportJWK(wrongKey);

  type VectorEntry = {
    id: string;
    file: string;
    expected: "valid" | "invalid";
    failure_code?: string;
  };

  const manifest = JSON.parse(
    readFileSync(join(PKG_DIR, "test-vectors/vectors.json"), "utf-8")
  ) as { vectors: VectorEntry[] };

  let passed = 0;
  let failed = 0;

  for (const v of manifest.vectors) {
    const rawPayload: unknown = JSON.parse(
      readFileSync(join(PKG_DIR, "test-vectors", v.file), "utf-8")
    );

    let jws: string;
    let expectedReason: VerifyFailureReason | undefined;

    if (v.id === "TC-008") {
      const wKey = await importJWK(wrongPrivateJwkRaw, "EdDSA");
      jws = await new CompactSign(
        new TextEncoder().encode(JSON.stringify(rawPayload))
      )
        .setProtectedHeader({ alg: "EdDSA", kid: "nonexistent-key-id-abc123" })
        .sign(wKey);
      expectedReason = "unknown_kid";
    } else {
      const payload =
        v.expected === "valid"
          ? {
              ...(rawPayload as Record<string, unknown>),
              issued_at: Math.floor(Date.now() / 1000),
              expires_at: Math.floor(Date.now() / 1000) + 3600,
            }
          : rawPayload;
      const pKey = await importJWK(privateJwkRaw, "EdDSA");
      jws = await new CompactSign(
        new TextEncoder().encode(JSON.stringify(payload))
      )
        .setProtectedHeader({ alg: "EdDSA", kid: TEST_KID })
        .sign(pKey);
      expectedReason =
        v.failure_code !== undefined
          ? (v.failure_code as VerifyFailureReason)
          : undefined;
    }

    const result = await verifyTrustReceipt(jws, {
      jwks: [publicJwk],
      clockToleranceSeconds: v.id === "TC-007" ? 0 : 30,
    });

    if (v.expected === "valid") {
      if (result.valid) {
        process.stdout.write(`✓ ${v.id} — valid\n`);
        passed++;
      } else {
        process.stderr.write(
          `✗ ${v.id} — expected valid, got ${result.reason}\n`
        );
        failed++;
      }
    } else {
      if (!result.valid && result.reason === expectedReason) {
        process.stdout.write(`✓ ${v.id} — invalid/${result.reason}\n`);
        passed++;
      } else {
        process.stderr.write(
          `✗ ${v.id} — want invalid/${expectedReason}, got valid=${String(result.valid)} reason=${result.reason}\n`
        );
        failed++;
      }
    }
  }

  process.stdout.write(
    `\n${passed}/${passed + failed} conformance vectors passed\n`
  );
  return failed > 0 ? 1 : 0;
}

async function cmdGenerateKey(): Promise<number> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });

  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);

  print({
    algorithm: "EdDSA",
    public_jwk: publicJwk,
    private_jwk: privateJwk,
    note: "Keep private_jwk secret. Publish public_jwk in your JWKS endpoint.",
  });
  return 0;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  if (args.showHelp || (!args.command && !args.showVersion)) {
    help();
    process.exit(0);
  }

  if (args.showVersion) {
    process.stdout.write(`trust-receipt v${VERSION}\n`);
    process.exit(0);
  }

  let exitCode = 0;

  switch (args.command) {
    case "verify": {
      if (!args.file) {
        printError("Missing file argument. Usage: trust-receipt verify <file>");
        process.exit(2);
      }
      exitCode = await cmdVerify(
        args.file,
        args.verifyType,
        args.jwksUrl,
        args.jwksFile
      );
      break;
    }
    case "inspect": {
      if (!args.file) {
        printError(
          "Missing file argument. Usage: trust-receipt inspect <file>"
        );
        process.exit(2);
      }
      exitCode = await cmdInspect(args.file);
      break;
    }
    case "generate-key": {
      exitCode = await cmdGenerateKey();
      break;
    }
    case "conformance": {
      exitCode = await cmdConformance();
      break;
    }
    default: {
      printError(`Unknown command: ${args.command ?? ""}. Run --help.`);
      process.exit(2);
    }
  }

  process.exit(exitCode);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  printError(msg);
  process.exit(2);
});
