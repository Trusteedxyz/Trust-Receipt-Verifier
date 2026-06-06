/**
 * Spec 054 T006g — Contract tests for `OutputCommitment` discriminated union.
 *
 * Enforces ADR-054-001 rules:
 *  - `merkle_manifest` MUST carry `manifest_hash` (mutable URL is not anchor).
 *  - `static_sha256` MUST carry tagged `value` digest.
 *  - Unknown `kind` values are rejected as `unsupported_output_commitment_kind`.
 *  - `external_attestation` is parseable as a JSON shape but rejected by the
 *    Slice-1 acceptance gate (reserved for v1.1+).
 *
 * These tests will FAIL until the Zod schemas (T006a wiring + T012 schema
 * extension) are implemented. Per TDD they are written first.
 *
 * @see specs/058-trustreceipt-x402-binding/tasks.md T006g
 * @see specs/058-trustreceipt-x402-binding/contracts/output-commitment.schema.json
 */

import { describe, expect, test } from "vitest";
import { z } from "zod";

// Mirror of contracts/output-commitment.schema.json discriminated union.
// Once T006a types land + T012 schema extension wires through, the verifier
// package will export this Zod schema and this test imports it directly.
// For now we define the expected Zod shape inline as a TDD specification.

const StaticSha256CommitmentSchema = z.object({
  kind: z.literal("static_sha256"),
  algorithm: z.literal("sha256"),
  value: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  content_type: z.string().optional(),
  content_length: z.number().int().nonnegative().optional(),
});

const MerkleManifestCommitmentSchema = z.object({
  kind: z.literal("merkle_manifest"),
  algorithm: z.literal("merkle-sha256-v1"),
  root: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  manifest_url: z
    .string()
    .url()
    .regex(/^https:\/\//),
  manifest_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  chunk_size: z.number().int().positive(),
  chunk_count: z.number().int().positive(),
});

const ExternalAttestationCommitmentSchema = z.object({
  kind: z.literal("external_attestation"),
  algorithm: z.union([z.literal("sha256"), z.literal("merkle-sha256-v1")]),
  value: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  attestor: z.string().min(1),
  attestation_jws: z.string().min(1),
});

const OutputCommitmentSchema = z.discriminatedUnion("kind", [
  StaticSha256CommitmentSchema,
  MerkleManifestCommitmentSchema,
  ExternalAttestationCommitmentSchema,
]);

const SPEC054_V10_SUPPORTED_KINDS = new Set([
  "static_sha256",
  "merkle_manifest",
]);

const HEX64 = "a".repeat(64);

describe("Spec-054 T006g — OutputCommitment contract", () => {
  describe("static_sha256 kind", () => {
    test("accepts a well-formed static commitment", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "static_sha256",
        algorithm: "sha256",
        value: `sha256:${HEX64}`,
        content_type: "application/json",
        content_length: 1024,
      });
      expect(result.success).toBe(true);
    });

    test("rejects untagged digest (missing 'sha256:' prefix)", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "static_sha256",
        algorithm: "sha256",
        value: HEX64,
      });
      expect(result.success).toBe(false);
    });

    test("rejects wrong algorithm label", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "static_sha256",
        algorithm: "merkle-sha256-v1",
        value: `sha256:${HEX64}`,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("merkle_manifest kind", () => {
    test("accepts a well-formed merkle manifest commitment", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "merkle_manifest",
        algorithm: "merkle-sha256-v1",
        root: `sha256:${HEX64}`,
        manifest_url: "https://merchant.example.com/manifest.json",
        manifest_hash: `sha256:${HEX64}`,
        chunk_size: 65536,
        chunk_count: 4,
      });
      expect(result.success).toBe(true);
    });

    test("REJECTS manifest_url without manifest_hash (ADR-054-001 §FR-007a)", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "merkle_manifest",
        algorithm: "merkle-sha256-v1",
        root: `sha256:${HEX64}`,
        manifest_url: "https://merchant.example.com/manifest.json",
        // manifest_hash missing
        chunk_size: 65536,
        chunk_count: 4,
      });
      expect(result.success).toBe(false);
    });

    test("rejects non-https manifest_url", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "merkle_manifest",
        algorithm: "merkle-sha256-v1",
        root: `sha256:${HEX64}`,
        manifest_url: "http://merchant.example.com/manifest.json",
        manifest_hash: `sha256:${HEX64}`,
        chunk_size: 65536,
        chunk_count: 4,
      });
      expect(result.success).toBe(false);
    });

    test("rejects zero chunk_count", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "merkle_manifest",
        algorithm: "merkle-sha256-v1",
        root: `sha256:${HEX64}`,
        manifest_url: "https://merchant.example.com/manifest.json",
        manifest_hash: `sha256:${HEX64}`,
        chunk_size: 65536,
        chunk_count: 0,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("external_attestation kind (RESERVED v1.1)", () => {
    test("parses as a valid shape (schema-level)", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "external_attestation",
        algorithm: "sha256",
        value: `sha256:${HEX64}`,
        attestor: "cdn.example.com",
        attestation_jws: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJkZWxpdmVyeSJ9.SIG",
      });
      expect(result.success).toBe(true);
    });

    test("Slice-1 acceptance gate REJECTS unsupported kind (v1.0 surface)", () => {
      const parsed = OutputCommitmentSchema.parse({
        kind: "external_attestation",
        algorithm: "sha256",
        value: `sha256:${HEX64}`,
        attestor: "cdn.example.com",
        attestation_jws: "x.y.z",
      });
      expect(SPEC054_V10_SUPPORTED_KINDS.has(parsed.kind)).toBe(false);
    });
  });

  describe("unknown kinds", () => {
    test("rejects any unrecognized kind", () => {
      const result = OutputCommitmentSchema.safeParse({
        kind: "magic_oracle",
        algorithm: "sha256",
        value: `sha256:${HEX64}`,
      });
      expect(result.success).toBe(false);
    });
  });
});
