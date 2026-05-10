/**
 * Deterministic seeded byte generator for v1.1 conformance vectors (T065).
 *
 * Uses an HKDF-Expand-style construction over SHA-256: emits a stream of bytes
 * by hashing `seed || counter || label` with a 32-bit big-endian counter. Same
 * seed + label → byte-identical output across runs and platforms (Node ≥18).
 *
 * NOT cryptographically secure — these are TEST vectors only.
 */
import { createHash } from "node:crypto";

export interface SeededStream {
  /** Pull `n` bytes from the stream. */
  bytes(n: number): Buffer;
  /** Spawn an independent sub-stream with the same seed but a different label. */
  derive(label: string): SeededStream;
}

export function createSeededStream(
  seed: Uint8Array,
  label: string
): SeededStream {
  let counter = 0;
  return {
    bytes(n: number): Buffer {
      const out = Buffer.alloc(n);
      let written = 0;
      while (written < n) {
        const ctrBuf = Buffer.alloc(4);
        ctrBuf.writeUInt32BE(counter++, 0);
        const block = createHash("sha256")
          .update(Buffer.from(seed))
          .update(Buffer.from(label, "utf8"))
          .update(ctrBuf)
          .digest();
        const take = Math.min(block.length, n - written);
        block.copy(out, written, 0, take);
        written += take;
      }
      return out;
    },
    derive(subLabel: string): SeededStream {
      return createSeededStream(seed, `${label}/${subLabel}`);
    },
  };
}

/** Master test seed — 32 bytes of `T065` repeated. NEVER change in-place. */
export const MASTER_SEED: Uint8Array = (() => {
  const out = new Uint8Array(32);
  const tag = Buffer.from("T065-spec049-v1.1-vectors", "utf8");
  for (let i = 0; i < out.length; i++) out[i] = tag[i % tag.length];
  return out;
})();
