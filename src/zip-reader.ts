/**
 * Small, strict, read-only ZIP reader.
 *
 * Replaces a general-purpose ZIP library for the one place the verifier
 * unpacks untrusted archives (export bundles). It supports exactly what a
 * bundle needs and rejects everything else with a typed error:
 *
 *   - single-disk archives, no ZIP64, no encryption;
 *   - compression methods 0 (stored) and 8 (deflate) only.
 *
 * Every offset and length read from the archive is bounds-checked against the
 * buffer before use, and no length is trusted as an allocation size: inflation
 * is capped at the declared size and the real size must equal it.
 *
 * Two steps, so the caller can apply its own limits between them:
 *   1. {@link readZipDirectory} parses and validates the structure (nothing is
 *      inflated);
 *   2. {@link extractZipEntry} inflates one entry and verifies its CRC-32.
 *
 * Both throw only {@link ZipReaderError}, for any input.
 */

import { inflateRawSync } from "node:zlib";

export type ZipErrorKind = "invalid" | "limits";

export class ZipReaderError extends Error {
  readonly kind: ZipErrorKind;
  readonly code: string;
  constructor(kind: ZipErrorKind, code: string, detail: string) {
    super(`${code}: ${detail}`);
    this.name = "ZipReaderError";
    this.kind = kind;
    this.code = code;
  }
}

export interface ZipEntry {
  /** Entry name, strictly decoded from UTF-8. */
  readonly name: string;
  readonly isDirectory: boolean;
  /** 0 = stored, 8 = deflate. */
  readonly method: 0 | 8;
  readonly crc32: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  /** Offset of the first data byte, derived from the LOCAL header. */
  readonly dataStart: number;
}

const SIG_EOCD = 0x06054b50;
const SIG_EOCD64_LOCATOR = 0x07064b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const EOCD_SIZE = 22;
const CENTRAL_SIZE = 46;
const LOCAL_SIZE = 30;
const MAX_COMMENT = 0xffff;

const invalid = (code: string, detail: string): ZipReaderError =>
  new ZipReaderError("invalid", code, detail);

// --- CRC-32 (IEEE) ---------------------------------------------------------

const CRC_TABLE: Uint32Array = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    c = (CRC_TABLE[(c ^ (data[i] as number)) & 0xff] as number) ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

// --- name handling -----------------------------------------------------------

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

function decodeName(bytes: Buffer): string {
  let name: string;
  try {
    name = STRICT_UTF8.decode(bytes);
  } catch {
    throw invalid("zip_name_encoding", "entry name is not valid UTF-8");
  }
  return name;
}

function assertSafeName(name: string): void {
  if (name.length === 0) throw invalid("zip_name_unsafe", "empty entry name");
  if (name.includes("\0")) throw invalid("zip_name_unsafe", "NUL in entry name");
  if (name.includes("\\"))
    throw invalid("zip_name_unsafe", "backslash in entry name");
  if (name.startsWith("/") || /^[A-Za-z]:/.test(name))
    throw invalid("zip_name_unsafe", "absolute entry name");
  if (name.split("/").some((seg) => seg === ".."))
    throw invalid("zip_name_unsafe", "'..' segment in entry name");
}

/** Normal form used to detect duplicate / confusable names. */
function nameKey(name: string): string {
  return name
    .normalize("NFC")
    .replace(/\\/g, "/")
    .toLowerCase()
    .replace(/\/+/g, "/")
    .replace(/^\.\//, "")
    .replace(/\/$/, "");
}

// --- directory ---------------------------------------------------------------

function findEocd(buf: Buffer): number {
  if (buf.length < EOCD_SIZE) throw invalid("zip_no_eocd", "buffer too small");
  const lowest = Math.max(0, buf.length - EOCD_SIZE - MAX_COMMENT);
  for (let pos = buf.length - EOCD_SIZE; pos >= lowest; pos--) {
    if (buf.readUInt32LE(pos) !== SIG_EOCD) continue;
    const commentLen = buf.readUInt16LE(pos + 20);
    // The comment must end exactly at the end of the buffer.
    if (pos + EOCD_SIZE + commentLen === buf.length) return pos;
  }
  throw invalid("zip_no_eocd", "end of central directory not found");
}

interface Range {
  start: number;
  end: number;
  what: string;
}

/**
 * Parses and validates the archive structure. Nothing is inflated.
 * `maxEntries` is checked before any per-entry structure is allocated.
 */
export function readZipDirectory(
  input: Uint8Array,
  opts: { maxEntries: number }
): ZipEntry[] {
  try {
    return parseDirectory(Buffer.from(input.buffer, input.byteOffset, input.byteLength), opts);
  } catch (err) {
    if (err instanceof ZipReaderError) throw err;
    throw invalid("zip_malformed", "archive could not be parsed");
  }
}

function parseDirectory(buf: Buffer, opts: { maxEntries: number }): ZipEntry[] {
  const eocd = findEocd(buf);

  // ZIP64 is not supported: refuse rather than misread.
  if (eocd >= 20 && buf.readUInt32LE(eocd - 20) === SIG_EOCD64_LOCATOR)
    throw invalid("zip_unsupported_zip64", "ZIP64 archives are not supported");
  if (eocd >= 4 && buf.readUInt32LE(eocd - 4) === SIG_EOCD64)
    throw invalid("zip_unsupported_zip64", "ZIP64 archives are not supported");

  const diskNo = buf.readUInt16LE(eocd + 4);
  const cdDisk = buf.readUInt16LE(eocd + 6);
  const entriesOnDisk = buf.readUInt16LE(eocd + 8);
  const total = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);

  if (
    entriesOnDisk === 0xffff ||
    total === 0xffff ||
    cdSize === 0xffffffff ||
    cdOffset === 0xffffffff
  )
    throw invalid("zip_unsupported_zip64", "ZIP64 sentinel in end record");
  if (diskNo !== 0 || cdDisk !== 0 || entriesOnDisk !== total)
    throw invalid("zip_multi_disk", "multi-disk archives are not supported");

  if (total > opts.maxEntries)
    throw new ZipReaderError(
      "limits",
      "zip_too_many_entries",
      `ZIP has ${total} entries, limit is ${opts.maxEntries}`
    );

  const cdEnd = cdOffset + cdSize;
  if (cdEnd > eocd)
    throw invalid("zip_bad_directory", "central directory outside the archive");
  if (total * CENTRAL_SIZE > cdSize)
    throw invalid("zip_bad_directory", "entry count inconsistent with directory size");

  const entries: ZipEntry[] = [];
  const ranges: Range[] = [{ start: cdOffset, end: cdEnd, what: "central directory" }];
  const exact = new Set<string>();
  const normal = new Set<string>();

  let p = cdOffset;
  for (let i = 0; i < total; i++) {
    if (p + CENTRAL_SIZE > cdEnd)
      throw invalid("zip_bad_directory", "truncated central directory record");
    if (buf.readUInt32LE(p) !== SIG_CENTRAL)
      throw invalid("zip_bad_directory", "bad central directory signature");
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28);
    const elen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const startDisk = buf.readUInt16LE(p + 34);
    const localOff = buf.readUInt32LE(p + 42);

    if (csize === 0xffffffff || usize === 0xffffffff || localOff === 0xffffffff || startDisk === 0xffff)
      throw invalid("zip_unsupported_zip64", "ZIP64 sentinel in entry");
    if (startDisk !== 0) throw invalid("zip_multi_disk", "entry on another disk");
    if (flags & 0x1) throw invalid("zip_encrypted", "encrypted entry");
    if (flags & (0x40 | 0x2000))
      throw invalid("zip_encrypted", "strong encryption / masked headers");
    if (method !== 0 && method !== 8)
      throw invalid("zip_unsupported_method", `compression method ${method}`);

    const recEnd = p + CENTRAL_SIZE + nlen + elen + clen;
    if (recEnd > cdEnd)
      throw invalid("zip_bad_directory", "central record overruns directory");
    const nameBytes = buf.subarray(p + CENTRAL_SIZE, p + CENTRAL_SIZE + nlen);
    const name = decodeName(nameBytes);
    assertSafeName(name);

    const key1 = name;
    const key2 = nameKey(name);
    if (exact.has(key1) || normal.has(key2))
      throw invalid("zip_duplicate_entry", `duplicate entry "${name}"`);
    exact.add(key1);
    normal.add(key2);

    // Local header: must agree with the central directory.
    if (localOff + LOCAL_SIZE > cdOffset)
      throw invalid("zip_bad_local_header", "local header outside the data area");
    if (buf.readUInt32LE(localOff) !== SIG_LOCAL)
      throw invalid("zip_bad_local_header", "bad local header signature");
    const lflags = buf.readUInt16LE(localOff + 6);
    const lmethod = buf.readUInt16LE(localOff + 8);
    const lnlen = buf.readUInt16LE(localOff + 26);
    const lelen = buf.readUInt16LE(localOff + 28);
    if (lflags & 0x1) throw invalid("zip_encrypted", "encrypted local header");
    if (lmethod !== method)
      throw invalid("zip_bad_local_header", "local/central method mismatch");
    const lnameStart = localOff + LOCAL_SIZE;
    const dataStart = lnameStart + lnlen + lelen;
    if (dataStart > cdOffset)
      throw invalid("zip_bad_local_header", "local header overruns the data area");
    if (lnlen !== nlen || !buf.subarray(lnameStart, lnameStart + lnlen).equals(nameBytes))
      throw invalid("zip_name_mismatch", `local header name differs for "${name}"`);

    const dataEnd = dataStart + csize;
    if (dataEnd > cdOffset)
      throw invalid("zip_bad_local_header", "entry data outside the data area");

    const isDirectory = name.endsWith("/");
    if (isDirectory && usize !== 0)
      throw invalid("zip_bad_directory", "directory entry with data");
    if (method === 0 && csize !== usize)
      throw invalid("zip_size_mismatch", `stored entry "${name}" sizes differ`);

    ranges.push({ start: localOff, end: dataEnd, what: `entry "${name}"` });
    entries.push({ name, isDirectory, method, crc32: crc, compressedSize: csize, uncompressedSize: usize, dataStart });
    p = recEnd;
  }
  if (p !== cdEnd)
    throw invalid("zip_bad_directory", "unexpected bytes after the last record");

  // Overlapping regions amplify bombs and enable confusion: reject.
  ranges.sort((a, b) => a.start - b.start || a.end - b.end);
  for (let i = 1; i < ranges.length; i++) {
    const prev = ranges[i - 1] as Range;
    const cur = ranges[i] as Range;
    if (cur.start < prev.end)
      throw invalid("zip_overlap", `${prev.what} overlaps ${cur.what}`);
  }
  return entries;
}

/**
 * Inflates one entry. `maxBytes` caps the declared (and thus the allocated)
 * size; the real inflated size must equal the declared one and the CRC-32 must
 * match. Directories yield an empty buffer.
 */
export function extractZipEntry(
  input: Uint8Array,
  entry: ZipEntry,
  maxBytes: number
): Buffer {
  try {
    const buf = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    if (entry.isDirectory) return Buffer.alloc(0);
    if (entry.uncompressedSize > maxBytes)
      throw new ZipReaderError(
        "limits",
        "zip_entry_too_large",
        `entry "${entry.name}" declares ${entry.uncompressedSize} bytes, limit is ${maxBytes}`
      );
    const end = entry.dataStart + entry.compressedSize;
    if (entry.dataStart > buf.length || end > buf.length)
      throw invalid("zip_bad_local_header", "entry data outside the archive");
    const raw = buf.subarray(entry.dataStart, end);
    let data: Buffer;
    if (entry.method === 0) {
      data = raw;
    } else {
      try {
        data = inflateRawSync(raw, {
          maxOutputLength: Math.max(entry.uncompressedSize, 1),
        });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ERR_BUFFER_TOO_LARGE")
          throw new ZipReaderError(
            "limits",
            "zip_inflate_overrun",
            `entry "${entry.name}" inflates beyond its declared size of ${entry.uncompressedSize} bytes`
          );
        throw invalid("zip_inflate_failed", `entry "${entry.name}" is not valid deflate data`);
      }
    }
    if (data.length !== entry.uncompressedSize)
      throw new ZipReaderError(
        "limits",
        "zip_size_mismatch",
        `entry "${entry.name}" inflated to ${data.length} bytes but declares ${entry.uncompressedSize}`
      );
    if (crc32(data) !== entry.crc32)
      throw invalid("zip_crc_mismatch", `CRC-32 mismatch for "${entry.name}"`);
    return data;
  } catch (err) {
    if (err instanceof ZipReaderError) throw err;
    throw invalid("zip_malformed", "entry could not be read");
  }
}
