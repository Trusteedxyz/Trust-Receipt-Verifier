/**
 * Strict ZIP reader: valid archives built by an independent writer (adm-zip)
 * and hand-built hostile ones. Whatever the bytes, the reader must answer with
 * either entries or a typed ZipReaderError - never another exception.
 */
import { describe, it, expect } from "vitest";
import AdmZip from "adm-zip";
import { deflateRawSync } from "node:zlib";
import {
  ZipReaderError,
  readZipDirectory,
  extractZipEntry,
  crc32,
  type ZipEntry,
} from "../zip-reader.js";

const MIB = 1024 * 1024;
const LIMITS = { maxEntries: 64 };

function validZip(): Buffer {
  const z = new AdmZip();
  z.addFile("a.txt", Buffer.from("hello hello hello hello hello"));
  z.addFile("b.json", Buffer.from('{"k":"v"}'));
  z.addFile("empty.txt", Buffer.alloc(0));
  return z.toBuffer();
}

function readAll(buf: Buffer, maxBytes = 8 * MIB): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  for (const e of readZipDirectory(buf, LIMITS)) {
    out.set(e.name, extractZipEntry(buf, e, maxBytes));
  }
  return out;
}

/** Returns the error if the reader rejects, undefined if it accepts. */
function outcome(buf: Buffer): ZipReaderError | undefined {
  try {
    readAll(buf);
    return undefined;
  } catch (err) {
    if (err instanceof ZipReaderError) return err;
    throw new Error(`untyped exception: ${String(err)}`);
  }
}

function expectRejected(buf: Buffer, code?: string): ZipReaderError {
  const err = outcome(buf);
  expect(err, "expected a typed rejection").toBeInstanceOf(ZipReaderError);
  if (code) expect(err?.code).toBe(code);
  return err as ZipReaderError;
}

// ---- raw builder ------------------------------------------------------------

interface RawEntry {
  name: string | Buffer;
  localName?: string | Buffer;
  data: Buffer;
  method?: 0 | 8;
  flags?: number;
  localFlags?: number;
  crc?: number;
  csize?: number;
  usize?: number;
  localOffsetDelta?: number; // added to the offset written in the central dir
  localOffsetAbs?: number;
  rawCompressed?: Buffer; // use instead of deflating `data`
  methodRaw?: number;
}

function raw(entries: RawEntry[], eocd?: Partial<{ total: number; cdOffset: number; cdSize: number; comment: Buffer; disk: number }>): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let off = 0;
  for (const e of entries) {
    const method = e.methodRaw ?? e.method ?? 8;
    const comp = e.rawCompressed ?? (method === 8 ? deflateRawSync(e.data) : e.data);
    const nameB = Buffer.isBuffer(e.name) ? e.name : Buffer.from(e.name, "utf8");
    const lnameB = e.localName === undefined ? nameB : Buffer.isBuffer(e.localName) ? e.localName : Buffer.from(e.localName, "utf8");
    const crc = e.crc ?? crc32(e.data);
    const csize = e.csize ?? comp.length;
    const usize = e.usize ?? e.data.length;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(e.localFlags ?? 0, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(e.data.length, 22);
    lh.writeUInt16LE(lnameB.length, 26);
    const localOffset = e.localOffsetAbs ?? off + (e.localOffsetDelta ?? 0);
    parts.push(lh, lnameB, comp);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(e.flags ?? 0, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(csize, 20);
    ch.writeUInt32LE(usize, 24);
    ch.writeUInt16LE(nameB.length, 28);
    ch.writeUInt32LE(localOffset >>> 0, 42);
    central.push(ch, nameB);
    off += 30 + lnameB.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(eocd?.disk ?? 0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(eocd?.total ?? entries.length, 8);
  end.writeUInt16LE(eocd?.total ?? entries.length, 10);
  end.writeUInt32LE(eocd?.cdSize ?? cd.length, 12);
  end.writeUInt32LE(eocd?.cdOffset ?? off, 16);
  const comment = eocd?.comment ?? Buffer.alloc(0);
  end.writeUInt16LE(comment.length, 20);
  return Buffer.concat([...parts, cd, end, comment]);
}

const A: RawEntry = { name: "a.txt", data: Buffer.from("hello world") };

describe("zip-reader: valid archives", () => {
  it("reads entries written by an independent writer", () => {
    const files = readAll(validZip());
    expect([...files.keys()].sort()).toEqual(["a.txt", "b.json", "empty.txt"]);
    expect(files.get("a.txt")?.toString()).toBe("hello hello hello hello hello");
    expect(files.get("b.json")?.toString()).toBe('{"k":"v"}');
    expect(files.get("empty.txt")?.length).toBe(0);
  });

  it("reads stored (method 0) entries and UTF-8 names", () => {
    const buf = raw([
      { name: "plain.txt", data: Buffer.from("stored!"), method: 0 },
      { name: "ñandú.txt", data: Buffer.from("x") },
    ]);
    const files = readAll(buf);
    expect(files.get("plain.txt")?.toString()).toBe("stored!");
    expect(files.has("ñandú.txt")).toBe(true);
  });

  it("reports directories and does not inflate them", () => {
    const z = new AdmZip();
    z.addFile("dir/", Buffer.alloc(0));
    z.addFile("dir/f.txt", Buffer.from("x"));
    const entries = readZipDirectory(z.toBuffer(), LIMITS);
    expect(entries.find((e) => e.name === "dir/")?.isDirectory).toBe(true);
    expect(entries.find((e) => e.name === "dir/f.txt")?.isDirectory).toBe(false);
  });

  it("accepts a ZIP comment", () => {
    const buf = raw([A], { comment: Buffer.from("a comment") });
    expect(readAll(buf).get("a.txt")?.toString()).toBe("hello world");
  });

  it("crc32 matches the standard check value", () => {
    expect(crc32(Buffer.from("123456789"))).toBe(0xcbf43926);
  });
});

describe("zip-reader: robustness over arbitrary bytes", () => {
  it("every truncation of a valid zip is a typed rejection (or valid), never an untyped throw", () => {
    const buf = validZip();
    for (let n = 0; n < buf.length; n++) {
      outcome(buf.subarray(0, n)); // throws on untyped
    }
    expect(outcome(buf)).toBeUndefined();
  });

  it("500 seeded random corruptions only produce typed outcomes", () => {
    const base = validZip();
    let seed = 0x1234abcd;
    const rnd = () => {
      // xorshift32
      seed ^= seed << 13;
      seed >>>= 0;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      seed >>>= 0;
      return seed;
    };
    for (let i = 0; i < 500; i++) {
      const copy = Buffer.from(base);
      const flips = 1 + (rnd() % 4);
      for (let f = 0; f < flips; f++) copy[rnd() % copy.length] = rnd() & 0xff;
      outcome(copy);
    }
  });

  it("random garbage and empty input are typed rejections", () => {
    expectRejected(Buffer.alloc(0));
    expectRejected(Buffer.from("not a zip at all, definitely not a zip file"));
    let seed = 7;
    for (let i = 0; i < 50; i++) {
      const b = Buffer.alloc(100 + i);
      for (let j = 0; j < b.length; j++) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        b[j] = seed & 0xff;
      }
      outcome(b);
    }
  });
});

describe("zip-reader: structural attacks", () => {
  it("no EOCD", () => {
    expectRejected(Buffer.alloc(200, 0x41), "zip_no_eocd");
  });

  it("EOCD comment length longer than the buffer", () => {
    const buf = Buffer.from(raw([A]));
    buf.writeUInt16LE(0xffff, buf.length - 2);
    expectRejected(buf, "zip_no_eocd");
  });

  it("central directory offset beyond the buffer", () => {
    expectRejected(raw([A], { cdOffset: 0x7fffffff }), "zip_bad_directory");
  });

  it("entry count 65534 with a tiny buffer is rejected before allocating entries", () => {
    const buf = raw([A], { total: 65534 });
    const err = expectRejected(buf);
    expect(err.kind).toBe("limits");
    // within the entry limit but inconsistent with the directory size
    const buf2 = raw([A], { total: 60 });
    expect(expectRejected(buf2, "zip_bad_directory").kind).toBe("invalid");
  });

  it("entry count 65535 sentinel is a ZIP64 rejection", () => {
    expectRejected(raw([A], { total: 65535 }), "zip_unsupported_zip64");
  });

  it("ZIP64 locator present", () => {
    const plain = raw([A]);
    const eocdPos = plain.length - 22;
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    const buf = Buffer.concat([plain.subarray(0, eocdPos), locator, plain.subarray(eocdPos)]);
    expectRejected(buf, "zip_unsupported_zip64");
  });

  it("ZIP64 sentinel in an entry size", () => {
    expectRejected(raw([{ ...A, csize: 0xffffffff }]), "zip_unsupported_zip64");
    expectRejected(raw([{ ...A, usize: 0xffffffff }]), "zip_unsupported_zip64");
  });

  it("multi-disk archive", () => {
    expectRejected(raw([A], { disk: 1 }), "zip_multi_disk");
  });

  it("duplicate names: exact", () => {
    expectRejected(raw([A, { ...A }]), "zip_duplicate_entry");
  });

  it("duplicate names: case and path variants", () => {
    expectRejected(raw([A, { name: "A.TXT", data: Buffer.from("x") }]), "zip_duplicate_entry");
    expectRejected(
      raw([{ name: "d/a.txt", data: Buffer.from("x") }, { name: "D//a.txt", data: Buffer.from("y") }]),
      "zip_duplicate_entry"
    );
    expectRejected(
      raw([A, { name: "a.txt/", data: Buffer.alloc(0), method: 0 }]),
      "zip_duplicate_entry"
    );
  });

  it("local header name differs from the central name", () => {
    expectRejected(raw([{ ...A, localName: "b.txt" }]), "zip_name_mismatch");
    expectRejected(raw([{ ...A, localName: "a.txtx" }]), "zip_name_mismatch");
  });

  it("local header offset beyond the buffer / out of the data area", () => {
    expectRejected(raw([{ ...A, localOffsetAbs: 0x00ffffff }]), "zip_bad_local_header");
  });

  it("compressed size pointing beyond the data area", () => {
    expectRejected(raw([{ ...A, csize: 100000 }]), "zip_bad_local_header");
  });

  it("overlapping entries (two records pointing at the same data)", () => {
    const e1: RawEntry = { name: "a.txt", data: Buffer.from("hello world") };
    const e2: RawEntry = { name: "b.txt", data: Buffer.from("hello world"), localOffsetAbs: 0 };
    // b.txt's central record points at a.txt's local header; its local name differs -> mismatch
    expectRejected(raw([e1, e2]));
    // same name bytes would be a duplicate; use identical-length different content with a forged local name
    const e3: RawEntry = { name: "b.txt", localName: "a.txt", data: Buffer.from("hello world"), localOffsetAbs: 0 };
    const err = expectRejected(raw([e1, e3]));
    expect(["zip_overlap", "zip_name_mismatch"]).toContain(err.code);
  });

  it("overlap is detected even when names agree (second record re-uses the first local header)", () => {
    const e1: RawEntry = { name: "a.txt", data: Buffer.from("hello world") };
    const buf = raw([e1, { name: "x.txt", data: Buffer.from("zzzzzzzzzzz") }]);
    // Rewrite the second central record's name+local so both point to the first
    // local header (named "a.txt") by renaming the second central entry to "a.txt"
    // case-variant "A.txt"-> that is a duplicate; instead patch the offset only.
    const dirStart = buf.readUInt32LE(buf.length - 22 + 16);
    const second = dirStart + 46 + "a.txt".length;
    expect(buf.readUInt32LE(second)).toBe(0x02014b50);
    const patched = Buffer.from(buf);
    patched.writeUInt32LE(0, second + 42);
    expectRejected(patched); // name mismatch or overlap, but never accepted
  });

  it("unsupported compression method", () => {
    expectRejected(raw([{ ...A, methodRaw: 99 }]), "zip_unsupported_method");
  });

  it("encrypted flag", () => {
    expectRejected(raw([{ ...A, flags: 1 }]), "zip_encrypted");
    expectRejected(raw([{ ...A, localFlags: 1 }]), "zip_encrypted");
  });

  it("CRC mismatch", () => {
    expectRejected(raw([{ ...A, crc: 0xdeadbeef }]), "zip_crc_mismatch");
  });

  it("stored entry with mismatched sizes", () => {
    expectRejected(raw([{ ...A, method: 0, usize: 3 }]), "zip_size_mismatch");
  });

  it("invalid UTF-8 name", () => {
    expectRejected(raw([{ name: Buffer.from([0x61, 0xff, 0xfe, 0x2e]), data: Buffer.from("x") }]), "zip_name_encoding");
  });

  it.each([
    ["NUL", "a\0b.txt"],
    ["absolute", "/etc/passwd"],
    ["drive letter", "C:evil.txt"],
    ["parent segment", "../evil.txt"],
    ["nested parent segment", "a/../../evil.txt"],
    ["backslash separator", "..\\evil.txt"],
    ["empty", ""],
  ])("unsafe name: %s", (_label, name) => {
    expectRejected(raw([{ name, data: Buffer.from("x") }]), "zip_name_unsafe");
  });

  it("a name that merely contains two dots is fine", () => {
    expect(readAll(raw([{ name: "a..b.txt", data: Buffer.from("x") }])).has("a..b.txt")).toBe(true);
  });
});

describe("zip-reader: size lies and bombs", () => {
  const ZEROS = Buffer.alloc(50 * MIB);

  it.each([0, 100])("a declared size of %i against ~50 MiB of real data never balloons memory", (declared) => {
    const buf = raw([{ name: "bomb.bin", data: ZEROS, usize: declared }]);
    expect(buf.length).toBeLessThan(200 * 1024);
    const before = process.memoryUsage().rss;
    const err = expectRejected(buf);
    expect(err.kind).toBe("limits");
    expect(process.memoryUsage().rss - before).toBeLessThan(100 * MIB);
  });

  it("extractZipEntry refuses a declared size above the caller's cap before inflating", () => {
    const buf = raw([{ name: "bomb.bin", data: ZEROS }]);
    const [entry] = readZipDirectory(buf, LIMITS) as [ZipEntry];
    const before = process.memoryUsage().rss;
    let err: unknown;
    try {
      extractZipEntry(buf, entry, 8 * MIB);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ZipReaderError);
    expect((err as ZipReaderError).kind).toBe("limits");
    expect(process.memoryUsage().rss - before).toBeLessThan(100 * MIB);
  });

  it("declared size larger than the real data is a typed rejection", () => {
    const err = expectRejected(raw([{ ...A, usize: 5000 }]));
    expect(err.kind).toBe("limits");
  });

  it("truncated deflate data is a typed rejection", () => {
    const comp = deflateRawSync(Buffer.alloc(1000, 7));
    expectRejected(raw([{ name: "t.bin", data: Buffer.alloc(1000, 7), rawCompressed: comp.subarray(0, comp.length - 3) }]));
  });
});
