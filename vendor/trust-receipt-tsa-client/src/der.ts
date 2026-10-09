export interface DerNode {
  readonly tag: number;
  readonly start: number;
  readonly headerEnd: number;
  readonly valueStart: number;
  readonly end: number;
  readonly value: Uint8Array;
  readonly children: readonly DerNode[];
}

function readLength(
  bytes: Uint8Array,
  offset: number
): { length: number; next: number } {
  const first = bytes[offset];
  if (first === undefined) throw new Error("DER length missing");
  if ((first & 0x80) === 0) return { length: first, next: offset + 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 4) throw new Error("unsupported DER length");
  let length = 0;
  for (let i = 0; i < count; i++) {
    const b = bytes[offset + 1 + i];
    if (b === undefined) throw new Error("truncated DER length");
    length = (length << 8) | b;
  }
  return { length, next: offset + 1 + count };
}

export function parseDer(bytes: Uint8Array, offset = 0): DerNode {
  const tag = bytes[offset];
  if (tag === undefined) throw new Error("DER tag missing");
  const len = readLength(bytes, offset + 1);
  const valueStart = len.next;
  const end = valueStart + len.length;
  if (end > bytes.length) throw new Error("truncated DER value");
  const value = bytes.slice(valueStart, end);
  const children: DerNode[] = [];
  if ((tag & 0x20) !== 0) {
    let childOffset = valueStart;
    while (childOffset < end) {
      const child = parseDer(bytes, childOffset);
      children.push(child);
      childOffset = child.end;
    }
  }
  return {
    tag,
    start: offset,
    headerEnd: valueStart,
    valueStart,
    end,
    value,
    children,
  };
}

export function parseAllDer(bytes: Uint8Array): DerNode {
  const node = parseDer(bytes, 0);
  if (node.end !== bytes.length) throw new Error("trailing DER bytes");
  return node;
}

export function derLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length);
  if (length < 0x100) return Uint8Array.of(0x81, length);
  if (length < 0x10000) return Uint8Array.of(0x82, length >> 8, length & 0xff);
  if (length < 0x1000000) {
    return Uint8Array.of(
      0x83,
      length >> 16,
      (length >> 8) & 0xff,
      length & 0xff
    );
  }
  throw new Error("DER length too large");
}

export function tlv(tag: number, body: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(tag), derLength(body.length), body);
}

export function sequence(...children: Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(...children));
}

export function integer(bytesOrNumber: Uint8Array | number): Uint8Array {
  const raw =
    typeof bytesOrNumber === "number"
      ? numberToBytes(bytesOrNumber)
      : bytesOrNumber.length === 0
        ? Uint8Array.of(0)
        : bytesOrNumber;
  const body = (raw[0] ?? 0) & 0x80 ? concat(Uint8Array.of(0), raw) : raw;
  return tlv(0x02, body);
}

export function objectIdentifier(oid: string): Uint8Array {
  const parts = oid.split(".").map((part) => Number.parseInt(part, 10));
  if (
    parts.length < 2 ||
    parts.some((part) => !Number.isInteger(part) || part < 0)
  ) {
    throw new Error(`invalid OID: ${oid}`);
  }
  const out = [(parts[0] ?? 0) * 40 + (parts[1] ?? 0)];
  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let value = Math.floor(part / 0x80);
    while (value > 0) {
      stack.push((value & 0x7f) | 0x80);
      value = Math.floor(value / 0x80);
    }
    out.push(...stack.reverse());
  }
  return tlv(0x06, Uint8Array.from(out));
}

export function nullValue(): Uint8Array {
  return Uint8Array.of(0x05, 0x00);
}

export function octetString(bytes: Uint8Array): Uint8Array {
  return tlv(0x04, bytes);
}

export function booleanValue(value: boolean): Uint8Array {
  return tlv(0x01, Uint8Array.of(value ? 0xff : 0x00));
}

export function decodeOid(node: DerNode): string {
  if (node.tag !== 0x06) throw new Error("node is not an OID");
  const bytes = node.value;
  const first = bytes[0];
  if (first === undefined) throw new Error("empty OID");
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (const b of bytes.slice(1)) {
    value = (value << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

export function integerToHex(node: DerNode): string {
  if (node.tag !== 0x02) throw new Error("node is not an INTEGER");
  const value = node.value[0] === 0 ? node.value.slice(1) : node.value;
  return toHex(value);
}

export function integerToNumber(node: DerNode): number {
  const hex = integerToHex(node);
  return hex.length === 0 ? 0 : Number.parseInt(hex, 16);
}

export function generalizedTimeToUnix(node: DerNode): number {
  if (node.tag !== 0x18) throw new Error("node is not GeneralizedTime");
  const text = new TextDecoder().decode(node.value);
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (!match) throw new Error(`unsupported GeneralizedTime: ${text}`);
  const [, y, mo, d, h, mi, s] = match;
  return Math.floor(
    Date.UTC(
      Number(y),
      Number(mo) - 1,
      Number(d),
      Number(h),
      Number(mi),
      Number(s)
    ) / 1000
  );
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function numberToBytes(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0)
    throw new Error("INTEGER must be non-negative");
  if (value === 0) return Uint8Array.of(0);
  const out: number[] = [];
  let cursor = value;
  while (cursor > 0) {
    out.unshift(cursor & 0xff);
    cursor = Math.floor(cursor / 256);
  }
  return Uint8Array.from(out);
}

export function derBytes(source: Uint8Array, node: DerNode): Uint8Array {
  return source.slice(node.start, node.end);
}
