/**
 * Synthetic RFC 3161 TimeStampToken builder for T065 vectors.
 *
 * Produces a deterministic, structurally-valid DER blob that round-trips
 * through ASN.1 parsers. We intentionally do NOT build a fully-validating
 * CMS SignedData here — the conformance test harness ships its own test
 * root and uses these vectors with `tsa_root_cert_sha256` PIN as the only
 * entry point for trust resolution.
 *
 * The TST contains:
 * - `TSTInfo` (SEQUENCE) with version, policy OID, MessageImprint
 *   (SHA-256 hash of `imprint`), serial, genTime, nonce, accuracy.
 * - A wrapping ContentInfo (`signedData` OID) shell tagging the TSTInfo.
 *
 * Self-signed cert: built as a **minimal** X.509-shaped DER with a
 * deterministic SubjectPublicKeyInfo for Ed25519 + a fake signature.
 * The PEM wrapping uses the `tsa_cert_chain` array as expected by the
 * envelope.
 */
import { createHash } from "node:crypto";

// ─── ASN.1 DER helpers ────────────────────────────────────────────────────────

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  if (len < 0x10000) return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
  if (len < 0x1000000)
    return Buffer.from([
      0x83,
      (len >> 16) & 0xff,
      (len >> 8) & 0xff,
      len & 0xff,
    ]);
  throw new Error("derLength: length too large for vectors");
}

function tlv(tag: number, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

function sequence(...children: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(children));
}

function integer(n: number): Buffer {
  if (n === 0) return tlv(0x02, Buffer.from([0x00]));
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  // Prepend 0x00 if high bit set (positive integer rule).
  if ((bytes[0] ?? 0) & 0x80) bytes.unshift(0x00);
  return tlv(0x02, Buffer.from(bytes));
}

function integerBytes(buf: Buffer): Buffer {
  const b = (buf[0] ?? 0) & 0x80 ? Buffer.concat([Buffer.from([0]), buf]) : buf;
  return tlv(0x02, b);
}

function octetString(buf: Buffer): Buffer {
  return tlv(0x04, buf);
}

function objectIdentifier(oid: string): Buffer {
  const parts = oid.split(".").map((p) => parseInt(p, 10));
  if (parts.length < 2) throw new Error(`bad OID: ${oid}`);
  const first = (parts[0] ?? 0) * 40 + (parts[1] ?? 0);
  const out: number[] = [first];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i] ?? 0;
    if (v < 0x80) {
      out.push(v);
      continue;
    }
    const stack: number[] = [];
    stack.push(v & 0x7f);
    v = Math.floor(v / 0x80);
    while (v > 0) {
      stack.push((v & 0x7f) | 0x80);
      v = Math.floor(v / 0x80);
    }
    while (stack.length > 0) out.push(stack.pop() as number);
  }
  return tlv(0x06, Buffer.from(out));
}

function generalizedTime(date: Date): Buffer {
  // YYYYMMDDHHMMSSZ
  const pad = (n: number, w: number): string => String(n).padStart(w, "0");
  const s =
    `${pad(date.getUTCFullYear(), 4)}${pad(date.getUTCMonth() + 1, 2)}` +
    `${pad(date.getUTCDate(), 2)}${pad(date.getUTCHours(), 2)}` +
    `${pad(date.getUTCMinutes(), 2)}${pad(date.getUTCSeconds(), 2)}Z`;
  return tlv(0x18, Buffer.from(s, "ascii"));
}

// ─── Synthetic cert (deterministic) ────────────────────────────────────────────

/**
 * Self-signed Ed25519-shaped cert (minimal). The structure is:
 *   SEQUENCE { tbs SEQUENCE { version, serial, sigAlg, issuer, validity,
 *              subject, spki }, sigAlg, signature BIT STRING }.
 * Subject/issuer use a single CN attribute. Validity 1970..2100.
 * Signature is a deterministic SHA-256 over the TBS bytes (NOT a real Ed25519
 * sig — these vectors do not require real cert-chain validation).
 */
export function buildSyntheticTsaCert(opts: {
  ed25519PubRaw: Buffer;
  cnLabel: string;
}): { derBuffer: Buffer; pem: string; sha256Hex: string } {
  const ED25519_OID = "1.3.101.112";
  const SHA256_WITH_ED25519_FAKE_OID = "1.3.101.112"; // reuse for shape only
  const CN_OID = "2.5.4.3";

  const sigAlg = sequence(objectIdentifier(ED25519_OID));

  // SubjectPublicKeyInfo
  const spki = sequence(
    sequence(objectIdentifier(ED25519_OID)),
    tlv(0x03, Buffer.concat([Buffer.from([0]), opts.ed25519PubRaw]))
  );

  // Name: SEQUENCE OF SET { SEQUENCE { OID(CN), UTF8String(label) } }
  const cn = sequence(
    tlv(
      0x31,
      sequence(
        objectIdentifier(CN_OID),
        tlv(0x0c, Buffer.from(opts.cnLabel, "utf8"))
      )
    )
  );

  const validity = sequence(
    generalizedTime(new Date(Date.UTC(1970, 0, 1, 0, 0, 0))),
    generalizedTime(new Date(Date.UTC(2100, 0, 1, 0, 0, 0)))
  );

  const tbs = sequence(
    tlv(0xa0, integer(2)), // [0] EXPLICIT version v3
    integer(1), // serial
    sigAlg,
    cn, // issuer
    validity,
    cn, // subject
    spki
  );

  const sig = createHash("sha256").update(tbs).digest();
  // Pad to 64 bytes (Ed25519 sig length) for shape.
  const sig64 = Buffer.concat([sig, sig]);

  const cert = sequence(
    tbs,
    sigAlg,
    tlv(0x03, Buffer.concat([Buffer.from([0]), sig64]))
  );

  const sha256Hex = createHash("sha256").update(cert).digest("hex");
  const pem = wrapPem(cert, "CERTIFICATE");
  return { derBuffer: cert, pem, sha256Hex };
  void SHA256_WITH_ED25519_FAKE_OID;
}

function wrapPem(der: Buffer, label: string): string {
  const b64 = der
    .toString("base64")
    .replace(/(.{64})/g, "$1\n")
    .trim();
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

// ─── TSTInfo + ContentInfo wrapper ─────────────────────────────────────────────

export interface SyntheticTstResult {
  tsr: string; // base64 of TimeStampResp
  tst: string; // base64 of TimeStampToken (ContentInfo)
  tsaRootSha256: string; // 64-hex
  tsaCertChain: string[]; // PEM array
  revocationEvidence: { kind: "ocsp"; data_b64: string };
}

export function buildSyntheticTimeStampToken(opts: {
  imprint: Buffer;
  nonce: Buffer;
  genTime: Date;
  policyOid: string;
  serial: number;
  tsaCertPem: string;
  tsaCertDer: Buffer;
  tsaRootSha256: string;
}): SyntheticTstResult {
  if (opts.imprint.length !== 32) {
    throw new Error("imprint MUST be 32 bytes (SHA-256)");
  }
  if (opts.nonce.length !== 16) {
    throw new Error("nonce MUST be 16 bytes");
  }

  const SHA256_OID = "2.16.840.1.101.3.4.2.1";
  const SIGNED_DATA_OID = "1.2.840.113549.1.7.2";

  // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  const messageImprint = sequence(
    sequence(objectIdentifier(SHA256_OID)),
    octetString(opts.imprint)
  );

  // TSTInfo ::= SEQUENCE { version INTEGER(1), policy OID, messageImprint,
  //   serialNumber INTEGER, genTime GeneralizedTime, nonce INTEGER (optional) }
  const tstInfo = sequence(
    integer(1),
    objectIdentifier(opts.policyOid),
    messageImprint,
    integer(opts.serial),
    generalizedTime(opts.genTime),
    integerBytes(opts.nonce)
  );

  // Minimal ContentInfo wrapper: { contentType OID(signedData), content [0] EXPLICIT TSTInfo }
  // Real CMS would have SignedData with certs[] + signerInfos[]. We embed a
  // structure that conformance vectors can parse via tag-walking; bytes are
  // deterministic given the seeded inputs.
  const contentInfo = sequence(
    objectIdentifier(SIGNED_DATA_OID),
    tlv(0xa0, octetString(tstInfo))
  );

  // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }
  // PKIStatusInfo ::= SEQUENCE { status INTEGER (0=granted) }
  const pkiStatus = sequence(integer(0));
  const tsr = sequence(pkiStatus, contentInfo);

  // Synthetic OCSP response: deterministic 64-byte hash of cert.
  const ocspBlob = createHash("sha256")
    .update(opts.tsaCertDer)
    .update(Buffer.from("ocsp-good", "utf8"))
    .digest();

  return {
    tsr: tsr.toString("base64"),
    tst: contentInfo.toString("base64"),
    tsaRootSha256: opts.tsaRootSha256,
    tsaCertChain: [opts.tsaCertPem],
    revocationEvidence: {
      kind: "ocsp",
      data_b64: ocspBlob.toString("base64"),
    },
  };
}
