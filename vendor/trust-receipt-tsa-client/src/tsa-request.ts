import { createHash, randomBytes } from "node:crypto";
import {
  booleanValue,
  integer,
  nullValue,
  objectIdentifier,
  octetString,
  sequence,
  toHex,
} from "./der.js";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";

export interface TimeStampRequest {
  readonly der: Uint8Array;
  readonly derBase64: string;
  readonly nonceHex: string;
  readonly imprintHex: string;
  readonly imprintAlgo: "sha-256";
}

export interface BuildTimeStampRequestOptions {
  readonly payload: Uint8Array | string;
  readonly nonce?: Uint8Array;
  readonly policyOid?: string;
  readonly certReq?: boolean;
}

export function sha256Bytes(payload: Uint8Array | string): Uint8Array {
  return createHash("sha256").update(payload).digest();
}

export function buildTimeStampRequest(
  options: BuildTimeStampRequestOptions
): TimeStampRequest {
  const nonce = options.nonce ?? randomBytes(16);
  if (nonce.length !== 16) throw new Error("RFC 3161 nonce must be 16 bytes");
  const imprint = sha256Bytes(options.payload);
  const algorithmIdentifier = sequence(
    objectIdentifier(SHA256_OID),
    nullValue()
  );
  const messageImprint = sequence(algorithmIdentifier, octetString(imprint));
  const der = sequence(
    integer(1),
    messageImprint,
    ...(options.policyOid ? [objectIdentifier(options.policyOid)] : []),
    integer(nonce),
    booleanValue(options.certReq ?? true)
  );
  return {
    der,
    derBase64: Buffer.from(der).toString("base64"),
    nonceHex: toHex(nonce),
    imprintHex: toHex(imprint),
    imprintAlgo: "sha-256",
  };
}
