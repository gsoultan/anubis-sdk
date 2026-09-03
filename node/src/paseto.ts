/**
 * PASETO v4.public — Ed25519-signed tokens — over node:crypto alone.
 *
 * Token layout:
 *
 *   v4.public.<b64url(message || signature)>[.<b64url(footer)>]
 *
 * where signature = Ed25519-Sign(sk, PAE([h, m, f, i])). PAE is the spec's
 * Pre-Authentication Encoding; it makes the signed byte string injective over
 * its pieces, which is what stops a footer byte being reinterpreted as a
 * message byte.
 */
import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";

const HEADER = "v4.public.";
const SIGNATURE_BYTES = 64;
const PUBLIC_KEY_BYTES = 32;

export class PasetoError extends Error {}

export function b64urlDecode(s: string): Buffer {
  // Strict: a token is generated, never typed, so padding or a stray
  // character means tampering rather than a formatting preference.
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new PasetoError("paseto: malformed token");
  return Buffer.from(s, "base64url");
}

export function b64urlEncode(b: Buffer | Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/** LE64 with the most significant bit cleared, per the PASETO spec. */
function le64(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n) & 0x7fffffffffffffffn);
  return b;
}

export function pae(...pieces: Buffer[]): Buffer {
  const out: Buffer[] = [le64(pieces.length)];
  for (const p of pieces) {
    out.push(le64(p.length), p);
  }
  return Buffer.concat(out);
}

export interface ParsedToken {
  message: Buffer;
  signature: Buffer;
  footer: Buffer;
}

/**
 * Split a token WITHOUT verifying it.
 *
 * The result is untrusted until verify() succeeds. It exists so the kid can be
 * read from the footer to select a verification key — a read that may only
 * ever index a bounded, already-loaded map.
 */
export function parse(token: string): ParsedToken {
  if (!token.startsWith(HEADER)) throw new PasetoError("paseto: not a v4.public token");
  const rest = token.slice(HEADER.length);
  const dot = rest.indexOf(".");
  let bodyPart = rest;
  let footerPart = "";
  if (dot >= 0) {
    bodyPart = rest.slice(0, dot);
    footerPart = rest.slice(dot + 1);
    if (footerPart === "" || footerPart.includes(".")) throw new PasetoError("paseto: malformed token");
  }
  const body = b64urlDecode(bodyPart);
  if (body.length < SIGNATURE_BYTES) throw new PasetoError("paseto: malformed token");
  const footer = footerPart ? b64urlDecode(footerPart) : Buffer.alloc(0);
  const cut = body.length - SIGNATURE_BYTES;
  return { message: body.subarray(0, cut), signature: body.subarray(cut), footer };
}

/** Build a KeyObject from the 32 raw public key bytes the key document carries. */
export function publicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== PUBLIC_KEY_BYTES) throw new PasetoError("paseto: wrong key size");
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/** Verify a token and return its message. Throws on any failure. */
export function verify(key: KeyObject, token: string, implicit: Buffer = Buffer.alloc(0)): ParsedToken {
  const parsed = parse(token);
  const m2 = pae(Buffer.from(HEADER), parsed.message, parsed.footer, implicit);
  // Ed25519 takes a null algorithm: the curve fixes the hash.
  if (!cryptoVerify(null, m2, key, parsed.signature)) {
    throw new PasetoError("paseto: signature verification failed");
  }
  return parsed;
}
