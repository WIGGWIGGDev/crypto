/**
 * Shared signing primitives for domain-separated Ed25519 payloads.
 *
 * Every place in the codebase that builds a byte string to Ed25519-sign (login
 * challenge-response, auth-key provisioning, recovery-auth) routes through here,
 * so the framing (domain tag + delimiters) and the sign/verify length checks
 * live in exactly one audited place and can never diverge between call sites.
 */

import { ed25519 } from '@noble/curves/ed25519.js'

export const ED25519_SEED_LEN = 32
export const ED25519_PUBLIC_LEN = 32
export const ED25519_SIGNATURE_LEN = 64

/**
 * Build an unambiguous byte string to sign:
 *   utf8(domain) || 0x00 || field0 || 0x00 || field1 || ...
 *
 * The leading domain tag binds the signature to one protocol, so a signature
 * made for one purpose can't be relayed against another that happens to sign
 * similar bytes. The 0x00 delimiter keeps the framing consistent; the verifier
 * reconstructs the identical payload from the same fields, so there is no
 * length-ambiguity attack across the fixed field set of a given domain.
 */
export function buildSignedPayload(domain: string, ...fields: readonly Uint8Array[]): Uint8Array {
  const domainBytes = new TextEncoder().encode(domain)
  let length = domainBytes.length
  for (const field of fields) {
    length += 1 + field.length
  }
  const out = new Uint8Array(length)
  out.set(domainBytes, 0)
  let offset = domainBytes.length
  for (const field of fields) {
    out[offset] = 0x00
    offset += 1
    out.set(field, offset)
    offset += field.length
  }
  return out
}

/** Ed25519-sign `payload` with a 32-byte secret seed. Returns the 64-byte signature. */
export function signEd25519(privateKey: Uint8Array, payload: Uint8Array): Uint8Array {
  if (privateKey.length !== ED25519_SEED_LEN) {
    throw new Error(
      `signed-payload: private seed must be ${ED25519_SEED_LEN} bytes, got ${privateKey.length}`,
    )
  }
  return ed25519.sign(payload, privateKey)
}

/**
 * Verify an Ed25519 signature over `payload`. Returns false on a well-formed but
 * invalid signature (callers treat that as an auth failure); throws only on a
 * malformed key or signature length.
 */
export function verifyEd25519(
  publicKey: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== ED25519_PUBLIC_LEN) {
    throw new Error(
      `signed-payload: public key must be ${ED25519_PUBLIC_LEN} bytes, got ${publicKey.length}`,
    )
  }
  if (signature.length !== ED25519_SIGNATURE_LEN) {
    throw new Error(
      `signed-payload: signature must be ${ED25519_SIGNATURE_LEN} bytes, got ${signature.length}`,
    )
  }
  return ed25519.verify(signature, payload, publicKey)
}
