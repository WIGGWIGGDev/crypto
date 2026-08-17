/**
 * Legacy password-authentication proof.
 *
 * The server never sees the password or the derived master key. The client
 * proves knowledge of the master key with a keyed hash of a fixed challenge:
 *
 *   proof     = HMAC-SHA256(masterKey, AUTH_CHALLENGE)
 *   proofHash = SHA-256(proof)
 *
 * The server stores proofHash and compares it on login. This keeps the password
 * and master key off the server and out of the vault-decryption path, but the
 * stored value equals what the client sends, so a leak of it is enough to
 * authenticate (it still cannot decrypt vault data). The Ed25519 challenge-
 * response scheme in ../auth-signing removes that property and supersedes this
 * one; this path remains only to read accounts that haven't migrated.
 *
 * Note: this module is the canonical definition of the scheme. A host that computes the same
 * value inline instead of importing it must produce byte-for-byte identical output — a single
 * wrong byte locks accounts out at login — so any such implementation should be guarded by
 * cross-implementation known-answer tests against this one.
 */

import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'

/**
 * Domain-separation tag for the proof. Not a secret. It must not change once
 * accounts exist, since every stored proof hash depends on it.
 */
export const AUTH_CHALLENGE = 'wiggwigg-auth-challenge-v1' as const

/**
 * Compute the proof hash the client sends at login. Returns 32 raw bytes;
 * callers hex- or base64-encode for transport.
 *
 *   HMAC-SHA256(masterKey, AUTH_CHALLENGE) -> SHA-256 -> 32 bytes
 *
 * The HMAC binds the output to the master key; the SHA-256 makes the stored
 * value non-invertible, so a leak doesn't reveal the master key (see the module
 * note for what a leak does still allow).
 */
export function computeAuthProofHash(masterKey: Uint8Array): Uint8Array {
  if (masterKey.length !== 32) {
    throw new Error(`auth-proof: master key must be 32 bytes, got ${masterKey.length}`)
  }
  const challenge = new TextEncoder().encode(AUTH_CHALLENGE)
  const proof = hmac(sha256, masterKey, challenge)
  return sha256(proof)
}

/** Hex-encoded variant for callers that need the 64-character wire string. */
export function computeAuthProofHashHex(masterKey: Uint8Array): string {
  return bytesToHex(computeAuthProofHash(masterKey))
}

/** Inline hex encoder so the package needs no utility dependency. */
function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte_ of bytes) {
    const byte = byte_ ?? 0
    out += byte.toString(16).padStart(2, '0')
  }
  return out
}
