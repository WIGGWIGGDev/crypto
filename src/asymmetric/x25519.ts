/**
 * X25519 scalar-multiplication primitives.
 *
 * Thin typed wrapper over `@noble/curves`'s X25519 so callers don't depend on
 * the curve library directly, and the implementation can be swapped without
 * touching call sites if the hybrid scheme ever rotates.
 */

import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

export interface X25519Keypair {
  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
}

/**
 * Deterministically derive an X25519 keypair from a secret (e.g. the Vault Key
 * V, or a BIP39 seed half) via HKDF-SHA256 with a domain-separation `info`.
 * Same secret + info ⇒ same keypair (so a registered public key keeps matching
 * across unlocks / a V rotation re-derives the right key); HKDF is one-way, so
 * the keypair never exposes the secret.
 *
 * Callers MUST use a DISTINCT `info` per purpose (one tag per keypair role) so
 * the keys are domain-separated — a compromise of one derived key can never
 * yield another. Single source of this derivation for every HKDF-from-secret
 * X25519 keypair a host derives.
 */
export function deriveX25519KeypairFromSecret(
  secret: Uint8Array,
  info: string | Uint8Array,
  salt?: Uint8Array,
): X25519Keypair {
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info
  const privateKey = hkdf(sha256, secret, salt, infoBytes, 32)
  const publicKey = x25519PublicFromPrivate(privateKey)
  return { privateKey, publicKey }
}

/**
 * Generate a fresh X25519 keypair using the platform CSPRNG.
 * Used for the per-seal ephemeral keypair inside `hybrid.seal`.
 */
export function generateX25519Keypair(): X25519Keypair {
  const privateKey = x25519.utils.randomSecretKey()
  const publicKey = x25519.getPublicKey(privateKey)
  return { privateKey, publicKey }
}

/**
 * Derive the X25519 public key corresponding to a given 32-byte secret.
 * Used when the private key comes from a deterministic source (e.g. HKDF
 * over a BIP39 seed in the recovery-key path).
 */
export function x25519PublicFromPrivate(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) {
    throw new Error(`X25519 private key must be 32 bytes, got ${privateKey.length}`)
  }
  return x25519.getPublicKey(privateKey)
}

/**
 * Compute the shared secret between a local private key and a remote public.
 * The raw ECDH output must always pass through a KDF before use; never use the
 * shared secret as a key directly.
 */
export function x25519Ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) {
    throw new Error(`X25519 private key must be 32 bytes, got ${privateKey.length}`)
  }
  if (publicKey.length !== 32) {
    throw new Error(`X25519 public key must be 32 bytes, got ${publicKey.length}`)
  }
  return x25519.getSharedSecret(privateKey, publicKey)
}
