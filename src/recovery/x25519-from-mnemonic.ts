/**
 * Derive an X25519 keypair from a BIP39 mnemonic.
 *
 * The recovery phrase is the root of trust for account recovery. The BIP39 seed
 * derivation lives in `deriveRecoverySubkey`; this module just pins the X25519
 * HKDF info tag and turns the derived scalar into a keypair. The info tag
 * domain-separates it from any other key derived from the same phrase.
 *
 * RECOVERY_KEY_SALT is a domain separator, not a secret. A test vector pins the
 * derived bytes so the constants can't drift unnoticed.
 */

import { x25519PublicFromPrivate } from '../asymmetric/x25519.js'
import { deriveRecoverySubkey } from './mnemonic-seed.js'

const X25519_INFO_BYTES = new TextEncoder().encode('wiggwigg-recovery-x25519-v1')

/**
 * Derive the 32-byte X25519 private key for the recovery scheme.
 * Caller is responsible for wiping the returned bytes after use.
 */
export async function deriveRecoveryX25519PrivateKey(mnemonic: string): Promise<Uint8Array> {
  return deriveRecoverySubkey(mnemonic, X25519_INFO_BYTES)
}

/**
 * Derive the 32-byte X25519 public key for the recovery scheme.
 * Computes the private key transiently and wipes it before returning.
 */
export async function deriveRecoveryX25519PublicKey(mnemonic: string): Promise<Uint8Array> {
  const privateKey = await deriveRecoveryX25519PrivateKey(mnemonic)
  try {
    return x25519PublicFromPrivate(privateKey)
  } finally {
    privateKey.fill(0)
  }
}
