/**
 * Shared BIP39-mnemonic → recovery subkey derivation.
 *
 * Every recovery key derived from the phrase (X25519 sealing, Ed25519 auth)
 * routes through here, so the domain-separator salt and the "first 32 bytes of
 * the 64-byte seed" convention live in exactly one audited place and can't drift
 * between derivations. Each key is separated by its own HKDF `info` tag.
 */

import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { mnemonicToSeed } from '@scure/bip39'

// A domain separator, not a secret. Frozen: every stored recovery public key is
// derived under it, so changing it would lock recovering users out.
const RECOVERY_KEY_SALT_BYTES = new TextEncoder().encode('wiggwigg-recovery-key-v1')

/**
 * Derive a 32-byte recovery subkey from `mnemonic`, domain-separated by `info`.
 * The caller is responsible for wiping the returned bytes after use.
 */
export async function deriveRecoverySubkey(
  mnemonic: string,
  info: Uint8Array,
): Promise<Uint8Array> {
  const seed = await mnemonicToSeed(mnemonic)
  const seedHalf = new Uint8Array(seed.buffer, seed.byteOffset, 32)
  return hkdf(sha256, seedHalf, RECOVERY_KEY_SALT_BYTES, info, 32)
}
