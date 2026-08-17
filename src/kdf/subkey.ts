/**
 * Domain-separated subkey derivation.
 *
 * Splits ONE strong key into independent per-purpose subkeys so the same key is
 * never reused across two contexts (e.g. an auth proof vs an encryption seal
 * derived from the same partial master key). HMAC-SHA256 over a UTF-8 label:
 *
 *   subkey = HMAC-SHA256(key, label)
 *
 * Deterministic and portable (pure @noble — identical bytes on every platform),
 * so a subkey derived on web unseals what mobile sealed and vice-versa.
 */

import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'

/**
 * Derive a 32-byte subkey from a strong key + a domain-separation label.
 *
 * IMPORTANT: this is NOT a password KDF — feed it an already-strong key (a
 * derived master/vault key), never a raw password. For password stretching use
 * argon2id/pbkdf2. The label MUST be a stable, versioned, purpose-unique string
 * (e.g. `"myapp-<purpose>-v1"`); reusing a label across purposes re-introduces
 * the key-reuse the split exists to prevent.
 *
 * @param key   - Strong input key material (>= 16 bytes recommended)
 * @param label - Domain-separation context, UTF-8 encoded
 * @returns 32-byte subkey (HMAC-SHA256 output)
 */
export function deriveSubkey(key: Uint8Array, label: string): Uint8Array {
  return hmac(sha256, key, new TextEncoder().encode(label))
}
