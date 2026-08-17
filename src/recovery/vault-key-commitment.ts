import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'

const VAULT_KEY_COMMITMENT_LABEL = new TextEncoder().encode('wiggwigg-vault-key-commitment-v1')

/**
 * A public, server-opaque commitment to the Vault Key V, stored beside a v2
 * recovery escrow (which seals V under the recovery phrase).
 *
 * At recovery the client unseals V from the server-supplied escrow and MUST
 * reproduce this commitment before trusting or re-sealing those bytes. It is a
 * POSITIVE check: it catches an escrow that was corrupted or MISLABELED even for
 * an account with NO decryptable records to fall back on — the gap that a
 * "did any record decrypt?" heuristic cannot cover, since an account may legitimately
 * have nothing stored yet.
 *
 * HMAC-SHA256(key = V, msg = label): V is a 256-bit random key, so the
 * commitment reveals nothing about V and cannot be brute-forced.
 *
 * ⚠ Threat scope: this defends the ACCIDENTAL / buggy wrong-V class. It does NOT
 * defend a fully-malicious server, which can substitute the escrow AND store the
 * matching `HMAC(K, label)` — an inherent limitation of any server-stored anchor.
 * Closing that requires an attestation the client verifies with a key derived
 * from the recovery phrase (see `escrow-attestation.ts`). Compare the result in
 * constant time (`bytesEqual`).
 */
export function computeVaultKeyCommitment(vaultKey: Uint8Array): Uint8Array {
  return hmac(sha256, vaultKey, VAULT_KEY_COMMITMENT_LABEL)
}
