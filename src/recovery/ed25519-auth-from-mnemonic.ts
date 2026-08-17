/**
 * Ed25519 "recovery-auth" keypair from a BIP39 mnemonic, and the payload the
 * recovery flow signs with it.
 *
 * The v2 recovery escrow seals the vault key V instead of the master key M, so a
 * recovering client unseals V directly — and therefore no longer holds M to build
 * a password-change auth proof from. This keypair fills that gap: the client signs
 * a fresh server challenge (bound to the new credential material) with the
 * mnemonic-derived private key, and the server verifies it against the recovery-auth
 * public key it holds for the account.
 *
 * The BIP39-seed derivation is shared with the X25519 recovery key
 * (`deriveRecoverySubkey`); this module only pins the DIFFERENT HKDF info tag,
 * so the signing key can never collide with the sealing key from the same
 * phrase. The info tag MUST NOT change once keys exist.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { lengthPrefixedConcat, u32be } from '../bytes.js'
import { buildSignedPayload } from '../signed-payload.js'
import { deriveRecoverySubkey } from './mnemonic-seed.js'

const ED25519_AUTH_INFO_BYTES = new TextEncoder().encode('wiggwigg-recovery-ed25519-auth-v1')

/**
 * Domain tag for the recovery-auth authorization signature. Distinct from the
 * login-challenge and auth-provisioning domains, so a recovery-auth signature
 * can never be relayed as one of those (or vice versa).
 */
const RECOVERY_AUTH_PAYLOAD_DOMAIN = 'wiggwigg-recovery-auth-v1'

export interface RecoveryAuthKeypair {
  /** 32-byte Ed25519 secret seed; the caller wipes it after signing. */
  readonly privateKey: Uint8Array
  /** 32-byte Ed25519 public key — the only half the server stores. */
  readonly publicKey: Uint8Array
}

/**
 * Derive the deterministic Ed25519 recovery-auth keypair. Same mnemonic always
 * yields the same keypair, so the server stores just the public key and the
 * client re-derives the private key at recovery time. Caller wipes `privateKey`.
 */
export async function deriveRecoveryAuthKeypair(mnemonic: string): Promise<RecoveryAuthKeypair> {
  const authSeed = await deriveRecoverySubkey(mnemonic, ED25519_AUTH_INFO_BYTES)
  const publicKey = ed25519.getPublicKey(authSeed)
  return { privateKey: authSeed, publicKey }
}

/**
 * Derive only the Ed25519 recovery-auth public key (what the client uploads at
 * escrow setup/rotation and the server stores). Wipes the transient seed.
 */
export async function deriveRecoveryAuthPublicKey(mnemonic: string): Promise<Uint8Array> {
  const { privateKey, publicKey } = await deriveRecoveryAuthKeypair(mnemonic)
  privateKey.fill(0)
  return publicKey
}

/**
 * Build the payload the recovery flow signs with the recovery-auth private key
 * to authorize a password change when a v2 escrow yields V but no M. Binds:
 *   - `userId` (the account being recovered),
 *   - a FRESH server-issued challenge (anti-replay),
 *   - `sha256(newCredentialMaterial)`, so the signature commits to the exact new
 *     keys/wraps being installed and a captured signature can't be relayed to
 *     install different credentials.
 *
 * ⛔ `newCredentialMaterial` MUST be framed with `lengthPrefixedConcat` (NOT a
 * bare concatenation of the fields). Because it is SHA-256'd here before
 * signing, a bare `a ‖ b ‖ c` is boundary-ambiguous — a malicious server could
 * shift bytes across the credential-field boundaries to a different `(a', b', c')`
 * with the same hash and keep the phrase-holder's signature valid, installing
 * swapped credentials. Client and server MUST frame it identically.
 *
 * Sign with `signEd25519(privateKey, payload)`; the server verifies with
 * `verifyEd25519(storedRecoveryAuthPublicKey, payload, signature)`.
 */
export function buildRecoveryAuthChallengePayload(
  userId: string,
  serverChallenge: Uint8Array,
  newCredentialMaterial: Uint8Array,
): Uint8Array {
  return buildSignedPayload(
    RECOVERY_AUTH_PAYLOAD_DOMAIN,
    new TextEncoder().encode(userId),
    serverChallenge,
    sha256(newCredentialMaterial),
  )
}

/**
 * The exact set of new-credential fields a v2-escrow recovery signature commits
 * to, framed collision-free with `lengthPrefixedConcat` (the material that
 * `buildRecoveryAuthChallengePayload` then hashes). Client and server MUST build
 * this identically — the client just before signing, the server from the params
 * it is about to write — so a malicious server that swaps ANY of these fields
 * invalidates the phrase-holder's signature.
 *
 * Field order is the wire contract and MUST NOT be reordered once signatures
 * exist. Every field a recovery installs that governs whether the new account can
 * decrypt — or whether the NEXT recovery can authenticate — is bound: the seal of
 * V (the new escrow) AND the new phrase public key it is sealed to; V wrapped under
 * the new M; the salt that derives M; the auth and partial-auth proofs (the wrapped
 * vault key's AAD is derived from the account id and the auth proof, so a swapped
 * proof would strand V); the new recovery-auth public key, so a server swap can't
 * silently brick the next recovery; and the escrow and vault-key VERSIONS, so a
 * server can't flip v2 back to v1 to mis-route the next recovery.
 */
export function buildRecoveryAuthMaterial(fields: {
  /** New per-login Ed25519 auth public key (provisioned from the new M). */
  newAuthPublicKey: Uint8Array
  /** New v2 recovery escrow: V sealed under the new recovery phrase's X25519 public. */
  newWrappedMasterKey: Uint8Array
  /** V wrapped under the new master key M. */
  newWrappedVaultKey: Uint8Array
  /** Salt the new master key M is derived under. */
  newEncryptionSalt: Uint8Array
  /** New full auth proof hash (`computeAuthProof(M_new)`). */
  newAuthProofHash: Uint8Array
  /** New partial (anti-phishing) auth proof hash. */
  newPartialAuthHash: Uint8Array
  /** New recovery phrase's X25519 public key (what the escrow is now bound to). */
  newRecoveryPublicKey: Uint8Array
  /** New recovery phrase's Ed25519 recovery-auth public key (authenticates the NEXT recovery). */
  newRecoveryAuthPublicKey: Uint8Array
  /** New escrow scheme version — bound so v2 can't be flipped back to v1. */
  newWrappedMasterKeyVersion: number
  /** New vault-key wrap scheme version. */
  newWrappedVaultKeyVersion: number
}): Uint8Array {
  return lengthPrefixedConcat([
    fields.newAuthPublicKey,
    fields.newWrappedMasterKey,
    fields.newWrappedVaultKey,
    fields.newEncryptionSalt,
    fields.newAuthProofHash,
    fields.newPartialAuthHash,
    fields.newRecoveryPublicKey,
    fields.newRecoveryAuthPublicKey,
    u32be(fields.newWrappedMasterKeyVersion),
    u32be(fields.newWrappedVaultKeyVersion),
  ])
}
