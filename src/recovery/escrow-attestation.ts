/**
 * Client-verifiable escrow self-attestation.
 *
 * The recovery escrow (a v2 seal of the vault key V) and its positive-check
 * commitment are both stored server-side, and the zero-knowledge threat model
 * treats the server as malicious. The commitment alone is only HMAC(V, label), so
 * a malicious server can substitute the escrow AND forge a matching commitment. A
 * signature the SERVER verifies at write time does not help either — a malicious
 * server simply ignores its own check.
 *
 * This attestation is instead verified by the CLIENT at recovery time, with a key
 * derived from the recovery phrase (`deriveRecoveryAuthKeypair`). At every escrow
 * write (initial setup, phrase rotation, recovery completion) the phrase-holder
 * signs the canonical escrow material; on the NEXT recovery the client re-derives
 * the SAME Ed25519 public key from the phrase it just typed and verifies the
 * stored attestation BEFORE trusting the escrow. The server never touches the
 * trust decision and cannot forge the signature (it lacks the phrase's private
 * key), so a swapped or tampered escrow — or a forged commitment — is caught.
 *
 * What it binds, and why each field is safe to bind here:
 *   - `wrappedMasterKey` (bytes)  — the escrow. A v2 escrow seals V, which is
 *      STABLE across password changes, so its bytes only change on phrase rotation
 *      or a re-mint — themselves escrow writes, which re-sign.
 *   - `wrappedMasterKeyVersion`   — the escrow scheme (2 = V-sealing). Binding it
 *      signs over a downgrade to the legacy master-key-sealing scheme.
 *   - `wrappedVaultKeyVersion`    — deliberately NOT bound. The v2 recovery path
 *      derives V from the escrow and never consumes the wrapped-vault-key bytes, so
 *      binding its version buys no recovery-time protection while coupling the
 *      attestation's lifetime to a field a legitimate wrap-scheme migration bumps
 *      OUTSIDE any phrase event — a desync/brick landmine. Wrap-version downgrade is
 *      instead covered per-recovery by `buildRecoveryAuthMaterial`, freshly signed
 *      each recovery and unable to desync.
 *   - `vaultKeyCommitment` (bytes)— derived from V; stable across password changes.
 *   - `recoveryX25519Public`      — the phrase's X25519 public key the escrow is
 *      sealed to; changes only on phrase rotation.
 *   - `integrityRequiredEpoch`    — an anti-downgrade latch: 0 = integrity not yet
 *      required; a positive E = "this account has required vault integrity since
 *      epoch E". A recovering or fresh device learns this from the PHRASE, via the
 *      verified attestation, so a malicious server can no longer answer "this
 *      account isn't protected yet" to strip the manifest — the client knows better.
 *
 * The verification key MUST be RE-DERIVED from the recovery phrase at recovery
 * time (`deriveRecoveryAuthKeypair`) — NEVER a server-stored public key, which a
 * malicious server could swap along with the escrow and then forge a matching
 * signature. A server-held copy of that public key exists only for the server's
 * own challenge-response; it is not the trust anchor for this attestation. Sign
 * with `signEd25519(privateKey, payload)`, verify with
 * `verifyEd25519(phraseDerivedPublicKey, payload, signature)`.
 *
 * Residual (inherent, documented): the server can still serve an OLD escrow with
 * its OLD valid attestation. But the old escrow is sealed to the old phrase, so a
 * rotated phrase won't open it → recovery fails safely (DoS), and V is stable so no
 * wrong key is ever installed. Escrow-rollback = DoS, acknowledged.
 */

import { lengthPrefixedConcat, u32be, u64be } from '../bytes.js'
import { buildSignedPayload } from '../signed-payload.js'

/**
 * Domain tag for the escrow self-attestation signature. Distinct from the
 * recovery-auth authorization domain (`wiggwigg-recovery-auth-v1`) and the login
 * domains, so an attestation signature can never be relayed as one of those or
 * vice versa. MUST NOT change once attestations exist.
 */
export const ESCROW_ATTESTATION_DOMAIN = 'wiggwigg-escrow-attest-v1'

export interface EscrowAttestationFields {
  /** The account the escrow belongs to. */
  readonly userId: string
  /** The escrow blob (v2 seals the vault key V). Bound by bytes. */
  readonly wrappedMasterKey: Uint8Array
  /** Escrow scheme version (2 = V-sealing). */
  readonly wrappedMasterKeyVersion: number
  /** Positive-check commitment (HMAC over V). Bound by bytes. */
  readonly vaultKeyCommitment: Uint8Array
  /** Recovery X25519 public key the escrow is sealed to. */
  readonly recoveryX25519Public: Uint8Array
  /**
   * Anti-downgrade latch: 0 = integrity not yet required; a positive value E =
   * "this account has required vault integrity (a manifest) since epoch E". The
   * recovering client trusts this over any server claim of "no manifest".
   */
  readonly integrityRequiredEpoch: number | bigint
}

const textEncoder = new TextEncoder()

/**
 * Frame the escrow fields collision-free (each length-prefixed) into the material
 * the attestation signs over. Field ORDER is the wire contract and MUST NOT be
 * reordered once any attestation exists — the client rebuilds this identically at
 * verify time, so a server that swaps ANY field invalidates the phrase signature.
 */
export function buildEscrowAttestationMaterial(fields: EscrowAttestationFields): Uint8Array {
  return lengthPrefixedConcat([
    fields.wrappedMasterKey,
    u32be(fields.wrappedMasterKeyVersion),
    fields.vaultKeyCommitment,
    fields.recoveryX25519Public,
    u64be(fields.integrityRequiredEpoch),
  ])
}

/**
 * Build the exact byte string the phrase-holder Ed25519-signs to attest an escrow.
 * Domain-tagged and bound to `userId`, over the framed escrow material. Both the
 * signer (at escrow write) and the verifier (at the next recovery) build this from
 * the same fields, so the signature covers every field with no length ambiguity.
 */
export function buildEscrowAttestationPayload(fields: EscrowAttestationFields): Uint8Array {
  return buildSignedPayload(
    ESCROW_ATTESTATION_DOMAIN,
    textEncoder.encode(fields.userId),
    buildEscrowAttestationMaterial(fields),
  )
}
