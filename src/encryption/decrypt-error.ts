/**
 * Shared decrypt-failure error + failure classification.
 *
 * WHY: AEAD primitives deliberately throw an OPAQUE error on any verification
 * failure — `crypto.subtle.decrypt` raises a bare `OperationError` and @noble's
 * `gcm` an "invalid tag" — because distinguishing "wrong key" from "corrupted
 * ciphertext" at the primitive level is exactly the oracle AEAD exists to deny.
 * A caller that wraps that in a bare `catch {}` and rethrows ONE string collapses
 * every failure mode into a single error group: wrong key, corrupted ciphertext,
 * malformed base64, and an AAD-binding mismatch all become indistinguishable in
 * logs. That distinction is what an operator needs — a decrypt failure across
 * many unrelated records with structurally VALID inputs points at the key, while
 * a single malformed input points at the record.
 *
 * `message` is a stable constant (see {@link DECRYPT_FAILURE_MESSAGE}) that
 * callers may match on; {@link DecryptionFailedError.reason} and `cause` carry
 * the diagnostics.
 *
 * SECURITY — this is not a padding oracle. `reason` is derived ONLY from facts
 * the caller already holds before calling decrypt (input lengths, base64
 * validity). The AEAD verification itself stays a single undifferentiated
 * `aead-verify-failed*`: we never report WHY the tag failed, only that it did
 * and whether an AAD was bound. Classification also runs strictly AFTER a
 * failure — it never gates or short-circuits a decrypt attempt, so adding it
 * cannot reject ciphertext that previously decrypted (notably ciphertext written
 * with a 16-byte IV, which AES-GCM accepts and readers must keep accepting).
 */

/** The single user-facing message; a stable contract callers may match on. */
export const DECRYPT_FAILURE_MESSAGE = 'Failed to decrypt content. Invalid key or corrupted data.'

/**
 * Why a decrypt failed, at the coarsest granularity that is safe to record.
 *
 * - `malformed-base64` — an input field wasn't decodable at all. Wire/storage
 *   corruption or a schema mismatch; never a key problem.
 * - `empty-ciphertext` / `bad-nonce-length` / `bad-tag-length` — the AEAD
 *   rejected the input AND the input was structurally anomalous. Points at the
 *   row/writer, not the key.
 * - `aead-verify-failed` — structurally valid input, tag did not verify, no AAD
 *   bound. Wrong key or corrupted bytes.
 * - `aead-verify-failed-aad` — same, but an AAD was bound, so a mismatched
 *   row-binding (wrong id/epoch fed to the AAD) is also a candidate.
 * - `unknown` — decrypt threw for a reason none of the above explains.
 */
export type DecryptFailureReason =
  | 'malformed-base64'
  | 'empty-ciphertext'
  | 'bad-nonce-length'
  | 'bad-tag-length'
  | 'aead-verify-failed'
  | 'aead-verify-failed-aad'
  | 'unknown'

/** Nonce lengths this package's AES-GCM ciphertext is known to use. */
const VALID_NONCE_LENGTHS: readonly number[] = [12, 16]

/** AES-GCM authentication tag length in bytes. */
const TAG_LENGTH = 16

export interface DecryptFailureShape {
  /** Ciphertext length in bytes (WITHOUT the tag). */
  readonly ciphertextLength: number
  /** Nonce/IV length in bytes. */
  readonly nonceLength: number
  /** Authentication tag length in bytes. */
  readonly tagLength: number
  /** Whether additional authenticated data was bound to this decrypt. */
  readonly hasAad: boolean
}

/**
 * Classify an already-failed decrypt from the shape of its inputs.
 *
 * Call this ONLY from a `catch` — it explains a failure, it never predicts one.
 * Structural anomalies are checked first because they are the specific,
 * actionable answers; a structurally sound input that still failed to verify is
 * the generic key-or-corruption case.
 */
export function classifyDecryptFailure(shape: DecryptFailureShape): DecryptFailureReason {
  if (shape.ciphertextLength === 0) return 'empty-ciphertext'
  if (!VALID_NONCE_LENGTHS.includes(shape.nonceLength)) return 'bad-nonce-length'
  if (shape.tagLength !== TAG_LENGTH) return 'bad-tag-length'
  return shape.hasAad ? 'aead-verify-failed-aad' : 'aead-verify-failed'
}

/**
 * A decrypt that failed, carrying a machine-readable {@link reason} and the
 * original error as `cause`.
 *
 * `message` is deliberately constant so callers can match on it as a contract.
 */
export class DecryptionFailedError extends Error {
  readonly reason: DecryptFailureReason

  constructor(reason: DecryptFailureReason, options?: ErrorOptions) {
    super(DECRYPT_FAILURE_MESSAGE, options)
    this.name = 'DecryptionFailedError'
    this.reason = reason
  }
}

/**
 * True when `error` is a {@link DecryptionFailedError}.
 *
 * Structural rather than `instanceof` on purpose: a duplicated package copy (two
 * bundle chunks each resolving their own dist) would break `instanceof` exactly
 * when the signal matters most. Telemetry must degrade to "no reason attribute",
 * never to a wrong answer.
 */
export function isDecryptionFailedError(error: Error): error is DecryptionFailedError {
  return (
    error.name === 'DecryptionFailedError' && 'reason' in error && typeof error.reason === 'string'
  )
}
