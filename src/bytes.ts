/**
 * Constant-time byte-equality.
 *
 * Use whenever a length- or prefix-dependent early return could leak
 * information via timing: comparing public keys, MACs, auth proofs, or the
 * recovery-key substitution check. Returns false immediately on a length
 * mismatch — lengths are not secret, only contents are.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    const ai = a[i]
    const bi = b[i]
    // Unreachable given the equal-length guard above; satisfies
    // noUncheckedIndexedAccess without a non-null assertion.
    if (ai === undefined || bi === undefined) return false
    diff |= ai ^ bi
  }
  return diff === 0
}

/**
 * Frame a fixed sequence of variable-length byte fields into one collision-free
 * blob: each field is prefixed with its length as a 4-byte big-endian integer.
 *
 * Use this ANY time variable-length fields are concatenated and then hashed or
 * signed as a unit. A bare concatenation (`a ‖ b ‖ c`) is boundary-ambiguous —
 * a different split `(a', b', c')` can produce the identical bytes and therefore
 * the same hash/signature, letting an attacker shift bytes across field
 * boundaries while a signature stays valid. Length prefixes make the split
 * unforgeable.
 *
 * Shared by the recovery-auth material (`buildRecoveryAuthChallengePayload`
 * hashes the material before signing) so every implementation frames it
 * byte-identically. Big-endian u32 caps any single field at 4 GiB — far beyond
 * any key/wrap/salt this frames.
 */
export function lengthPrefixedConcat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0
  for (const part of parts) {
    total += 4 + part.length
  }
  const out = new Uint8Array(total)
  const view = new DataView(out.buffer)
  let offset = 0
  for (const part of parts) {
    view.setUint32(offset, part.length, false)
    offset += 4
    out.set(part, offset)
    offset += part.length
  }
  return out
}

/**
 * Encode a non-negative integer as a fixed 4-byte big-endian value.
 *
 * Use when a version/count/enum must be framed into signed or AAD-bound material:
 * a decimal string ("12") would be variable-length and boundary-ambiguous, and a
 * bare byte would cap at 255. Fixed width keeps the field self-delimiting so the
 * signer and verifier frame it identically. Rejects a non-integer or out-of-range
 * value rather than silently wrapping/truncating.
 */
export function u32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`u32be: expected an integer in [0, 2^32), got ${value}`)
  }
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, value, false)
  return out
}

/**
 * Encode a non-negative integer as a fixed 8-byte big-endian value.
 *
 * Accepts a bigint (full u64 range) or a number that is a safe integer; a number
 * above Number.MAX_SAFE_INTEGER is rejected because it can't be represented
 * exactly — pass a bigint for values that large. Used to bind a monotonic entry
 * version / manifest counter into AAD or signed material with a self-delimiting,
 * cross-platform-identical field (no decimal-string boundary ambiguity).
 */
export function u64be(value: number | bigint): Uint8Array {
  let big: bigint
  if (typeof value === 'bigint') {
    big = value
  } else {
    if (!Number.isSafeInteger(value)) {
      throw new Error(
        `u64be: number ${value} is not a safe integer; pass a bigint for large values`,
      )
    }
    big = BigInt(value)
  }
  if (big < 0n || big > 0xffffffffffffffffn) {
    throw new Error(`u64be: expected an integer in [0, 2^64), got ${value}`)
  }
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, big, false)
  return out
}
