import { describe, expect, it } from 'vitest'

import {
  classifyDecryptFailure,
  DECRYPT_FAILURE_MESSAGE,
  DecryptionFailedError,
  isDecryptionFailedError,
} from './decrypt-error.js'

function shape(overrides: Partial<Parameters<typeof classifyDecryptFailure>[0]> = {}) {
  return {
    ciphertextLength: 64,
    nonceLength: 12,
    tagLength: 16,
    hasAad: false,
    ...overrides,
  }
}

describe('classifyDecryptFailure', () => {
  it('reports a structurally sound failure as a key-or-corruption problem', () => {
    expect(classifyDecryptFailure(shape())).toBe('aead-verify-failed')
  })

  it('distinguishes an AAD-bound failure, which can also be a bad row binding', () => {
    expect(classifyDecryptFailure(shape({ hasAad: true }))).toBe('aead-verify-failed-aad')
  })

  it('accepts a 16-byte GCM IV as structurally valid', () => {
    // Some ciphertext carries a 16-byte GCM IV. Reading one back must not be
    // mislabelled 'bad-nonce-length' — that would send debugging after the data
    // when the real fault is the key.
    expect(classifyDecryptFailure(shape({ nonceLength: 16 }))).toBe('aead-verify-failed')
  })

  it('names the structural fault when the input is anomalous', () => {
    expect(classifyDecryptFailure(shape({ ciphertextLength: 0 }))).toBe('empty-ciphertext')
    expect(classifyDecryptFailure(shape({ nonceLength: 8 }))).toBe('bad-nonce-length')
    expect(classifyDecryptFailure(shape({ tagLength: 12 }))).toBe('bad-tag-length')
  })

  it('prefers the structural fault over the generic AEAD answer', () => {
    // A structurally broken input that ALSO had an AAD is a data problem first;
    // reporting 'aead-verify-failed-aad' would hide the actionable cause.
    expect(classifyDecryptFailure(shape({ nonceLength: 0, hasAad: true }))).toBe('bad-nonce-length')
  })
})

describe('DecryptionFailedError', () => {
  it('keeps the user-facing message stable', () => {
    // Callers render `error.message` and tests match on this string — it is a
    // contract.
    expect(new DecryptionFailedError('aead-verify-failed').message).toBe(
      'Failed to decrypt content. Invalid key or corrupted data.',
    )
    expect(DECRYPT_FAILURE_MESSAGE).toBe(
      'Failed to decrypt content. Invalid key or corrupted data.',
    )
  })

  it('preserves the underlying cause instead of swallowing it', () => {
    const cause = new Error('OperationError')
    expect(new DecryptionFailedError('aead-verify-failed', { cause }).cause).toBe(cause)
  })

  it('carries the machine-readable reason', () => {
    expect(new DecryptionFailedError('malformed-base64').reason).toBe('malformed-base64')
  })
})

describe('isDecryptionFailedError', () => {
  it('recognises the error', () => {
    expect(isDecryptionFailedError(new DecryptionFailedError('unknown'))).toBe(true)
  })

  it('recognises a structurally identical copy from a duplicated bundle chunk', () => {
    // The guard is structural precisely so a second copy of this package still
    // yields the telemetry attribute rather than silently dropping it.
    const copy = new Error(DECRYPT_FAILURE_MESSAGE)
    copy.name = 'DecryptionFailedError'
    Object.defineProperty(copy, 'reason', { value: 'aead-verify-failed' })
    expect(isDecryptionFailedError(copy)).toBe(true)
  })

  it('rejects unrelated errors', () => {
    expect(isDecryptionFailedError(new Error('boom'))).toBe(false)
    // Same message, but not our error — must not be credited with a reason.
    expect(isDecryptionFailedError(new Error(DECRYPT_FAILURE_MESSAGE))).toBe(false)
  })

  it('rejects an error named right but carrying no reason', () => {
    const impostor = new Error(DECRYPT_FAILURE_MESSAGE)
    impostor.name = 'DecryptionFailedError'
    expect(isDecryptionFailedError(impostor)).toBe(false)
  })
})
