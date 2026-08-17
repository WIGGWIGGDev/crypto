import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, it } from 'vitest'

import { buildSignedPayload, signEd25519, verifyEd25519 } from './signed-payload.js'

describe('buildSignedPayload', () => {
  it('lays out utf8(domain) || 0x00 || field || 0x00 || field', () => {
    const out = buildSignedPayload('dom', new Uint8Array([1, 2]), new Uint8Array([9]))
    // 'dom' = [0x64, 0x6f, 0x6d]
    expect(Array.from(out)).toEqual([0x64, 0x6f, 0x6d, 0x00, 1, 2, 0x00, 9])
  })

  it('handles the domain-only case (no fields)', () => {
    expect(Array.from(buildSignedPayload('x'))).toEqual([0x78])
  })

  it('is deterministic', () => {
    const a = buildSignedPayload('d', new Uint8Array([1]), new Uint8Array([2]))
    const b = buildSignedPayload('d', new Uint8Array([1]), new Uint8Array([2]))
    expect(Array.from(a)).toEqual(Array.from(b))
  })
})

describe('signEd25519 / verifyEd25519', () => {
  const seed = new Uint8Array(32).fill(7)
  const publicKey = ed25519.getPublicKey(seed)

  it('round-trips a signature and rejects a different payload', () => {
    const payload = buildSignedPayload('test', new Uint8Array([1, 2, 3]))
    const signature = signEd25519(seed, payload)
    expect(signature.length).toBe(64)
    expect(verifyEd25519(publicKey, payload, signature)).toBe(true)
    expect(
      verifyEd25519(publicKey, buildSignedPayload('test', new Uint8Array([9])), signature),
    ).toBe(false)
  })

  it('throws on a wrong-length private seed', () => {
    expect(() => signEd25519(new Uint8Array(31), new Uint8Array(1))).toThrow(/32 bytes/)
  })

  it('throws on a wrong-length public key or signature', () => {
    const payload = new Uint8Array(1)
    expect(() => verifyEd25519(new Uint8Array(31), payload, new Uint8Array(64))).toThrow(/32 bytes/)
    expect(() => verifyEd25519(new Uint8Array(32), payload, new Uint8Array(63))).toThrow(/64 bytes/)
  })
})
