import { describe, expect, it } from 'vitest'

import {
  deserializeEnvelope,
  open,
  seal,
  sealSerialized,
  serializeEnvelope,
  type HybridEnvelope,
} from './hybrid.js'
import { generateX25519Keypair } from './x25519.js'

describe('hybrid.seal / hybrid.open', () => {
  it('round-trips plaintext of various sizes', () => {
    const { privateKey, publicKey } = generateX25519Keypair()

    for (const size of [0, 1, 16, 32, 256, 4096]) {
      const plaintext = crypto.getRandomValues(new Uint8Array(size))
      const envelope = seal(publicKey, plaintext)
      const opened = open(privateKey, publicKey, envelope)
      expect(opened).toEqual(plaintext)
    }
  })

  it('rejects with the wrong private key', () => {
    const alice = generateX25519Keypair()
    const bob = generateX25519Keypair()
    const envelope = seal(alice.publicKey, new Uint8Array([1, 2, 3, 4]))
    expect(() => open(bob.privateKey, alice.publicKey, envelope)).toThrow()
  })

  it('rejects with the wrong public key used for binding', () => {
    const alice = generateX25519Keypair()
    const bob = generateX25519Keypair()
    const envelope = seal(alice.publicKey, new Uint8Array([1, 2, 3, 4]))
    // Correct private but wrong binding public → HKDF salt mismatch → AEAD fails
    expect(() => open(alice.privateKey, bob.publicKey, envelope)).toThrow()
  })

  it('rejects if the ciphertext is tampered', () => {
    const { privateKey, publicKey } = generateX25519Keypair()
    const envelope = seal(publicKey, new Uint8Array([1, 2, 3, 4, 5]))
    const tampered: HybridEnvelope = {
      ...envelope,
      ciphertext: new Uint8Array(envelope.ciphertext),
    }
    const firstByte = tampered.ciphertext[0] ?? 0
    tampered.ciphertext[0] = firstByte ^ 0x01
    expect(() => open(privateKey, publicKey, tampered)).toThrow()
  })

  it('rejects envelopes with the wrong scheme version', () => {
    const { privateKey, publicKey } = generateX25519Keypair()
    const envelope = seal(publicKey, new Uint8Array([1]))
    expect(() => open(privateKey, publicKey, { ...envelope, schemeVersion: 99 })).toThrow(
      /scheme version/,
    )
  })

  it('throws on a non-32-byte recipient public', () => {
    expect(() => seal(new Uint8Array(31), new Uint8Array(10))).toThrow()
  })
})

describe('hybrid.serializeEnvelope / deserializeEnvelope', () => {
  it('round-trips through a single byte array', () => {
    const { privateKey, publicKey } = generateX25519Keypair()
    const plaintext = new TextEncoder().encode('hello recovery')
    const envelope = seal(publicKey, plaintext)

    const wire = serializeEnvelope(envelope)
    const parsed = deserializeEnvelope(wire)

    expect(parsed.schemeVersion).toBe(envelope.schemeVersion)
    expect(parsed.ephemeralPublicKey).toEqual(envelope.ephemeralPublicKey)
    expect(parsed.nonce).toEqual(envelope.nonce)
    expect(parsed.ciphertext).toEqual(envelope.ciphertext)

    expect(open(privateKey, publicKey, parsed)).toEqual(plaintext)
  })

  it('throws on under-length input', () => {
    expect(() => deserializeEnvelope(new Uint8Array(10))).toThrow(/too short/)
  })

  it('sealSerialized equals serializeEnvelope(seal(...)) and round-trips through open', () => {
    const { privateKey, publicKey } = generateX25519Keypair()
    const plaintext = new TextEncoder().encode('master key wrap')

    const wire = sealSerialized(publicKey, plaintext)
    // Same wire shape as the two-step form (fresh ephemeral/nonce, so only the
    // structure and round-trip are asserted, not byte-equality across calls).
    const parsed = deserializeEnvelope(wire)
    expect(parsed.schemeVersion).toBe(1)
    expect(parsed.ephemeralPublicKey.length).toBe(32)
    expect(open(privateKey, publicKey, parsed)).toEqual(plaintext)
  })
})

describe('hybrid uniqueness', () => {
  it('produces a distinct envelope for the same plaintext across calls (fresh ephemeral)', () => {
    const { publicKey } = generateX25519Keypair()
    const plaintext = new Uint8Array([1, 2, 3])
    const a = seal(publicKey, plaintext)
    const b = seal(publicKey, plaintext)
    expect(a.ephemeralPublicKey).not.toEqual(b.ephemeralPublicKey)
    expect(a.nonce).not.toEqual(b.nonce)
    expect(a.ciphertext).not.toEqual(b.ciphertext)
  })
})
