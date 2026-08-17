import { describe, expect, it } from 'vitest'

import {
  deriveX25519KeypairFromSecret,
  generateX25519Keypair,
  x25519Ecdh,
  x25519PublicFromPrivate,
} from './x25519.js'

describe('deriveX25519KeypairFromSecret', () => {
  const secret = new Uint8Array(32).fill(7)

  it('produces 32-byte components whose public key matches the private', () => {
    const kp = deriveX25519KeypairFromSecret(secret, 'wiggwigg-test-v1')
    expect(kp.privateKey.length).toBe(32)
    expect(kp.publicKey.length).toBe(32)
    expect(kp.publicKey).toEqual(x25519PublicFromPrivate(kp.privateKey))
  })

  it('is deterministic for the same secret + info', () => {
    const a = deriveX25519KeypairFromSecret(secret, 'wiggwigg-test-v1')
    const b = deriveX25519KeypairFromSecret(secret, 'wiggwigg-test-v1')
    expect(a.privateKey).toEqual(b.privateKey)
    expect(a.publicKey).toEqual(b.publicKey)
  })

  it('is domain-separated by info — a different info yields a different key', () => {
    const a = deriveX25519KeypairFromSecret(secret, 'wiggwigg-purpose-a-v1')
    const b = deriveX25519KeypairFromSecret(secret, 'wiggwigg-purpose-b-v1')
    expect(a.privateKey).not.toEqual(b.privateKey)
    expect(a.publicKey).not.toEqual(b.publicKey)
  })

  it('is secret-specific — a different secret yields a different key', () => {
    const a = deriveX25519KeypairFromSecret(secret, 'wiggwigg-test-v1')
    const b = deriveX25519KeypairFromSecret(new Uint8Array(32).fill(9), 'wiggwigg-test-v1')
    expect(a.publicKey).not.toEqual(b.publicKey)
  })

  it('accepts a string or pre-encoded info identically', () => {
    const str = deriveX25519KeypairFromSecret(secret, 'wiggwigg-test-v1')
    const bytes = deriveX25519KeypairFromSecret(
      secret,
      new TextEncoder().encode('wiggwigg-test-v1'),
    )
    expect(str.privateKey).toEqual(bytes.privateKey)
  })
})

describe('x25519', () => {
  it('generateX25519Keypair produces 32-byte components', () => {
    const { privateKey, publicKey } = generateX25519Keypair()
    expect(privateKey.length).toBe(32)
    expect(publicKey.length).toBe(32)
  })

  it('x25519PublicFromPrivate is deterministic', () => {
    const { privateKey } = generateX25519Keypair()
    const p1 = x25519PublicFromPrivate(privateKey)
    const p2 = x25519PublicFromPrivate(privateKey)
    expect(p1).toEqual(p2)
  })

  it('ECDH is commutative (Alice.priv × Bob.pub == Bob.priv × Alice.pub)', () => {
    const alice = generateX25519Keypair()
    const bob = generateX25519Keypair()
    const ab = x25519Ecdh(alice.privateKey, bob.publicKey)
    const ba = x25519Ecdh(bob.privateKey, alice.publicKey)
    expect(ab).toEqual(ba)
  })

  it('rejects malformed key lengths', () => {
    expect(() => x25519Ecdh(new Uint8Array(31), new Uint8Array(32))).toThrow()
    expect(() => x25519Ecdh(new Uint8Array(32), new Uint8Array(31))).toThrow()
    expect(() => x25519PublicFromPrivate(new Uint8Array(31))).toThrow()
  })
})
