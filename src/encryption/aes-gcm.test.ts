import { createCipheriv, randomBytes } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { decrypt, decryptSplit, encrypt, encryptSplit } from './aes-gcm.js'

describe('aes-gcm', () => {
  const key = new Uint8Array(32).fill(0x42)

  it('encrypt/decrypt round-trips arbitrary bytes', () => {
    const plaintext = new TextEncoder().encode('hello, vault')
    const { ciphertext, nonce } = encrypt(key, plaintext)
    const decrypted = decrypt(key, ciphertext, nonce)
    expect(new TextDecoder().decode(decrypted)).toBe('hello, vault')
  })

  it('ciphertext includes the 16-byte AEAD tag', () => {
    const plaintext = new Uint8Array([1, 2, 3, 4, 5])
    const { ciphertext } = encrypt(key, plaintext)
    expect(ciphertext.length).toBe(plaintext.length + 16)
  })

  it('uses a fresh nonce per call', () => {
    const plaintext = new TextEncoder().encode('same plaintext')
    const a = encrypt(key, plaintext)
    const b = encrypt(key, plaintext)
    expect(a.nonce).not.toEqual(b.nonce)
    expect(a.ciphertext).not.toEqual(b.ciphertext)
  })

  it('encryptSplit produces a 16-byte tag and ciphertext-without-tag', () => {
    const plaintext = new Uint8Array([10, 20, 30])
    const { ciphertext, nonce, tag } = encryptSplit(key, plaintext)
    expect(tag.length).toBe(16)
    expect(ciphertext.length).toBe(plaintext.length)
    expect(nonce.length).toBe(12)
  })

  it('decryptSplit reverses encryptSplit', () => {
    const plaintext = new TextEncoder().encode('split-mode payload')
    const { ciphertext, nonce, tag } = encryptSplit(key, plaintext)
    const decrypted = decryptSplit(key, ciphertext, nonce, tag)
    expect(new TextDecoder().decode(decrypted)).toBe('split-mode payload')
  })

  it('decrypt fails on tampered ciphertext', () => {
    const plaintext = new TextEncoder().encode("don't tamper with me")
    const { ciphertext, nonce } = encrypt(key, plaintext)
    const tampered = new Uint8Array(ciphertext)
    tampered[0] = (tampered[0] ?? 0) ^ 0xff
    expect(() => decrypt(key, tampered, nonce)).toThrow()
  })

  it('decrypt fails on wrong key', () => {
    const plaintext = new TextEncoder().encode('authentic')
    const { ciphertext, nonce } = encrypt(key, plaintext)
    const wrongKey = new Uint8Array(32).fill(0x99)
    expect(() => decrypt(wrongKey, ciphertext, nonce)).toThrow()
  })

  it('AAD must match between encrypt and decrypt', () => {
    const plaintext = new TextEncoder().encode('aad-bound')
    const aad = new TextEncoder().encode('context-v1')
    const { ciphertext, nonce } = encrypt(key, plaintext, aad)
    const decrypted = decrypt(key, ciphertext, nonce, aad)
    expect(new TextDecoder().decode(decrypted)).toBe('aad-bound')

    expect(() => decrypt(key, ciphertext, nonce)).toThrow()
    expect(() => decrypt(key, ciphertext, nonce, new TextEncoder().encode('wrong'))).toThrow()
  })

  it('rejects malformed inputs', () => {
    const plaintext = new Uint8Array([1, 2, 3])
    expect(() => encrypt(new Uint8Array(31), plaintext)).toThrow()
    const { ciphertext } = encrypt(key, plaintext)
    expect(() => decrypt(key, ciphertext, new Uint8Array(11))).toThrow()
    expect(() =>
      decryptSplit(key, ciphertext.slice(0, -16), new Uint8Array(12), new Uint8Array(15)),
    ).toThrow()
  })

  // Some producers emit a 16-byte GCM IV (Node `createCipheriv` default style)
  // rather than the 12-byte nonce this module writes. `decrypt` MUST accept both
  // sizes, or every such ciphertext fails with "nonce must be 12 bytes, got 16".
  it('decrypts a 16-byte-IV ciphertext produced by Node createCipheriv', () => {
    const sessionKey = randomBytes(32)
    const iv16 = randomBytes(16)
    const message = 'hey, this is a message body'
    const cipher = createCipheriv('aes-256-gcm', sessionKey, iv16)
    const ct = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()

    const keyBytes = new Uint8Array(sessionKey)
    const out = decryptSplit(
      keyBytes,
      new Uint8Array(ct),
      new Uint8Array(iv16),
      new Uint8Array(tag),
    )
    expect(new TextDecoder().decode(out)).toBe(message)

    // 12-byte IVs (vault / noble-origin) still work …
    const enc = encryptSplit(keyBytes, new TextEncoder().encode('vault payload'))
    expect(
      new TextDecoder().decode(decryptSplit(keyBytes, enc.ciphertext, enc.nonce, enc.tag)),
    ).toBe('vault payload')
    // … and an unsupported length (e.g. 11) is still rejected.
    expect(() => decrypt(keyBytes, new Uint8Array(ct), new Uint8Array(11))).toThrow()
  })
})
