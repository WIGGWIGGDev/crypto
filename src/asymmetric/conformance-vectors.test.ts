import { createDecipheriv } from 'node:crypto'

import { describe, expect, it } from 'vitest'
import { hchacha, xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js'

import { deserializeEnvelope, open } from './hybrid.js'
import {
  ENVELOPE_STORAGE_SCHEME,
  ENVELOPE_E_B64,
  ENVELOPE_MESSAGE_PREVIEW,
  ENVELOPE_N_B64,
  ENVELOPE_RECIPIENT_PRIVATE_B64,
  ENVELOPE_RECIPIENT_PUBLIC_B64,
  ENVELOPE_SENDER_NUMBER,
  ENVELOPE_SK_B64,
  ENVELOPE_T_B64,
  HCHACHA20_RFC_EXPECTED_HEX,
  HCHACHA20_RFC_INPUT_HEX,
  HCHACHA20_RFC_KEY_HEX,
  XCHACHA_CIPHERTEXT_HEX,
  XCHACHA_KEY_HEX,
  XCHACHA_NONCE_HEX,
  XCHACHA_PLAINTEXT_HEX,
} from './conformance-vectors.js'

// HChaCha20 operates on little-endian 32-bit words; convert at the hex boundary.
function leWords(hex: string): Uint32Array {
  const bytes = hexToBytes(hex)
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const words = new Uint32Array(bytes.length / 4)
  for (let i = 0; i < words.length; i++) words[i] = view.getUint32(i * 4, true)
  return words
}

function leBytes(words: Uint32Array): Uint8Array {
  const bytes = new Uint8Array(words.length * 4)
  const view = new DataView(bytes.buffer)
  for (const [i, word] of words.entries()) view.setUint32(i * 4, word, true)
  return bytes
}

// Pins the canonical XChaCha20-Poly1305 interop vector against the SAME primitive
// this package seals with (@noble/ciphers). The Swift and Kotlin known-answer tests
// cite the SAME hex from conformance-vectors.ts — this is the anchor that keeps every
// hybrid-scheme port from drifting.
describe('hybrid conformance vectors (canonical for native ports)', () => {
  it('opens the canonical @noble XChaCha20-Poly1305 interop vector', () => {
    const aead = xchacha20poly1305(hexToBytes(XCHACHA_KEY_HEX), hexToBytes(XCHACHA_NONCE_HEX))
    const plaintext = aead.decrypt(hexToBytes(XCHACHA_CIPHERTEXT_HEX))
    expect(bytesToHex(plaintext)).toBe(XCHACHA_PLAINTEXT_HEX)
  })

  it('fails closed on a tampered ciphertext (Poly1305 tag mismatch)', () => {
    const bad = hexToBytes(XCHACHA_CIPHERTEXT_HEX)
    const last = bad.length - 1
    const lastByte = bad[last]
    if (lastByte !== undefined) bad[last] = lastByte ^ 0x01
    const aead = xchacha20poly1305(hexToBytes(XCHACHA_KEY_HEX), hexToBytes(XCHACHA_NONCE_HEX))
    expect(() => aead.decrypt(bad)).toThrow()
  })

  // The Swift/Kotlin ports hand-roll HChaCha20 (CryptoKit/BouncyCastle lack
  // extended-nonce ChaCha); @noble exposes `hchacha`, so TS pins the SAME
  // RFC draft-irtf-cfrg-xchacha-03 §2.2.1 known-answer here too — a typo'd
  // EXPECTED hex now fails in this suite, not only in the native KATs.
  it('derives the RFC HChaCha20 subkey (anchors the native hand-rolled ports)', () => {
    // "expand 32-byte k" sigma constants as little-endian 32-bit words.
    const sigma = Uint32Array.of(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
    const out = new Uint32Array(8)
    hchacha(sigma, leWords(HCHACHA20_RFC_KEY_HEX), leWords(HCHACHA20_RFC_INPUT_HEX), out)
    expect(bytesToHex(leBytes(out))).toBe(HCHACHA20_RFC_EXPECTED_HEX)
  })
})

// The full ENVELOPE vector — the layer the primitive KATs can't see (scheme
// dispatch, wire offsets, HKDF salt/info, base64, 16-byte-IV AES-GCM, UTF-8).
// This is the SAME committed envelope the Swift and Kotlin KATs decrypt
// through their real production decrypt path; opening it here proves the
// committed bytes stay openable by the canonical TS sealer's twin.
describe('canonical envelope vector (canonical for native ports)', () => {
  const b64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'))

  it('pins the two version namespaces apart', () => {
    // The storage-level scheme id a port dispatches on (2 = X25519 sealed box)…
    expect(ENVELOPE_STORAGE_SCHEME).toBe(2)
    // …is NOT the serialized envelope's first byte (hybrid.ts
    // ASYMMETRIC_SCHEME_CURRENT_VERSION = 1). Comparing byte 0 against the
    // storage scheme would make nothing decryptable.
    expect(b64(ENVELOPE_SK_B64)[0]).toBe(1)
  })

  it('unwraps the session key and decrypts the payload byte-for-byte', () => {
    const sessionKey = open(
      b64(ENVELOPE_RECIPIENT_PRIVATE_B64),
      b64(ENVELOPE_RECIPIENT_PUBLIC_B64),
      deserializeEnvelope(b64(ENVELOPE_SK_B64)),
    )
    expect(sessionKey.length).toBe(32)

    const decipher = createDecipheriv('aes-256-gcm', sessionKey, b64(ENVELOPE_N_B64))
    decipher.setAuthTag(b64(ENVELOPE_T_B64))
    const plaintext = Buffer.concat([
      decipher.update(b64(ENVELOPE_E_B64)),
      decipher.final(),
    ]).toString('utf8')

    const parsed: unknown = JSON.parse(plaintext)
    expect(parsed).toEqual({
      senderNumber: ENVELOPE_SENDER_NUMBER,
      messagePreview: ENVELOPE_MESSAGE_PREVIEW,
    })
  })

  it('fails closed when the wrapped session key is tampered', () => {
    const tampered = b64(ENVELOPE_SK_B64)
    const last = tampered.length - 1
    const lastByte = tampered[last]
    if (lastByte !== undefined) tampered[last] = lastByte ^ 0x01
    expect(() =>
      open(
        b64(ENVELOPE_RECIPIENT_PRIVATE_B64),
        b64(ENVELOPE_RECIPIENT_PUBLIC_B64),
        deserializeEnvelope(tampered),
      ),
    ).toThrow()
  })
})
