import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, it } from 'vitest'

import { signEd25519, verifyEd25519 } from '../signed-payload.js'
import {
  buildRecoveryAuthChallengePayload,
  buildRecoveryAuthMaterial,
  deriveRecoveryAuthKeypair,
  deriveRecoveryAuthPublicKey,
} from './ed25519-auth-from-mnemonic.js'
import { deriveRecoveryX25519PublicKey } from './x25519-from-mnemonic.js'

const RECOVERY_AUTH_MATERIAL_FIELDS = {
  newAuthPublicKey: Uint8Array.from({ length: 32 }, (_, i) => i + 1),
  newWrappedMasterKey: Uint8Array.from({ length: 80 }, (_, i) => (i * 3) & 0xff),
  newWrappedVaultKey: Uint8Array.from({ length: 72 }, (_, i) => (i * 5) & 0xff),
  newEncryptionSalt: Uint8Array.from({ length: 16 }, (_, i) => (i * 7) & 0xff),
  newAuthProofHash: Uint8Array.from({ length: 32 }, (_, i) => (i * 9) & 0xff),
  newPartialAuthHash: Uint8Array.from({ length: 32 }, (_, i) => (i * 11) & 0xff),
  newRecoveryPublicKey: Uint8Array.from({ length: 32 }, (_, i) => (i * 13) & 0xff),
  newRecoveryAuthPublicKey: Uint8Array.from({ length: 32 }, (_, i) => (i * 17) & 0xff),
  newWrappedMasterKeyVersion: 2,
  newWrappedVaultKeyVersion: 1,
}

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const toHex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('')

describe('deriveRecoveryAuthKeypair', () => {
  it('pins the derived public key — drift guard for the HKDF info tag', async () => {
    // If this fails, the derivation changed: every stored recovery-auth public key
    // would stop matching and recovering users would be locked out. Do NOT update
    // this vector to make a test pass — the constant must not change once keys exist.
    const { publicKey } = await deriveRecoveryAuthKeypair(MNEMONIC)
    expect(toHex(publicKey)).toBe(
      'cfc92eb1f72f6192d6225d82dd4214527c64e2cbfcfc5638a4dff553c3ef01a1',
    )
  })

  it('is deterministic for the same mnemonic', async () => {
    const a = await deriveRecoveryAuthKeypair(MNEMONIC)
    const b = await deriveRecoveryAuthKeypair(MNEMONIC)
    expect(toHex(a.publicKey)).toBe(toHex(b.publicKey))
    expect(toHex(a.privateKey)).toBe(toHex(b.privateKey))
  })

  it('is domain-separated from the X25519 recovery key of the same phrase', async () => {
    const { publicKey } = await deriveRecoveryAuthKeypair(MNEMONIC)
    const x25519 = await deriveRecoveryX25519PublicKey(MNEMONIC)
    expect(toHex(publicKey)).not.toBe(toHex(x25519))
  })

  it('produces a working signing key (sign → verify round-trips; tamper fails)', async () => {
    const { privateKey, publicKey } = await deriveRecoveryAuthKeypair(MNEMONIC)
    const message = new TextEncoder().encode('recovery-auth challenge')
    const signature = ed25519.sign(message, privateKey)
    expect(ed25519.verify(signature, message, publicKey)).toBe(true)
    const tampered = new TextEncoder().encode('recovery-auth challengX')
    expect(ed25519.verify(signature, tampered, publicKey)).toBe(false)
  })

  it('deriveRecoveryAuthPublicKey matches the keypair public half', async () => {
    const { publicKey } = await deriveRecoveryAuthKeypair(MNEMONIC)
    const pubOnly = await deriveRecoveryAuthPublicKey(MNEMONIC)
    expect(toHex(pubOnly)).toBe(toHex(publicKey))
  })

  it('signs a recovery-auth challenge bound to userId + challenge + new credentials', async () => {
    const { privateKey, publicKey } = await deriveRecoveryAuthKeypair(MNEMONIC)
    const challenge = new Uint8Array([1, 2, 3, 4])
    const newCredentials = new Uint8Array([9, 9, 9])

    const payload = buildRecoveryAuthChallengePayload('user-abc', challenge, newCredentials)
    const signature = signEd25519(privateKey, payload)
    expect(verifyEd25519(publicKey, payload, signature)).toBe(true)

    // Replaying the signature against a FRESH challenge fails (anti-replay).
    const replay = buildRecoveryAuthChallengePayload(
      'user-abc',
      new Uint8Array([5, 6, 7, 8]),
      newCredentials,
    )
    expect(verifyEd25519(publicKey, replay, signature)).toBe(false)

    // Relaying it to install DIFFERENT credentials fails (credential binding).
    const swapped = buildRecoveryAuthChallengePayload(
      'user-abc',
      challenge,
      new Uint8Array([1, 1, 1]),
    )
    expect(verifyEd25519(publicKey, swapped, signature)).toBe(false)

    // A different account fails.
    const otherUser = buildRecoveryAuthChallengePayload('user-xyz', challenge, newCredentials)
    expect(verifyEd25519(publicKey, otherUser, signature)).toBe(false)
  })
})

describe('buildRecoveryAuthMaterial', () => {
  it('is deterministic and frames all ten fields (length-prefixed)', () => {
    const a = buildRecoveryAuthMaterial(RECOVERY_AUTH_MATERIAL_FIELDS)
    const b = buildRecoveryAuthMaterial(RECOVERY_AUTH_MATERIAL_FIELDS)
    expect(toHex(a)).toBe(toHex(b))
    // 10 fields, each with a 4-byte length prefix:
    // 10*4 + (32+80+72+16+32+32+32 + 32[auth-pub] + 4[mk-ver] + 4[vk-ver]).
    expect(a.length).toBe(376)
  })

  it('is order-sensitive: swapping two equal-length fields changes the bytes', () => {
    const base = buildRecoveryAuthMaterial(RECOVERY_AUTH_MATERIAL_FIELDS)
    const swapped = buildRecoveryAuthMaterial({
      ...RECOVERY_AUTH_MATERIAL_FIELDS,
      // both 32 bytes — a bare concat would be identical; framing must not be
      newAuthProofHash: RECOVERY_AUTH_MATERIAL_FIELDS.newPartialAuthHash,
      newPartialAuthHash: RECOVERY_AUTH_MATERIAL_FIELDS.newAuthProofHash,
    })
    expect(toHex(base)).not.toBe(toHex(swapped))
  })

  it('round-trips through the signed payload, and tampering any field breaks it', async () => {
    const { privateKey, publicKey } = await deriveRecoveryAuthKeypair(MNEMONIC)
    const userId = 'user-abc'
    const challenge = new Uint8Array([1, 2, 3, 4])
    const material = buildRecoveryAuthMaterial(RECOVERY_AUTH_MATERIAL_FIELDS)
    const payload = buildRecoveryAuthChallengePayload(userId, challenge, material)
    const signature = signEd25519(privateKey, payload)
    expect(verifyEd25519(publicKey, payload, signature)).toBe(true)

    const tampered = buildRecoveryAuthMaterial({
      ...RECOVERY_AUTH_MATERIAL_FIELDS,
      newWrappedMasterKey: RECOVERY_AUTH_MATERIAL_FIELDS.newWrappedMasterKey.map((v) => v ^ 0x01),
    })
    const tamperedPayload = buildRecoveryAuthChallengePayload(userId, challenge, tampered)
    expect(verifyEd25519(publicKey, tamperedPayload, signature)).toBe(false)
  })
})
