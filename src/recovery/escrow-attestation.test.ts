import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, it } from 'vitest'

import { signEd25519, verifyEd25519 } from '../signed-payload.js'
import {
  buildEscrowAttestationMaterial,
  buildEscrowAttestationPayload,
  ESCROW_ATTESTATION_DOMAIN,
  type EscrowAttestationFields,
} from './escrow-attestation.js'

// Deterministic test keypair (a fixed 32-byte seed — the real key is derived from
// the recovery phrase via deriveRecoveryAuthKeypair, tested separately).
const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 1)
const publicKey = ed25519.getPublicKey(seed)
const otherPublicKey = ed25519.getPublicKey(Uint8Array.from({ length: 32 }, (_, i) => i + 100))

const fields: EscrowAttestationFields = {
  userId: 'user-123',
  wrappedMasterKey: new Uint8Array([1, 2, 3, 4]),
  wrappedMasterKeyVersion: 2,
  vaultKeyCommitment: new Uint8Array([9, 9, 9, 9]),
  recoveryX25519Public: new Uint8Array([5, 6, 7, 8]),
  integrityRequiredEpoch: 42,
}

// ── Independent framing oracle (not the production helpers) ──────────────────
const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))
const u32 = (n: number): number[] => [
  (n >>> 24) & 0xff,
  (n >>> 16) & 0xff,
  (n >>> 8) & 0xff,
  n & 0xff,
]
const u64 = (n: number): number[] => [0, 0, 0, 0, ...u32(n)]
const frame = (parts: number[][]): number[] => parts.flatMap((p) => [...u32(p.length), ...p])

describe('buildEscrowAttestationMaterial / Payload — framing', () => {
  it('frames the escrow fields with u32 length prefixes in the fixed order', () => {
    const expected = frame([[1, 2, 3, 4], u32(2), [9, 9, 9, 9], [5, 6, 7, 8], u64(42)])
    expect([...buildEscrowAttestationMaterial(fields)]).toEqual(expected)
  })

  it('builds a domain-tagged payload: utf8(domain) 0x00 userId 0x00 material', () => {
    const material = [...buildEscrowAttestationMaterial(fields)]
    const expected = [...ascii(ESCROW_ATTESTATION_DOMAIN), 0, ...ascii('user-123'), 0, ...material]
    expect([...buildEscrowAttestationPayload(fields)]).toEqual(expected)
  })

  it('is deterministic', () => {
    expect([...buildEscrowAttestationPayload(fields)]).toEqual([
      ...buildEscrowAttestationPayload(fields),
    ])
  })

  it('treats integrityRequiredEpoch as a number or the equivalent bigint identically', () => {
    expect([...buildEscrowAttestationPayload({ ...fields, integrityRequiredEpoch: 42 })]).toEqual([
      ...buildEscrowAttestationPayload({ ...fields, integrityRequiredEpoch: 42n }),
    ])
  })
})

describe('escrow attestation — sign / verify', () => {
  const sign = (f: EscrowAttestationFields): Uint8Array =>
    signEd25519(seed, buildEscrowAttestationPayload(f))
  const verify = (f: EscrowAttestationFields, sig: Uint8Array): boolean =>
    verifyEd25519(publicKey, buildEscrowAttestationPayload(f), sig)

  it('verifies a signature the phrase key produced over the escrow', () => {
    expect(verify(fields, sign(fields))).toBe(true)
  })

  it('fails verification under a different (non-phrase) public key', () => {
    const sig = sign(fields)
    expect(verifyEd25519(otherPublicKey, buildEscrowAttestationPayload(fields), sig)).toBe(false)
  })

  // Every field must be covered: a server that swaps ANY of them must invalidate
  // the phrase-holder's signature. Sign the honest fields once, then verify the
  // signature against each single-field mutation.
  const tampers: ReadonlyArray<readonly [string, EscrowAttestationFields]> = [
    ['userId', { ...fields, userId: 'user-999' }],
    [
      'wrappedMasterKey (escrow swap)',
      { ...fields, wrappedMasterKey: new Uint8Array([1, 2, 3, 5]) },
    ],
    ['wrappedMasterKeyVersion (v2→v1 downgrade)', { ...fields, wrappedMasterKeyVersion: 1 }],
    [
      'vaultKeyCommitment (forged HMAC)',
      { ...fields, vaultKeyCommitment: new Uint8Array([9, 9, 9, 8]) },
    ],
    [
      'recoveryX25519Public (substitution)',
      { ...fields, recoveryX25519Public: new Uint8Array([5, 6, 7, 9]) },
    ],
    [
      'integrityRequiredEpoch (anti-downgrade latch stripped to 0)',
      { ...fields, integrityRequiredEpoch: 0 },
    ],
  ]

  for (const [label, tampered] of tampers) {
    it(`rejects a tampered ${label}`, () => {
      const honestSig = sign(fields)
      expect(verify(tampered, honestSig)).toBe(false)
    })
  }
})
