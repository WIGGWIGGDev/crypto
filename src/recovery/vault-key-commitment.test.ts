import { describe, expect, it } from 'vitest'

import { bytesEqual } from '../bytes.js'
import { computeVaultKeyCommitment } from './vault-key-commitment.js'

const toHex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('')

const V = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 1) & 0xff)
// KAT — the commitment for the fixed vault key above. Pins the label +
// construction: if this changes, every stored v2 vault-key commitment stops
// matching and v2 recovery aborts. Do NOT edit it to make a test pass.
const EXPECTED_HEX = 'b43cb023afbca75fe11372b9f2b22d4d0b3f155bbb74ec8b6dc4849cc5e433f0'

describe('computeVaultKeyCommitment', () => {
  it('is a deterministic 32-byte commitment matching the pinned KAT', () => {
    const a = computeVaultKeyCommitment(V)
    const b = computeVaultKeyCommitment(V)
    expect(a.length).toBe(32)
    expect(bytesEqual(a, b)).toBe(true)
    expect(toHex(a)).toBe(EXPECTED_HEX)
  })

  it('changes when the vault key changes (a wrong/substituted V is detectable)', () => {
    const other = Uint8Array.from(V, (v, i) => (i === 0 ? v ^ 0x01 : v))
    expect(bytesEqual(computeVaultKeyCommitment(V), computeVaultKeyCommitment(other))).toBe(false)
  })

  it('does not equal the raw key (it is a one-way commitment, not the key)', () => {
    expect(bytesEqual(computeVaultKeyCommitment(V), V)).toBe(false)
  })
})
