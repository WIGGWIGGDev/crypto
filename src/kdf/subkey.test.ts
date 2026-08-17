import { describe, it, expect } from 'vitest'

import { deriveSubkey } from './subkey.js'

const KEY = new Uint8Array(32).fill(0x11)

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

describe('deriveSubkey', () => {
  it('returns 32 bytes', () => {
    expect(deriveSubkey(KEY, 'ctx').length).toBe(32)
  })

  it('is deterministic (same key + label → same subkey)', () => {
    expect(toHex(deriveSubkey(KEY, 'purpose-a-v1'))).toBe(toHex(deriveSubkey(KEY, 'purpose-a-v1')))
  })

  it('domain-separates: different labels → different subkeys', () => {
    expect(toHex(deriveSubkey(KEY, 'purpose-a-v1'))).not.toBe(
      toHex(deriveSubkey(KEY, 'purpose-b-v1')),
    )
  })

  it('depends on the key: different keys → different subkeys', () => {
    const otherKey = new Uint8Array(32).fill(0x22)
    expect(toHex(deriveSubkey(KEY, 'ctx'))).not.toBe(toHex(deriveSubkey(otherKey, 'ctx')))
  })

  it('known-answer vector locks the byte format (cross-platform parity anchor)', () => {
    // HMAC-SHA256(key=0x11*32, "purpose-a-v1"). Pinning the exact bytes catches an
    // accidental algorithm/encoding change that would silently strand a subkey
    // derived on one platform from unsealing what another sealed.
    expect(toHex(deriveSubkey(KEY, 'purpose-a-v1'))).toBe(
      '1c1fc4b2582470a8ae3ff014f8b1f6f889744a233f8843b28d65fae3eacb3461',
    )
  })
})
