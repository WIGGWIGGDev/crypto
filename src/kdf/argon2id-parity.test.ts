/**
 * Argon2id determinism vectors.
 *
 * Argon2id must produce byte-identical output for the same (password, salt,
 * params) on every implementation the clients route through, or a user who
 * derives their key on one device can't unlock on another. These vectors pin the
 * @noble/hashes output (the JS reference path); a native implementation is
 * checked by running the same inputs and comparing bytes.
 */

import { describe, expect, it } from 'vitest'

import { argon2id } from './argon2id.js'
import { ARGON2_MASTER_PARAMS, ARGON2_PIN_PARAMS } from '../params.js'

// 16-byte salt, the RFC 9106 minimum recommended length. Fixed for determinism.
const FIXED_SALT = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
])

// 32-byte salt, the size the clients actually generate. Both lengths are
// exercised because some Argon2 wrappers accept only 16-byte salts.
const FIXED_SALT_32 = new Uint8Array([
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
])

const PASSWORD_ASCII = new TextEncoder().encode('correct horse battery staple')

// Small params so the suite stays fast; the production master and PIN params
// take about a second each. Their shapes are pinned separately below.
const TEST_PARAMS = {
  memKiB: 64,
  iterations: 2,
  parallelism: 1,
  outputLen: 32,
} as const

describe('argon2id determinism', () => {
  // Canonical cross-platform anchor. This @noble (web) output for the PRODUCTION
  // master params (PASSWORD_ASCII + FIXED_SALT_32 + ARGON2_MASTER_PARAMS) MUST
  // equal what the native ports produce, or a user who derives their key on web
  // cannot unwrap their vault on mobile. The native ports pin this same hex in
  // their own known-answer tests. Change it only when @noble/hashes is
  // intentionally bumped AND both native
  // ports are re-validated against the new bytes.
  const MASTER_KAT_EXPECTED_HEX = 'fcdf988e6b17b6f2a5eb5a4a0962cecef3991e960aa1c6cbb8da66ec03ccb7be'

  // ARGON2_MASTER_PARAMS is memory-hard (128 MiB) and intentionally ~1s; under a
  // loaded test run the memory/CPU contention can push a single
  // derivation past vitest's default 5s. Give it a generous explicit timeout so
  // this deterministic KAT can't flake on load.
  it('master params match the cross-platform reference (web anchor for native KATs)', async () => {
    const out = await argon2id(PASSWORD_ASCII, FIXED_SALT_32, ARGON2_MASTER_PARAMS)
    expect(Buffer.from(out).toString('hex')).toBe(MASTER_KAT_EXPECTED_HEX)
  }, 60_000)

  it('produces stable bytes for an ascii password and 16-byte salt', async () => {
    const out = await argon2id(PASSWORD_ASCII, FIXED_SALT, TEST_PARAMS)
    // Pinned @noble/hashes output. A change here means an implementation has
    // diverged from the baseline, which breaks anyone holding a key derived
    // under the old one. Update it only when @noble/hashes is intentionally
    // bumped and every platform has been re-validated.
    const expected = new Uint8Array([
      0x2d, 0xf4, 0x7e, 0xde, 0x63, 0x58, 0xed, 0x17, 0xa9, 0x97, 0x6d, 0x4f, 0xce, 0xdb, 0x89,
      0x7a, 0x10, 0x03, 0x6d, 0x43, 0x2a, 0x4a, 0xce, 0xf1, 0x7d, 0x26, 0x3b, 0xfc, 0x98, 0xbd,
      0x20, 0xac,
    ])
    expect([...out]).toEqual([...expected])
  })

  it('produces stable bytes for an ascii password and 32-byte salt', async () => {
    const out = await argon2id(PASSWORD_ASCII, FIXED_SALT_32, TEST_PARAMS)
    const expected = new Uint8Array([
      0xaa, 0xce, 0x19, 0xc7, 0x83, 0xa7, 0x47, 0x78, 0xa8, 0x54, 0x80, 0x3b, 0x2c, 0x46, 0xf8,
      0x63, 0x27, 0xdb, 0xe4, 0x41, 0xf7, 0xf3, 0x24, 0x93, 0x66, 0xd5, 0xf0, 0x7c, 0x6e, 0x7b,
      0x59, 0xc0,
    ])
    expect([...out]).toEqual([...expected])
  })

  it('treats a different salt size as different output (catches naive truncation)', async () => {
    const out16 = await argon2id(PASSWORD_ASCII, FIXED_SALT, TEST_PARAMS)
    const out32 = await argon2id(PASSWORD_ASCII, FIXED_SALT_32, TEST_PARAMS)
    expect([...out16]).not.toEqual([...out32])
  })

  it('pins the production master params', () => {
    // These must stay byte-identical across implementations; changing them
    // invalidates every key derived under the old values.
    expect(ARGON2_MASTER_PARAMS).toEqual({
      memKiB: 131_072, // 128 MiB
      iterations: 3,
      parallelism: 1,
      outputLen: 32,
    })
  })

  it('pins the production PIN params', () => {
    expect(ARGON2_PIN_PARAMS).toEqual({
      memKiB: 65_536, // 64 MiB
      iterations: 3,
      parallelism: 1,
      outputLen: 32,
    })
  })
})
