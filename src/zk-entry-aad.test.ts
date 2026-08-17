import { describe, expect, it } from 'vitest'

import {
  buildEntryAad,
  buildEntryAadV2,
  ZK2_NO_PARENT,
  type EntryAadV2Params,
} from './zk-entry-aad.js'

// ── Independent framing oracle ──────────────────────────────────────────────
// Re-implements the u32-length-prefix framing from first principles (NOT via the
// production lengthPrefixedConcat/u32be/u64be), so if the production composition
// drifts, the known-answer test below catches it instead of both moving together.
const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))
const u32 = (n: number): number[] => [
  (n >>> 24) & 0xff,
  (n >>> 16) & 0xff,
  (n >>> 8) & 0xff,
  n & 0xff,
]
const u64 = (n: number): number[] => [0, 0, 0, 0, ...u32(n)] // only used for small versions here
const frame = (parts: number[][]): number[] => parts.flatMap((p) => [...u32(p.length), ...p])

const base: EntryAadV2Params = {
  entryType: 'password',
  entryId: 'e1',
  entryVersion: 1,
  parentId: 'p1',
}

describe('buildEntryAadV2 — known-answer vectors', () => {
  it('frames [zk2, type, id, u64be(version), parent] with u32 length prefixes', () => {
    const expected = frame([ascii('zk2'), ascii('password'), ascii('e1'), u64(1), ascii('p1')])
    expect([...buildEntryAadV2(base)]).toEqual(expected)
  })

  it('leads with the length-prefixed "zk2" scheme tag (0,0,0,3, z,k,2)', () => {
    expect([...buildEntryAadV2(base)].slice(0, 7)).toEqual([0, 0, 0, 3, 122, 107, 50])
  })

  it('can never collide with a zk1 blob (zk1 has no length prefix, starts with "zk1:")', () => {
    // zk1 wire is UTF-8 of `zk1:password:e1` — starts with byte 122 ('z').
    // zk2 starts with a u32 length prefix (0,0,0,3), so the byte strings are
    // structurally disjoint and a zk1 ciphertext can never be replayed as zk2.
    const zk1Bytes = ascii('zk1:password:e1')
    expect([...buildEntryAadV2(base)]).not.toEqual(zk1Bytes)
    expect(buildEntryAadV2(base)[0]).not.toBe(zk1Bytes[0])
  })

  it('returns an ArrayBuffer-backed view (Web Crypto additionalData requirement)', () => {
    expect(buildEntryAadV2(base).buffer).toBeInstanceOf(ArrayBuffer)
  })
})

describe('buildEntryAadV2 — security-relevant bindings', () => {
  it('is deterministic for identical inputs', () => {
    expect([...buildEntryAadV2(base)]).toEqual([...buildEntryAadV2(base)])
  })

  it('binds the entry version — a rolled-back version yields different AAD (auth fails on stale blob)', () => {
    expect([...buildEntryAadV2({ ...base, entryVersion: 7 })]).not.toEqual([
      ...buildEntryAadV2({ ...base, entryVersion: 4 }),
    ])
  })

  it('binds parentId — a re-parented entry yields different AAD (auth fails on moved blob)', () => {
    expect([...buildEntryAadV2({ ...base, parentId: 'identity-a' })]).not.toEqual([
      ...buildEntryAadV2({ ...base, parentId: 'identity-b' }),
    ])
  })

  it('distinguishes the no-parent sentinel from a real parent', () => {
    expect([...buildEntryAadV2({ ...base, parentId: ZK2_NO_PARENT })]).not.toEqual([
      ...buildEntryAadV2({ ...base, parentId: 'p1' }),
    ])
  })

  it('binds entry type and id (per-entry, per-type distinct)', () => {
    expect([...buildEntryAadV2({ ...base, entryType: 'note' })]).not.toEqual([
      ...buildEntryAadV2(base),
    ])
    expect([...buildEntryAadV2({ ...base, entryId: 'e2' })]).not.toEqual([...buildEntryAadV2(base)])
  })

  it('treats version as a number or the equivalent bigint identically', () => {
    expect([...buildEntryAadV2({ ...base, entryVersion: 258 })]).toEqual([
      ...buildEntryAadV2({ ...base, entryVersion: 258n }),
    ])
  })

  it('accepts a 64-bit version beyond the safe-integer range (bigint) and binds it distinctly', () => {
    const huge = buildEntryAadV2({ ...base, entryVersion: 9007199254740993n })
    expect([...huge]).not.toEqual([...buildEntryAadV2({ ...base, entryVersion: 1 })])
    // the u64be field is 8 bytes; total length is unchanged by the version's magnitude
    expect(huge.length).toBe(buildEntryAadV2(base).length)
  })

  it('is not boundary-ambiguous: (type=ab,id=c) and (type=a,id=bc) frame differently', () => {
    expect([...buildEntryAadV2({ ...base, entryType: 'ab', entryId: 'c' })]).not.toEqual([
      ...buildEntryAadV2({ ...base, entryType: 'a', entryId: 'bc' }),
    ])
  })
})

describe('buildEntryAad — FROZEN zk1 wire format (byte-pinned)', () => {
  // A byte-exact known-answer against an independent oracle, so no implementation can drift
  // from the wire spec that existing ciphertexts depend on. `zk1:...` is pure ASCII, so
  // `ascii()` yields the exact UTF-8 bytes.
  it('is the UTF-8 of `zk1:<type>:<id>` (exact bytes)', () => {
    expect([...buildEntryAad('password', 'v1')]).toEqual(ascii('zk1:password:v1'))
  })

  it('is deterministic and per-type / per-id distinct', () => {
    expect([...buildEntryAad('password', 'a')]).toEqual([...buildEntryAad('password', 'a')])
    expect([...buildEntryAad('password', 'a')]).not.toEqual([...buildEntryAad('password', 'b')])
    expect([...buildEntryAad('password', 'a')]).not.toEqual([...buildEntryAad('note', 'a')])
  })

  it('returns an ArrayBuffer-backed view (Web Crypto additionalData requirement)', () => {
    expect(buildEntryAad('password', 'v1').buffer).toBeInstanceOf(ArrayBuffer)
  })

  it('is structurally disjoint from any zk2 AAD (zk1 starts with "z", zk2 with a u32 length)', () => {
    expect(buildEntryAad('password', 'e1')[0]).not.toBe(buildEntryAadV2(base)[0])
  })
})
