import { describe, expect, it } from 'vitest'

import { bytesEqual, lengthPrefixedConcat, u32be, u64be } from './bytes.js'

const bytesAreEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i])

describe('bytesEqual', () => {
  it('is true for identical byte arrays', () => {
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true)
  })

  it('is true for two empty arrays', () => {
    expect(bytesEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true)
  })

  it('is false for same-length arrays differing in the middle', () => {
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 9, 3]))).toBe(false)
  })

  it('is false when only the last byte differs', () => {
    expect(bytesEqual(new Uint8Array([0, 0, 0]), new Uint8Array([0, 0, 1]))).toBe(false)
  })

  it('is false for different-length arrays', () => {
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false)
  })
})

describe('lengthPrefixedConcat', () => {
  it('prefixes each field with its big-endian u32 length', () => {
    const out = lengthPrefixedConcat([new Uint8Array([0xaa, 0xbb]), new Uint8Array([0xcc])])
    expect([...out]).toEqual([0, 0, 0, 2, 0xaa, 0xbb, 0, 0, 0, 1, 0xcc])
  })

  it('frames a single empty field as its length prefix alone', () => {
    expect([...lengthPrefixedConcat([new Uint8Array(0)])]).toEqual([0, 0, 0, 0])
  })

  it('differs from a bare concatenation of the same bytes', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([4, 5])
    expect(bytesAreEqual(lengthPrefixedConcat([a, b]), new Uint8Array([...a, ...b]))).toBe(false)
  })

  it('distinguishes different field splits of the same concatenated payload (ambiguity attack)', () => {
    // a'‖b' == a‖b but the split differs: length prefixes must make the two
    // frame to different bytes so a shifted-boundary credential swap fails.
    const split1 = lengthPrefixedConcat([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])])
    const split2 = lengthPrefixedConcat([new Uint8Array([1, 2]), new Uint8Array([3, 4, 5, 6])])
    expect(bytesAreEqual(split1, split2)).toBe(false)
  })

  it('is deterministic', () => {
    const parts = [new Uint8Array([7, 8]), new Uint8Array([9])]
    expect(bytesAreEqual(lengthPrefixedConcat(parts), lengthPrefixedConcat(parts))).toBe(true)
  })
})

describe('u32be', () => {
  it('encodes 0 as four zero bytes', () => {
    expect([...u32be(0)]).toEqual([0, 0, 0, 0])
  })

  it('encodes 1 in big-endian order', () => {
    expect([...u32be(1)]).toEqual([0, 0, 0, 1])
  })

  it('encodes the max u32 as four 0xff bytes', () => {
    expect([...u32be(0xffffffff)]).toEqual([0xff, 0xff, 0xff, 0xff])
  })

  it('encodes a mixed value big-endian', () => {
    expect([...u32be(0x01020304)]).toEqual([0x01, 0x02, 0x03, 0x04])
  })

  it('rejects a negative value', () => {
    expect(() => u32be(-1)).toThrow()
  })

  it('rejects a value above the u32 range', () => {
    expect(() => u32be(0x1_0000_0000)).toThrow()
  })

  it('rejects a non-integer', () => {
    expect(() => u32be(1.5)).toThrow()
  })
})

describe('u64be', () => {
  it('encodes 0 as eight zero bytes', () => {
    expect([...u64be(0)]).toEqual([0, 0, 0, 0, 0, 0, 0, 0])
  })

  it('encodes 1 in big-endian order', () => {
    expect([...u64be(1)]).toEqual([0, 0, 0, 0, 0, 0, 0, 1])
  })

  it('encodes a number and the equivalent bigint identically', () => {
    expect([...u64be(258)]).toEqual([...u64be(258n)])
    expect([...u64be(258)]).toEqual([0, 0, 0, 0, 0, 0, 1, 2])
  })

  it('encodes a bigint above 2^53 exactly (beyond safe-integer range)', () => {
    // 2^53 + 1 = 9007199254740993; a number can't hold it exactly, a bigint can.
    expect([...u64be(9007199254740993n)]).toEqual([0, 0x20, 0, 0, 0, 0, 0, 1])
  })

  it('encodes the max u64 as eight 0xff bytes', () => {
    expect([...u64be(0xffffffffffffffffn)]).toEqual([
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ])
  })

  it('rejects a number that is not a safe integer', () => {
    expect(() => u64be(2 ** 53)).toThrow()
    expect(() => u64be(1.5)).toThrow()
  })

  it('rejects a negative bigint', () => {
    expect(() => u64be(-1n)).toThrow()
  })

  it('rejects a bigint above the u64 range', () => {
    expect(() => u64be(0x1_0000_0000_0000_0000n)).toThrow()
  })
})
