import { describe, it, expect } from 'vitest'

import { entryReadAad, entryWriteAad, findCommittedEntry } from './entry-aad-dispatch.js'
import { entryAadV2ParamsFor, type ManifestEntry, type VaultManifest } from './vault-manifest.js'
import { buildEntryAad, buildEntryAadV2 } from './zk-entry-aad.js'

const zk1Entry: ManifestEntry = {
  t: 'vault',
  id: 'v1',
  ver: 3,
  parent: 'i1',
  ord: null,
  sch: 'zk1',
  et: 'password',
}
const zk2Entry: ManifestEntry = { ...zk1Entry, sch: 'zk2' }

describe('entryWriteAad — write-path AAD dispatch', () => {
  it('a zk1 entry yields the frozen v1 AAD (NOT v2)', () => {
    const aad = entryWriteAad(zk1Entry, 'password', 'v1')
    expect([...aad]).toEqual([...buildEntryAad('password', 'v1')])
    // The v1 wire format starts with `zk1:`; a hardcoded-v2 bug would not.
    expect(new TextDecoder().decode(aad).startsWith('zk1:')).toBe(true)
  })

  it('no committed entry (manifest inactive) → v1 AAD', () => {
    expect([...entryWriteAad(undefined, 'password', 'v1')]).toEqual([
      ...buildEntryAad('password', 'v1'),
    ])
  })

  it('a zk2 entry binds the committed ver + parent via the v2 AAD', () => {
    expect([...entryWriteAad(zk2Entry, 'password', 'v1')]).toEqual([
      ...buildEntryAadV2(entryAadV2ParamsFor(zk2Entry, 'password')),
    ])
  })

  it('the v2 AAD tracks the committed ver — a different ver yields different bytes', () => {
    const nextVer: ManifestEntry = { ...zk2Entry, ver: 4 }
    expect([...entryWriteAad(zk2Entry, 'password', 'v1')]).not.toEqual([
      ...entryWriteAad(nextVer, 'password', 'v1'),
    ])
  })

  it('a root (null-parent) zk2 entry routes through entryAadV2ParamsFor (null-parent sentinel)', () => {
    const root: ManifestEntry = {
      t: 'identity',
      id: 'id1',
      ver: 1,
      parent: null,
      ord: null,
      sch: 'zk2',
    }
    expect([...entryWriteAad(root, 'identity', 'id1')]).toEqual([
      ...buildEntryAadV2(entryAadV2ParamsFor(root, 'identity')),
    ])
  })
})

describe('findCommittedEntry', () => {
  const manifest: VaultManifest = {
    v: 5,
    entries: [zk1Entry, { t: 'identity', id: 'id1', ver: 1, parent: null, ord: null, sch: 'zk1' }],
  }

  it('finds the committed entry by (kind, id)', () => {
    expect(findCommittedEntry(manifest, 'vault', 'v1')).toBe(zk1Entry)
  })

  it('returns undefined for a missing row or an inactive (undefined) manifest', () => {
    expect(findCommittedEntry(manifest, 'vault', 'missing')).toBeUndefined()
    expect(findCommittedEntry(undefined, 'vault', 'v1')).toBeUndefined()
  })

  it('discriminates on kind (same id, different kind)', () => {
    expect(findCommittedEntry(manifest, 'contact', 'v1')).toBeUndefined()
  })
})

describe('entryReadAad — read dispatch + downgrade gate', () => {
  it('a zk1 / undefined entry → v1 AAD, exactAadOnly=false (full dual-key ladder runs)', () => {
    const r = entryReadAad(zk1Entry, 'password', 'v1')
    expect([...r.aad]).toEqual([...buildEntryAad('password', 'v1')])
    expect(r.exactAadOnly).toBe(false)
    expect(entryReadAad(undefined, 'password', 'v1').exactAadOnly).toBe(false)
  })

  it('a zk2 entry → v2 AAD (committed ver/parent), exactAadOnly=true (no fallback → no downgrade)', () => {
    const r = entryReadAad(zk2Entry, 'password', 'v1')
    expect([...r.aad]).toEqual([...buildEntryAadV2(entryAadV2ParamsFor(zk2Entry, 'password'))])
    expect(r.exactAadOnly).toBe(true)
  })

  it('read AAD == write AAD for the SAME entry (encrypt/decrypt round-trip by construction)', () => {
    expect([...entryReadAad(zk2Entry, 'password', 'v1').aad]).toEqual([
      ...entryWriteAad(zk2Entry, 'password', 'v1'),
    ])
    expect([...entryReadAad(zk1Entry, 'password', 'v1').aad]).toEqual([
      ...entryWriteAad(zk1Entry, 'password', 'v1'),
    ])
  })
})
