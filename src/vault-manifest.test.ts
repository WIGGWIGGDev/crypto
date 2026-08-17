import { describe, expect, it, vi } from 'vitest'

import { buildEntryAadV2, ZK2_NO_PARENT } from './zk-entry-aad.js'
import {
  aadTypesForEntry,
  buildManifestAad,
  buildManifestLookup,
  compareManifestOrder,
  entryAadV2ParamsFor,
  evaluateManifest,
  manifestEntryKey,
  buildManifestFromItems,
  buildManifestFromPrior,
  confirmVaultVerdict,
  gatherServerRows,
  isActiveManifestIdentity,
  isManifestConflictCode,
  MANIFEST_CONFLICT,
  MANIFEST_REQUIRED,
  VAULT_EPOCH_MISMATCH,
  mustUseZk2,
  toManifestItems,
  parseManifest,
  rebuildManifest,
  reconcileManifest,
  serializeManifest,
  type ManifestItemInput,
  type EntryKey,
  type EntryScheme,
  type ManifestEntry,
  type ManifestEntryKind,
  type ManifestReconciliation,
  type ManifestVerdict,
  type VaultManifest,
} from './vault-manifest.js'

// Typed factory — references ManifestEntryKind + EntryScheme so the public type
// surface is exercised, not just the value API.
function entry(
  t: ManifestEntryKind,
  id: string,
  ver: number,
  parent: string | null,
  ord: number | null,
  sch: EntryScheme,
  et?: string,
): ManifestEntry {
  // Never assign `et: undefined` explicitly (exactOptionalPropertyTypes): omit the
  // key. A vault entry built with no `et` models the invalid "missing entry type".
  if (t !== 'vault') return { t, id, ver, parent, ord, sch }
  if (et === undefined) return { t, id, ver, parent, ord, sch }
  return { t, id, ver, parent, ord, sch, et }
}

const vaultEntry = entry('vault', 'v1', 3, 'id-1', 2, 'zk2', 'password')
const identityEntry = entry('identity', 'id-1', 1, null, 0, 'zk2')
const contactEntry = entry('contact', 'c1', 7, null, null, 'zk1')

const manifest: VaultManifest = {
  v: 5,
  entries: [
    { t: 'vault', id: 'v1', ver: 3, parent: 'id-1', ord: 2, sch: 'zk2', et: 'password' },
    { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: 0, sch: 'zk2' },
    { t: 'contact', id: 'c1', ver: 7, parent: null, ord: null, sch: 'zk1' },
  ],
}

const bytesOf = (o: object | number): Uint8Array => new TextEncoder().encode(JSON.stringify(o))

describe('serializeManifest / parseManifest', () => {
  it('round-trips a manifest across all three kinds, entries in canonical (kind,id) order', () => {
    const parsed = parseManifest(serializeManifest(manifest))
    expect(parsed.v).toBe(5)
    expect(parsed.entries).toEqual([
      { t: 'contact', id: 'c1', ver: 7, parent: null, ord: null, sch: 'zk1' },
      { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: 0, sch: 'zk2' },
      { t: 'vault', id: 'v1', ver: 3, parent: 'id-1', ord: 2, sch: 'zk2', et: 'password' },
    ])
  })

  it('serializes deterministically regardless of input entry order', () => {
    const reordered: VaultManifest = {
      v: 5,
      entries: [
        { t: 'contact', id: 'c1', ver: 7, parent: null, ord: null, sch: 'zk1' },
        { t: 'vault', id: 'v1', ver: 3, parent: 'id-1', ord: 2, sch: 'zk2', et: 'password' },
        { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: 0, sch: 'zk2' },
      ],
    }
    expect([...serializeManifest(reordered)]).toEqual([...serializeManifest(manifest)])
  })

  it('omits the et key for non-vault entries and keeps it for vault entries', () => {
    const parsed = parseManifest(serializeManifest(manifest))
    const contact = parsed.entries.find((e) => e.t === 'contact')
    const vault = parsed.entries.find((e) => e.t === 'vault')
    expect(contact !== undefined && !('et' in contact)).toBe(true)
    expect(vault !== undefined && 'et' in vault && vault.et === 'password').toBe(true)
  })
})

// Forward-compat: a manifest written by a NEWER client can carry rows of a kind
// THIS version doesn't know. It must round-trip losslessly (so an older client's
// write doesn't strand a newer client's rows) and stay out of the known-entry
// logic. Regression guard for the installed-mobile wire-format-freeze constraint.
describe('forward-compat (unknown entry kinds)', () => {
  // A future kind ('label') with a kind-specific field ('scope') the old client can't interpret.
  const withFuture = {
    v: 9,
    entries: [
      { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: 0, sch: 'zk2' },
      { t: 'label', id: 'lbl-1', ver: 4, parent: null, ord: 3, sch: 'zk2', scope: 'contact' },
      { t: 'vault', id: 'v1', ver: 3, parent: 'id-1', ord: 2, sch: 'zk2', et: 'password' },
    ],
  }

  it('preserves an unknown kind in opaque, absent from the typed entries', () => {
    const parsed = parseManifest(bytesOf(withFuture))
    expect(parsed.entries.map((e) => e.t).sort()).toEqual(['identity', 'vault'])
    expect(parsed.opaque).toEqual([
      {
        t: 'label',
        id: 'lbl-1',
        raw: {
          t: 'label',
          id: 'lbl-1',
          ver: 4,
          parent: null,
          ord: 3,
          sch: 'zk2',
          scope: 'contact',
        },
      },
    ])
  })

  it('round-trips the opaque row losslessly, including its unknown field', () => {
    const reserialized = parseManifest(serializeManifest(parseManifest(bytesOf(withFuture))))
    expect(reserialized.opaque?.[0]?.raw['scope']).toBe('contact')
    // Idempotent bytes: an older client re-emitting a newer manifest is stable.
    const once = serializeManifest(parseManifest(bytesOf(withFuture)))
    const twice = serializeManifest(parseManifest(once))
    expect([...once]).toEqual([...twice])
  })

  it('reconcile ignores opaque rows — no false missing/extra for kinds this client cannot fetch', () => {
    const parsed = parseManifest(bytesOf(withFuture))
    // The old client fetched only the kinds it knows; it never fetches 'label' rows.
    const serverRows: EntryKey[] = [
      { t: 'identity', id: 'id-1' },
      { t: 'vault', id: 'v1' },
    ]
    const result = reconcileManifest(parsed, serverRows, 9)
    expect(result.missing).toEqual([])
    expect(result.extra).toEqual([])
    expect(result.rollbackAlarm).toBe(false)
  })

  it('an opaque row does NOT mask a real missing known row (split cannot weaken detection)', () => {
    const parsed = parseManifest(bytesOf(withFuture))
    // A malicious server omits the known vault row (delete/omit tamper) but returns
    // identity. The presence of an opaque 'label' row must not suppress the alarm.
    const serverRows: EntryKey[] = [{ t: 'identity', id: 'id-1' }]
    const result = reconcileManifest(parsed, serverRows, 9)
    expect(result.missing.map((e) => e.id)).toEqual(['v1'])
  })

  it('dedup spans known and opaque buckets', () => {
    const dup = {
      v: 1,
      entries: [
        { t: 'label', id: 'x', ver: 1, foo: 1 },
        { t: 'label', id: 'x', ver: 2, foo: 2 },
      ],
    }
    expect(() => parseManifest(bytesOf(dup))).toThrow(/duplicate/)
  })
})

// Write-side generation. The load-bearing property is that a rebuild
// carries the previous manifest's opaque (forward-compat) rows forward BY
// CONSTRUCTION — an older client editing its known kinds must not strand a newer
// client's rows.
describe('rebuildManifest (write side)', () => {
  const withOpaque = parseManifest(
    bytesOf({
      v: 4,
      entries: [
        { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: 0, sch: 'zk2' },
        { t: 'label', id: 'lbl-1', ver: 2, parent: null, ord: 1, sch: 'zk2', scope: 'contact' },
      ],
    }),
  )

  it('carries the previous opaque rows forward and sets the new v + entries', () => {
    const next = rebuildManifest(withOpaque, [vaultEntry, identityEntry], 5)
    expect(next.v).toBe(5)
    expect(next.entries).toEqual([vaultEntry, identityEntry])
    expect(next.opaque).toEqual(withOpaque.opaque)
  })

  it('omits opaque entirely when the previous manifest had none', () => {
    const next = rebuildManifest(manifest, [vaultEntry], 6)
    expect('opaque' in next).toBe(false)
  })

  it('a deleted known row drops out while the opaque row survives (round-trips)', () => {
    // Rebuild with ONLY the identity (the old client removed nothing it doesn't know).
    const round = parseManifest(serializeManifest(rebuildManifest(withOpaque, [identityEntry], 5)))
    expect(round.v).toBe(5)
    expect(round.entries.map((e) => e.t)).toEqual(['identity'])
    expect(round.opaque?.[0]?.id).toBe('lbl-1')
    expect(round.opaque?.[0]?.raw['scope']).toBe('contact')
  })
})

describe('gatherServerRows', () => {
  it('flattens the three lists into typed (kind,id) keys', () => {
    expect(gatherServerRows([{ id: 'v1' }], [{ id: 'i1' }], [{ id: 'c1' }])).toEqual([
      { t: 'vault', id: 'v1' },
      { t: 'identity', id: 'i1' },
      { t: 'contact', id: 'c1' },
    ])
  })

  it('is empty for empty lists (an empty vault has no rows to reconcile)', () => {
    expect(gatherServerRows([], [], [])).toEqual([])
  })

  // Identities are scoped to the manifest canon (active): archived/deleted are excluded so
  // a snapshot and a delta-maintained manifest agree on membership; a missing status is kept.
  it('scopes identities to ACTIVE (drops archived/deleted, keeps active + missing status)', () => {
    expect(
      gatherServerRows(
        [{ id: 'v1' }],
        [
          { id: 'active-1', status: 'active' },
          { id: 'archived-1', status: 'archived' },
          { id: 'deleted-1', status: 'deleted' },
          { id: 'nostatus-1' },
        ],
        [{ id: 'c1' }],
      ),
    ).toEqual([
      { t: 'vault', id: 'v1' },
      { t: 'identity', id: 'active-1' },
      { t: 'identity', id: 'nostatus-1' },
      { t: 'contact', id: 'c1' },
    ])
  })
})

describe('isActiveManifestIdentity', () => {
  it('keeps active + missing status, drops archived/deleted', () => {
    expect(isActiveManifestIdentity('active')).toBe(true)
    expect(isActiveManifestIdentity(undefined)).toBe(true)
    expect(isActiveManifestIdentity('archived')).toBe(false)
    expect(isActiveManifestIdentity('deleted')).toBe(false)
  })
})

describe('confirmVaultVerdict', () => {
  const clean: ManifestVerdict = {
    rollback: false,
    missing: [],
    extra: [],
    tampered: false,
    nextHwm: 1,
  }
  const missing: ManifestVerdict = {
    rollback: false,
    missing: [{ t: 'identity', id: 'i1', ver: 1, parent: null, ord: null, sch: 'zk1' }],
    extra: [],
    tampered: true,
    nextHwm: 1,
  }
  const rollback: ManifestVerdict = {
    rollback: true,
    missing: [],
    extra: [],
    tampered: true,
    nextHwm: 0,
  }

  it('returns a clean verdict without re-checking', async () => {
    const fresh = vi.fn()
    expect(await confirmVaultVerdict(clean, fresh)).toBe(clean)
    expect(fresh).not.toHaveBeenCalled()
  })

  it('returns a rollback immediately without re-checking (deterministic)', async () => {
    const fresh = vi.fn()
    expect(await confirmVaultVerdict(rollback, fresh)).toBe(rollback)
    expect(fresh).not.toHaveBeenCalled()
  })

  it('re-checks a `missing` and returns the fresh result (a transient read clears)', async () => {
    const fresh = vi.fn().mockResolvedValue(clean)
    expect(await confirmVaultVerdict(missing, fresh)).toBe(clean)
    expect(fresh).toHaveBeenCalledTimes(1)
  })

  it('re-checks a `missing` and still reports it when it persists', async () => {
    const fresh = vi.fn().mockResolvedValue(missing)
    expect(await confirmVaultVerdict(missing, fresh)).toBe(missing)
    expect(fresh).toHaveBeenCalledTimes(1)
  })
})

describe('toManifestItems', () => {
  it('maps the three lists to ManifestItemInput (seeds every item at zk1; vault gets parent/ord/et)', () => {
    expect(
      toManifestItems(
        [{ id: 'v1', identityId: 'id-1', entryType: 'password', sortOrder: 2 }],
        [{ id: 'id-1' }],
        [{ id: 'c1' }],
      ),
    ).toEqual([
      { t: 'vault', id: 'v1', parent: 'id-1', ord: 2, sch: 'zk1', et: 'password' },
      { t: 'identity', id: 'id-1', parent: null, ord: null, sch: 'zk1' },
      { t: 'contact', id: 'c1', parent: null, ord: null, sch: 'zk1' },
    ])
  })

  it('feeds buildManifestFromItems for a first manifest', () => {
    const items = toManifestItems(
      [{ id: 'v1', identityId: 'id-1', entryType: 'note', sortOrder: 0 }],
      [{ id: 'id-1' }],
      [],
    )
    const m = buildManifestFromItems(items, null, new Set())
    expect(m.v).toBe(1)
    expect(m.entries.map((e) => e.t).sort()).toEqual(['identity', 'vault'])
  })
})

describe('buildManifestFromPrior (read-modify-write)', () => {
  const prior: VaultManifest = {
    v: 5,
    entries: [
      { t: 'identity', id: 'id-1', ver: 2, parent: null, ord: 0, sch: 'zk1' },
      // A row a CONCURRENT device added — present in the fetched prior, untouched by this write.
      { t: 'vault', id: 'concurrent', ver: 1, parent: 'id-1', ord: 9, sch: 'zk1', et: 'note' },
    ],
  }

  it('PRESERVES a concurrent device row not in the local delta', () => {
    const next = buildManifestFromPrior(prior, {
      upserts: [{ t: 'vault', id: 'v1', parent: 'id-1', ord: 1, sch: 'zk1', et: 'password' }],
      bumped: new Set([manifestEntryKey('vault', 'v1')]),
    })
    expect(next.v).toBe(6)
    // The concurrent row survives — the whole point.
    expect(next.entries.map((e) => e.id).sort()).toEqual(['concurrent', 'id-1', 'v1'])
  })

  it('a new upsert = ver 1; a bumped existing upsert = +1; an unbumped upsert keeps ver', () => {
    const next = buildManifestFromPrior(prior, {
      upserts: [
        { t: 'identity', id: 'id-1', parent: null, ord: 0, sch: 'zk1' }, // metadata-only, NOT bumped
        { t: 'vault', id: 'new', parent: 'id-1', ord: 2, sch: 'zk1', et: 'password' }, // new
      ],
      bumped: new Set(), // neither had a ciphertext change... id-1 metadata-only, new is new
    })
    const byId = Object.fromEntries(next.entries.map((e) => [e.id, e.ver]))
    expect(byId['id-1']).toBe(2) // kept (metadata-only)
    expect(byId['new']).toBe(1) // new
    expect(byId['concurrent']).toBe(1) // untouched
  })

  it('a remove drops the row', () => {
    const next = buildManifestFromPrior(prior, {
      removes: new Set([manifestEntryKey('vault', 'concurrent')]),
    })
    expect(next.entries.map((e) => e.id)).toEqual(['id-1'])
  })

  it('PRESERVES the committed sch on a metadata-only (non-bumped) upsert — no zk2→zk1 strand', () => {
    const zk2Prior: VaultManifest = {
      v: 7,
      entries: [{ t: 'identity', id: 'id-9', ver: 4, parent: null, ord: null, sch: 'zk2' }],
    }
    // Archive-style upsert: flips `inactive`, NOT in `bumped`, and (harmlessly) carries sch:'zk1'.
    const next = buildManifestFromPrior(zk2Prior, {
      upserts: [{ t: 'identity', id: 'id-9', parent: null, ord: null, sch: 'zk1', inactive: true }],
    })
    const e = next.entries.find((x) => x.id === 'id-9')
    expect(e?.sch).toBe('zk2') // committed scheme preserved — the ciphertext is still zk2
    expect(e?.ver).toBe(4) // metadata-only → ver preserved
    expect(e?.inactive).toBe(true)
  })

  it('a bumped upsert (re-encrypt) DOES change sch — the zk1→zk2 re-encrypt', () => {
    const zk1Prior: VaultManifest = {
      v: 1,
      entries: [{ t: 'vault', id: 'v9', ver: 3, parent: 'i1', ord: null, sch: 'zk1', et: 'note' }],
    }
    const next = buildManifestFromPrior(zk1Prior, {
      upserts: [{ t: 'vault', id: 'v9', parent: 'i1', ord: null, sch: 'zk2', et: 'note' }],
      bumped: new Set([manifestEntryKey('vault', 'v9')]),
    })
    const e = next.entries.find((x) => x.id === 'v9')
    expect(e?.sch).toBe('zk2') // re-encrypt → new scheme applied
    expect(e?.ver).toBe(4) // bumped
  })

  it('a standalone bumped key (no upsert) bumps ver in place, preserving fields (UPDATE)', () => {
    const next = buildManifestFromPrior(prior, {
      bumped: new Set([manifestEntryKey('vault', 'concurrent')]),
    })
    expect(next.v).toBe(6)
    expect(next.entries.find((e) => e.id === 'concurrent')).toEqual({
      t: 'vault',
      id: 'concurrent',
      ver: 2, // +1
      parent: 'id-1', // preserved — the client didn't have to restate these
      ord: 9,
      sch: 'zk1',
      et: 'note',
    })
  })

  it('a standalone bumped key absent from prior is a no-op (no phantom row)', () => {
    const next = buildManifestFromPrior(prior, {
      bumped: new Set([manifestEntryKey('vault', 'ghost')]),
    })
    expect(next.entries.map((e) => e.id).sort()).toEqual(['concurrent', 'id-1'])
  })

  it('null prior seeds a first manifest from the upserts (v=1, ver=1)', () => {
    const next = buildManifestFromPrior(null, {
      upserts: [{ t: 'identity', id: 'id-1', parent: null, ord: null, sch: 'zk1' }],
    })
    expect(next.v).toBe(1)
    expect(next.entries).toEqual([
      { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: null, sch: 'zk1' },
    ])
  })

  it('carries opaque (forward-compat) rows forward', () => {
    const withOpaque = parseManifest(
      bytesOf({
        v: 3,
        entries: [
          { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: 0, sch: 'zk1' },
          { t: 'label', id: 'lbl-1', ver: 2, parent: null, ord: 1, sch: 'zk2', scope: 'contact' },
        ],
      }),
    )
    const next = buildManifestFromPrior(withOpaque, {
      removes: new Set([manifestEntryKey('identity', 'id-1')]),
    })
    expect(next.opaque?.[0]?.id).toBe('lbl-1')
  })
})

describe('buildManifestFromItems (write-side generation)', () => {
  const identityItem: ManifestItemInput = {
    t: 'identity',
    id: 'id-1',
    parent: null,
    ord: 0,
    sch: 'zk1',
  }
  const vaultItem: ManifestItemInput = {
    t: 'vault',
    id: 'v1',
    parent: 'id-1',
    ord: 1,
    sch: 'zk1',
    et: 'password',
  }

  it('first manifest (no previous): every ver is 1 and v is 1', () => {
    const m = buildManifestFromItems([identityItem, vaultItem], null, new Set())
    expect(m.v).toBe(1)
    expect(m.entries.map((e) => [e.id, e.ver])).toEqual([
      ['id-1', 1],
      ['v1', 1],
    ])
    expect('opaque' in m).toBe(false)
  })

  it('carries prior vers, bumps only re-encrypted items, starts a new item at 1', () => {
    const previous: VaultManifest = {
      v: 4,
      entries: [
        { t: 'identity', id: 'id-1', ver: 3, parent: null, ord: 0, sch: 'zk1' },
        { t: 'vault', id: 'v1', ver: 7, parent: 'id-1', ord: 1, sch: 'zk1', et: 'password' },
      ],
    }
    const contactItem: ManifestItemInput = {
      t: 'contact',
      id: 'c1',
      parent: null,
      ord: null,
      sch: 'zk1',
    }
    // v1 re-encrypted (bumped); id-1 metadata-only (not bumped, must NOT bump); c1 new.
    const bumped = new Set([manifestEntryKey('vault', 'v1')])
    const m = buildManifestFromItems([identityItem, vaultItem, contactItem], previous, bumped)
    expect(m.v).toBe(5)
    expect(Object.fromEntries(m.entries.map((e) => [e.id, e.ver]))).toEqual({
      'id-1': 3, // kept
      v1: 8, // bumped 7→8
      c1: 1, // new
    })
  })

  it('a deleted item drops out of the manifest', () => {
    const previous: VaultManifest = {
      v: 2,
      entries: [
        { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: 0, sch: 'zk1' },
        { t: 'vault', id: 'v1', ver: 1, parent: 'id-1', ord: 1, sch: 'zk1', et: 'password' },
      ],
    }
    const m = buildManifestFromItems([identityItem], previous, new Set())
    expect(m.entries.map((e) => e.id)).toEqual(['id-1'])
  })

  it('carries forward-compat opaque rows into the new manifest', () => {
    const previous = parseManifest(
      bytesOf({
        v: 3,
        entries: [
          { t: 'identity', id: 'id-1', ver: 1, parent: null, ord: 0, sch: 'zk1' },
          { t: 'label', id: 'lbl-1', ver: 2, parent: null, ord: 1, sch: 'zk2', scope: 'contact' },
        ],
      }),
    )
    const m = buildManifestFromItems([identityItem], previous, new Set())
    expect(m.opaque?.[0]?.id).toBe('lbl-1')
  })
})

describe('parseManifest — validation (rejects a malformed manifest)', () => {
  it('rejects a non-object', () => {
    expect(() => parseManifest(bytesOf(42))).toThrow()
  })
  it('rejects a missing / negative version', () => {
    expect(() => parseManifest(bytesOf({ entries: [] }))).toThrow()
    expect(() => parseManifest(bytesOf({ v: -1, entries: [] }))).toThrow()
  })
  it('rejects entries that are not an array', () => {
    expect(() => parseManifest(bytesOf({ v: 1, entries: {} }))).toThrow()
  })
  // An UNKNOWN kind is preserved (forward-compat), not rejected — see the
  // "forward-compat" suite. What's still malformed: an empty / non-string kind,
  // or an opaque entry missing the common (t,id) needed for dedup + identity.
  it('rejects an entry with an empty or non-string kind', () => {
    expect(() => parseManifest(bytesOf({ v: 1, entries: [{ t: '', id: 'x' }] }))).toThrow()
    expect(() => parseManifest(bytesOf({ v: 1, entries: [{ t: 42, id: 'x' }] }))).toThrow()
  })
  it('rejects an unknown-kind (opaque) entry missing its id', () => {
    expect(() => parseManifest(bytesOf({ v: 1, entries: [{ t: 'label', ver: 1 }] }))).toThrow()
  })
  it('rejects a vault entry missing its et (type)', () => {
    const bad = {
      v: 1,
      entries: [{ t: 'vault', id: 'x', ver: 1, parent: null, ord: 1, sch: 'zk1' }],
    }
    expect(() => parseManifest(bytesOf(bad))).toThrow()
  })
  it('rejects an et on a non-vault entry', () => {
    const bad = {
      v: 1,
      entries: [{ t: 'identity', id: 'x', ver: 1, parent: null, ord: 1, sch: 'zk1', et: 'nope' }],
    }
    expect(() => parseManifest(bytesOf(bad))).toThrow()
  })
  it('rejects a non-positive ver', () => {
    const bad = {
      v: 1,
      entries: [{ t: 'contact', id: 'x', ver: 0, parent: null, ord: null, sch: 'zk1' }],
    }
    expect(() => parseManifest(bytesOf(bad))).toThrow()
  })
  it('rejects an unknown scheme', () => {
    const bad = {
      v: 1,
      entries: [{ t: 'contact', id: 'x', ver: 1, parent: null, ord: null, sch: 'zk3' }],
    }
    expect(() => parseManifest(bytesOf(bad))).toThrow()
  })
  it('rejects a parent that is neither string nor null', () => {
    const bad = {
      v: 1,
      entries: [{ t: 'vault', id: 'x', ver: 1, parent: 5, ord: 1, sch: 'zk1', et: 'password' }],
    }
    expect(() => parseManifest(bytesOf(bad))).toThrow()
  })
  it('rejects an ord that is neither finite number nor null', () => {
    const bad = {
      v: 1,
      entries: [{ t: 'contact', id: 'x', ver: 1, parent: null, ord: '2', sch: 'zk1' }],
    }
    expect(() => parseManifest(bytesOf(bad))).toThrow()
  })
  it('rejects a duplicate (kind,id) entry (would mask a delete/omit alarm)', () => {
    const bad = {
      v: 1,
      entries: [
        { t: 'contact', id: 'dup', ver: 1, parent: null, ord: null, sch: 'zk1' },
        { t: 'contact', id: 'dup', ver: 2, parent: null, ord: null, sch: 'zk2' },
      ],
    }
    expect(() => parseManifest(bytesOf(bad))).toThrow()
  })
  it('allows the same id across different kinds (distinct keys)', () => {
    const ok = {
      v: 1,
      entries: [
        { t: 'identity', id: 'shared', ver: 1, parent: null, ord: 0, sch: 'zk2' },
        { t: 'contact', id: 'shared', ver: 1, parent: null, ord: null, sch: 'zk1' },
      ],
    }
    expect(() => parseManifest(bytesOf(ok))).not.toThrow()
  })
})

describe('buildManifestAad', () => {
  const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))
  const u32 = (n: number): number[] => [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ]
  const u64 = (n: number): number[] => [0, 0, 0, 0, ...u32(n)]
  const frame = (parts: number[][]): number[] => parts.flatMap((p) => [...u32(p.length), ...p])

  it('binds "vmanifest-v1" || userId || u64be(version) with length-prefix framing', () => {
    expect([...buildManifestAad('user-1', 5)]).toEqual(
      frame([ascii('vmanifest-v1'), ascii('user-1'), u64(5)]),
    )
  })
  it('is domain-separated from a zk2 entry AAD under the same key (leading tag differs)', () => {
    // The manifest AAD leads with the length-prefixed "vmanifest-v1" tag, never a
    // bare userId — so it can't collide with the zk2 entry AAD (leads with "zk2").
    expect([...buildManifestAad('user-1', 5)].slice(0, 16)).toEqual(frame([ascii('vmanifest-v1')]))
  })
  it('distinguishes userId and version (no cross-account / cross-version reuse)', () => {
    expect([...buildManifestAad('a', 5)]).not.toEqual([...buildManifestAad('b', 5)])
    expect([...buildManifestAad('a', 5)]).not.toEqual([...buildManifestAad('a', 6)])
  })
  it('treats version as a number or the equivalent bigint identically', () => {
    expect([...buildManifestAad('u', 5)]).toEqual([...buildManifestAad('u', 5n)])
  })
  it('returns an ArrayBuffer-backed view', () => {
    expect(buildManifestAad('u', 1).buffer).toBeInstanceOf(ArrayBuffer)
  })
})

describe('manifestEntryKey', () => {
  it('composes <kind>:<id>', () => {
    expect(manifestEntryKey('vault', 'abc')).toBe('vault:abc')
  })
})

// ── Reconciliation ──────────────────────────────────────────────────────────

const manifest3: VaultManifest = { v: 10, entries: [vaultEntry, identityEntry, contactEntry] }
const allRows: readonly EntryKey[] = [
  { t: 'vault', id: 'v1' },
  { t: 'identity', id: 'id-1' },
  { t: 'contact', id: 'c1' },
]

describe('buildManifestLookup', () => {
  it('indexes every entry by <kind>:<id>', () => {
    const lookup = buildManifestLookup(manifest3)
    expect(lookup.size).toBe(3)
    expect(lookup.get('vault:v1')).toEqual(vaultEntry)
    expect(lookup.get(manifestEntryKey('identity', 'id-1'))).toEqual(identityEntry)
  })
})

describe('reconcileManifest', () => {
  it('is clean when every manifest row is returned and version has not regressed', () => {
    const result: ManifestReconciliation = reconcileManifest(manifest3, allRows, 10)
    expect(result.rollbackAlarm).toBe(false) // v(10) < hwm(10) is false
    expect(result.missing).toEqual([])
    expect(result.extra).toEqual([])
  })

  it('flags a manifest row the server omitted (delete/omit)', () => {
    const rows = [
      { t: 'identity', id: 'id-1' },
      { t: 'contact', id: 'c1' },
    ] as const
    expect(reconcileManifest(manifest3, rows, 10).missing.map((e) => e.id)).toEqual(['v1'])
  })

  it('flags a server row that is not in the manifest (server-injected)', () => {
    const rows = [...allRows, { t: 'vault', id: 'injected' } as const]
    expect(reconcileManifest(manifest3, rows, 10).extra).toEqual([{ t: 'vault', id: 'injected' }])
  })

  it('raises the rollback alarm only when the manifest version is below the device HWM', () => {
    expect(reconcileManifest(manifest3, allRows, 11).rollbackAlarm).toBe(true) // 10 < 11
    expect(reconcileManifest(manifest3, allRows, 10).rollbackAlarm).toBe(false) // equal is fine
    expect(reconcileManifest(manifest3, allRows, 9).rollbackAlarm).toBe(false)
  })
})

describe('evaluateManifest (read-path orchestration)', () => {
  it('null manifest + no HWM = genuine pre-manifest state (TOFU) — no tamper, advance nothing', () => {
    const v = evaluateManifest(null, allRows, null)
    expect(v).toEqual({ rollback: false, missing: [], extra: [], tampered: false, nextHwm: null })
  })

  it('null manifest while a HWM exists = manifest DELETION (rollback tamper), floor held', () => {
    const v = evaluateManifest(null, allRows, 10)
    expect(v.rollback).toBe(true)
    expect(v.tampered).toBe(true)
    expect(v.nextHwm).toBe(10)
  })

  it('first sight of a manifest (no HWM) is trusted and stamps its version as the floor', () => {
    const v = evaluateManifest(manifest3, allRows, null)
    expect(v.tampered).toBe(false)
    expect(v.nextHwm).toBe(10)
  })

  it('a clean read advances the HWM to the manifest version', () => {
    const v = evaluateManifest(manifest3, allRows, 8)
    expect(v.rollback).toBe(false)
    expect(v.tampered).toBe(false)
    expect(v.nextHwm).toBe(10)
  })

  it('a version below the HWM is a rollback — tamper, and the floor is NOT lowered', () => {
    const v = evaluateManifest(manifest3, allRows, 11)
    expect(v.rollback).toBe(true)
    expect(v.tampered).toBe(true)
    expect(v.nextHwm).toBe(11)
  })

  it('an omitted row is a tamper, but the (current) manifest version still advances the HWM', () => {
    const rows = [
      { t: 'identity', id: 'id-1' },
      { t: 'contact', id: 'c1' },
    ] as const
    const v = evaluateManifest(manifest3, rows, 8)
    expect(v.tampered).toBe(true)
    expect(v.missing.map((e) => e.id)).toEqual(['v1'])
    expect(v.nextHwm).toBe(10)
  })

  it('a server-injected row is reported to drop but is NOT on its own a tamper (benign-race safe)', () => {
    const rows = [...allRows, { t: 'vault', id: 'injected' } as const]
    const v = evaluateManifest(manifest3, rows, 8)
    expect(v.tampered).toBe(false)
    expect(v.extra).toEqual([{ t: 'vault', id: 'injected' }])
    expect(v.nextHwm).toBe(10)
  })
})

describe('mustUseZk2', () => {
  it('is true for a zk2 entry and false for a zk1 entry', () => {
    expect(mustUseZk2(vaultEntry)).toBe(true)
    expect(mustUseZk2(contactEntry)).toBe(false)
  })
})

describe('aadTypesForEntry', () => {
  it('returns the entry type for a vault row', () => {
    expect(aadTypesForEntry(vaultEntry)).toEqual(['password'])
  })
  it('returns the fixed types per kind for identity and contact', () => {
    expect(aadTypesForEntry(identityEntry)).toEqual(['identity'])
    expect(aadTypesForEntry(contactEntry)).toEqual(['contact', 'contact-avatar'])
  })
  it('throws for a vault entry missing its et', () => {
    expect(() => aadTypesForEntry(entry('vault', 'x', 1, null, 1, 'zk1'))).toThrow()
  })
})

describe('entryAadV2ParamsFor — bridge to the per-entry AAD', () => {
  it('feeds the trusted version/parent from the manifest', () => {
    expect(entryAadV2ParamsFor(vaultEntry, 'password')).toEqual({
      entryType: 'password',
      entryId: 'v1',
      entryVersion: 3,
      parentId: 'id-1',
    })
  })

  it('maps a root row (null parent) to the ZK2_NO_PARENT sentinel', () => {
    expect(entryAadV2ParamsFor(identityEntry, 'identity').parentId).toBe(ZK2_NO_PARENT)
  })

  it('produces params that build a valid zk2 AAD', () => {
    const viaBridge = buildEntryAadV2(entryAadV2ParamsFor(vaultEntry, 'password'))
    const direct = buildEntryAadV2({
      entryType: 'password',
      entryId: 'v1',
      entryVersion: 3,
      parentId: 'id-1',
    })
    expect([...viaBridge]).toEqual([...direct])
  })
})

describe('compareManifestOrder', () => {
  it('orders by ord, nulls last, ties broken by id', () => {
    const sorted = [vaultEntry, identityEntry, contactEntry].sort(compareManifestOrder)
    expect(sorted.map((e) => e.id)).toEqual(['id-1', 'v1', 'c1']) // ord 0, 2, null-last
  })
  it('breaks equal ords by id', () => {
    const x = entry('vault', 'x', 1, null, 5, 'zk1', 'password')
    const y = entry('vault', 'y', 1, null, 5, 'zk1', 'password')
    expect(compareManifestOrder(x, y)).toBeLessThan(0)
  })
  it('breaks two null ords by id', () => {
    const a = entry('contact', 'a', 1, null, null, 'zk1')
    const b = entry('contact', 'b', 1, null, null, 'zk1')
    expect(compareManifestOrder(a, b)).toBeLessThan(0)
  })
})

describe('isManifestConflictCode', () => {
  it('accepts every manifest-CAS 409 code (retryable)', () => {
    for (const code of [MANIFEST_CONFLICT, MANIFEST_REQUIRED, VAULT_EPOCH_MISMATCH]) {
      expect(isManifestConflictCode(code)).toBe(true)
    }
  })
  it('rejects an unrelated 409 code / null / undefined (fail fast, no retry)', () => {
    expect(isManifestConflictCode('DUPLICATE_ENTRY')).toBe(false)
    expect(isManifestConflictCode('')).toBe(false)
    expect(isManifestConflictCode(null)).toBe(false)
    expect(isManifestConflictCode(undefined)).toBe(false)
  })
})

describe('archived identity parking (inactive entries)', () => {
  const activeId = 'id-active'
  const archId = 'id-arch'

  it('toManifestItems parks archived identities (inactive) and drops only deleted', () => {
    const items = toManifestItems(
      [],
      [{ id: activeId }, { id: archId, status: 'archived' }, { id: 'id-del', status: 'deleted' }],
      [],
    )
    const ids = items.map((i) => i.id)
    expect(ids).toContain(activeId)
    expect(ids).toContain(archId) // archived KEPT (parked)
    expect(ids).not.toContain('id-del') // deleted removed
    expect(items.find((i) => i.id === activeId)?.inactive).toBeUndefined()
    expect(items.find((i) => i.id === archId)?.inactive).toBe(true)
  })

  it('archive → restore preserves the entry ver + sch (no reset to 1)', () => {
    // Seed: an active identity that has been edited a few times (ver 3, and pretend zk2).
    const seeded: VaultManifest = {
      v: 5,
      entries: [{ t: 'identity', id: archId, ver: 3, parent: null, ord: null, sch: 'zk2' }],
    }
    // Archive = an inactive-flip upsert, NOT in `bumped` (metadata-only, no re-encrypt).
    const archivedManifest = buildManifestFromPrior(seeded, {
      upserts: [{ t: 'identity', id: archId, parent: null, ord: null, sch: 'zk2', inactive: true }],
    })
    const archivedEntry = buildManifestLookup(archivedManifest).get(
      manifestEntryKey('identity', archId),
    )
    expect(archivedEntry?.inactive).toBe(true)
    expect(archivedEntry?.ver).toBe(3) // FROZEN — not reset, not bumped
    expect(archivedEntry?.sch).toBe('zk2')

    // Restore = inactive:false-flip upsert, NOT in `bumped`.
    const restoredManifest = buildManifestFromPrior(archivedManifest, {
      upserts: [{ t: 'identity', id: archId, parent: null, ord: null, sch: 'zk2' }],
    })
    const restoredEntry = buildManifestLookup(restoredManifest).get(
      manifestEntryKey('identity', archId),
    )
    expect(restoredEntry?.inactive).toBeUndefined() // active again
    expect(restoredEntry?.ver).toBe(3) // STILL 3 across the full archive↔restore cycle
    expect(restoredEntry?.sch).toBe('zk2')
  })

  it('reconcile PARKS inactive entries: absent from active rows is NOT missing; an active absent IS', () => {
    const manifest: VaultManifest = {
      v: 2,
      entries: [
        { t: 'identity', id: activeId, ver: 1, parent: null, ord: null, sch: 'zk1' },
        { t: 'identity', id: archId, ver: 3, parent: null, ord: null, sch: 'zk1', inactive: true },
      ],
    }
    // Active server rows (the rendered set) — archived identity is NOT rendered.
    const serverRows: EntryKey[] = [{ t: 'identity', id: activeId }]
    const r = reconcileManifest(manifest, serverRows, 2)
    expect(r.missing).toHaveLength(0) // parked archived entry is NOT a delete alarm
    expect(r.extra).toHaveLength(0)

    // Now the ACTIVE identity really is absent from the server → that IS missing.
    const r2 = reconcileManifest(manifest, [], 2)
    expect(r2.missing.map((e) => e.id)).toEqual([activeId]) // active alarms; archived still parked
  })

  it('wire: an inactive entry round-trips; a manifest with no inactive entries is byte-identical to before', () => {
    const withArchived: VaultManifest = {
      v: 4,
      entries: [
        { t: 'identity', id: activeId, ver: 1, parent: null, ord: null, sch: 'zk1' },
        { t: 'identity', id: archId, ver: 3, parent: null, ord: null, sch: 'zk1', inactive: true },
      ],
    }
    const round = parseManifest(serializeManifest(withArchived))
    expect(round.entries.find((e) => e.id === archId)?.inactive).toBe(true)
    expect(round.entries.find((e) => e.id === activeId)?.inactive).toBeUndefined()

    // No-inactive manifest → the `inactive` key never appears in the bytes (no churn / no floor-force).
    const noArchived: VaultManifest = {
      v: 4,
      entries: [{ t: 'identity', id: activeId, ver: 1, parent: null, ord: null, sch: 'zk1' }],
    }
    expect(new TextDecoder().decode(serializeManifest(noArchived))).not.toContain('inactive')
  })

  it('an old client that strips `inactive` under zk1 does not strand or false-alarm (fwd-compat)', () => {
    // Simulate an old client re-emitting the entry WITHOUT the field (it can't preserve it).
    const stripped: VaultManifest = {
      v: 4,
      entries: [{ t: 'identity', id: archId, ver: 3, parent: null, ord: null, sch: 'zk1' }],
    }
    // Under zk1 the entry still decrypts (v1 AAD, ver-independent); reconcile now sees it as
    // active, so it must appear in the (active) render — which it will, since an old client
    // that stripped `inactive` also renders it active. No missing, no strand.
    const r = reconcileManifest(stripped, [{ t: 'identity', id: archId }], 4)
    expect(r.missing).toHaveLength(0)
    expect(stripped.entries[0]?.sch).toBe('zk1') // ver-independent decrypt path
  })

  it('inactive is rejected as a non-boolean at the parse trust boundary', () => {
    const bad = new TextEncoder().encode(
      JSON.stringify({
        v: 1,
        entries: [
          {
            t: 'identity',
            id: archId,
            ver: 1,
            parent: null,
            ord: null,
            sch: 'zk1',
            inactive: 'yes',
          },
        ],
      }),
    )
    expect(() => parseManifest(bad)).toThrow(/inactive must be a boolean/)
  })
})
