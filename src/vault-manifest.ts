/**
 * The V-AEAD vault manifest — the client's authenticated "packing list" of the
 * vault. This module is the DATA MODEL + wire format + the manifest's own AAD;
 * the reconciliation logic that consumes it lives alongside, and it feeds the
 * per-entry zk2 AAD (`buildEntryAadV2`).
 *
 * Why a manifest. The zk1/zk2 per-entry AAD binds each ciphertext to its record,
 * but says nothing about the SET: a malicious server can still delete or omit a
 * record, reorder them, serve an older ciphertext (rollback), or re-parent an
 * entry. The manifest is one small document, encrypted and authenticated under the
 * vault key V, that lists every LIVE entry with its version, parent, and order,
 * plus a monotonic counter. The client checks the server's answers against it, so
 * anything missing, stale, moved, or re-shuffled is detected client-side.
 *
 * Why AEAD-under-V rather than a signature: a signing key would have to be the
 * per-login Ed25519 key, which rotates on every password change and would
 * re-couple vault integrity to the master key M — the coupling the v2 escrow
 * exists to remove. V never rotates, so authenticating the manifest under V
 * (AES-GCM's tag IS the authenticator) binds it to the same key as the vault
 * itself, with no extra key to manage.
 *
 * What a manifest ENTRY models: one RECORD, of any covered kind. A record may hold
 * several AAD-bound blobs (a contact has both its data and its avatar); they share
 * the record's single version, and the read path builds each blob's zk2 AAD from
 * this record's `ver`/`parent`. The load-bearing rule: `ver`, `parent`, `ord`, and
 * (for vault entries) `et` are read from HERE — the manifest authenticated under V
 * — never from server-supplied plaintext. That is what makes rollback,
 * re-parenting, and reordering detectable.
 *
 * Scope: vault entries, identities, and contacts. `t` is a forward-compatible
 * enum: a record of a kind introduced by a NEWER client version parses into
 * {@link VaultManifest.opaque} and is preserved verbatim, so an OLDER client
 * round-trips it losslessly instead of rejecting the whole manifest (installed
 * mobile apps can't be recompiled — a hard reject would permanently lock the wire
 * format to today's three kinds). Adding a kind later is therefore expand-only.
 */

import { lengthPrefixedConcat, u64be } from './bytes.js'
import { ZK2_NO_PARENT, type EntryAadV2Params } from './zk-entry-aad.js'

/** Record kinds THIS client version understands (one manifest entry per record). */
export type ManifestEntryKind = 'vault' | 'identity' | 'contact'

/** Per-entry encryption scheme; `zk2` marks a row migrated to the version+parent AAD. */
export type EntryScheme = 'zk1' | 'zk2'

export interface ManifestEntry {
  /** Which kind of record this is. */
  readonly t: ManifestEntryKind
  /** The record's globally-unique id (UUID). */
  readonly id: string
  /** The record's monotonic version. The trusted source for the zk2 AAD. */
  readonly ver: number
  /**
   * The parent identity id for a vault entry; `null` for a root record (identity
   * or contact). Trusted source for the zk2 AAD's parent binding.
   */
  readonly parent: string | null
  /**
   * The trusted display order for a vault entry or identity; `null` for a contact
   * (contacts carry no stored order — they are client-ordered).
   */
  readonly ord: number | null
  /** Per-entry scheme. A reader holding a manifest refuses a zk1 fallback for a `zk2` record. */
  readonly sch: EntryScheme
  /**
   * The vault entry's type (`password`/`note`/…), which IS the record's AAD type.
   * It is server-supplied plaintext, so the trusted value is bound here. REQUIRED
   * when `t === 'vault'`, omitted otherwise (identity and contact AAD types are
   * fixed by kind).
   */
  readonly et?: string
  /**
   * `true` for an ARCHIVED identity (identity-only). An archived identity is PARKED in
   * the manifest — its ciphertext is untouched by archive/restore, so its `ver`/`sch`
   * are preserved here (an archived identity's read still sources the trusted zk2 AAD from them, and
   * an archive↔restore cycle no longer resets `ver` to 1). A parked entry is EXCLUDED
   * from reconcile's `missing` (it isn't in the active render set), so its absence there
   * is not a delete alarm. Only the CLIENT sets this (V-authenticated) — a malicious
   * server cannot flip an active entry to inactive to mask a deletion. Omitted (never
   * `false`) for active entries, so existing manifests serialize byte-identically.
   */
  readonly inactive?: boolean
}

/**
 * A row whose kind THIS client version does not understand — introduced by a
 * NEWER client. Preserved verbatim (its full original object is kept in `raw`) so
 * an older client re-serializes it byte-for-byte and never drops a newer client's
 * coverage, yet never validates or decrypts a schema it doesn't know. `t` + `id`
 * still drive dedup and (kind,id) identity. NOT reconciled or AAD-bound here — the
 * client version that OWNS the kind does that.
 */
export interface OpaqueManifestEntry {
  /** The (future) row kind — a non-empty string outside {@link ManifestEntryKind}. */
  readonly t: string
  /** The record's globally-unique id (UUID). */
  readonly id: string
  /** The complete original entry object, preserved for lossless round-trip. */
  readonly raw: JsonObject
}

export interface VaultManifest {
  /** The anti-rollback counter, mirrored by the server and bound in the manifest AAD. */
  readonly v: number
  /** One entry per LIVE record of a kind this version understands. */
  readonly entries: readonly ManifestEntry[]
  /**
   * Rows of kinds a NEWER client introduced, preserved verbatim for forward-compat.
   * Omitted when empty. Never reconciled/decrypted by this version — only carried
   * forward so a write from an older client doesn't strand a newer client's rows.
   */
  readonly opaque?: readonly OpaqueManifestEntry[]
}

/** The composite lookup/identity key for a row: `<kind>:<id>`. Accepts any kind string (incl. forward-compat opaque kinds). */
export function manifestEntryKey(t: string, id: string): string {
  return `${t}:${id}`
}

// ── Wire format ─────────────────────────────────────────────────────────────
// Canonical JSON: entries sorted by (kind, id) with a fixed field order, so the
// same logical manifest always serializes to the same bytes (testable, and no
// incidental churn). Byte-canonicality is not itself security-load-bearing — the
// AAD binds `userId || v`, and each write re-encrypts under a fresh nonce — but
// determinism keeps the model honest.

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

// A proper (non-`unknown`) type for parsed-but-unvalidated JSON. `JSON.parse`
// returns the built-in `any`, which we confine to `parseJson` below so the rest of
// the parser operates on this typed value and narrows it with real type guards.
export type JsonValue = string | number | boolean | null | JsonObject | JsonValue[]
export interface JsonObject {
  readonly [key: string]: JsonValue
}

function parseJson(text: string): JsonValue {
  return JSON.parse(text)
}

function canonicalEntry(e: ManifestEntry): JsonObject {
  const out: Record<string, JsonValue> = {
    t: e.t,
    id: e.id,
    ver: e.ver,
    parent: e.parent,
    ord: e.ord,
    sch: e.sch,
  }
  // Emit `inactive` ONLY when true — a manifest with no archived identities is byte-identical
  // to a manifest written before the field existed (no churn, no forced rewrite).
  if (e.inactive === true) out['inactive'] = true
  if (e.t === 'vault' && e.et !== undefined) out['et'] = e.et
  return out
}

/**
 * Serialize a manifest to canonical UTF-8 JSON bytes (the plaintext encrypted under
 * V). Known entries and forward-compat opaque entries are merged and sorted together
 * by `(kind, id)`, so an older client re-emits a newer client's opaque rows in the
 * same total order — no incidental churn from the split.
 */
export function serializeManifest(manifest: VaultManifest): Uint8Array {
  const items: { readonly key: string; readonly obj: JsonObject }[] = [
    ...manifest.entries.map((e) => ({ key: manifestEntryKey(e.t, e.id), obj: canonicalEntry(e) })),
    ...(manifest.opaque ?? []).map((o) => ({ key: manifestEntryKey(o.t, o.id), obj: o.raw })),
  ]
  items.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
  const entries = items.map((i) => i.obj)
  return textEncoder.encode(JSON.stringify({ v: manifest.v, entries }))
}

// ── Parsing + validation (no zod: crypto stays dependency-minimal) ───────────

// Guards accept `JsonValue | undefined` because object index access is
// `JsonValue | undefined` under noUncheckedIndexedAccess (a missing key). Each
// predicate returns false for undefined, so a missing field fails validation.
type MaybeJson = JsonValue | undefined

function isRecord(v: MaybeJson): v is JsonObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isNonNegativeInteger(v: MaybeJson): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0
}

function isPositiveInteger(v: MaybeJson): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 1
}

function isNonEmptyString(v: MaybeJson): v is string {
  return typeof v === 'string' && v.length > 0
}

function isKind(v: MaybeJson): v is ManifestEntryKind {
  return v === 'vault' || v === 'identity' || v === 'contact'
}

function isScheme(v: MaybeJson): v is EntryScheme {
  return v === 'zk1' || v === 'zk2'
}

// Validate + narrow a row of a kind THIS version understands. `t`/`id` are already
// validated + de-duped by the caller (parseManifest), which also routes unknown
// kinds to the opaque bucket, so this only runs for known kinds.
function parseKnownEntry(raw: JsonObject, t: ManifestEntryKind, id: string): ManifestEntry {
  const ver = raw['ver']
  if (!isPositiveInteger(ver)) throw new Error('manifest: entry.ver must be a positive integer')

  const parentRaw = raw['parent']
  if (parentRaw !== null && !isNonEmptyString(parentRaw)) {
    throw new Error('manifest: entry.parent must be a non-empty string or null')
  }
  const parent: string | null = parentRaw

  const ordRaw = raw['ord']
  if (ordRaw !== null && !(typeof ordRaw === 'number' && Number.isFinite(ordRaw))) {
    throw new Error('manifest: entry.ord must be a finite number or null')
  }
  const ord: number | null = ordRaw

  const sch = raw['sch']
  if (!isScheme(sch)) throw new Error('manifest: entry.sch must be zk1 or zk2')

  // `inactive` (archived identity). Optional; must be a boolean when present. Carried only
  // when true (an old client that predates the field simply omits it — see the field doc).
  const inactiveRaw = raw['inactive']
  if (inactiveRaw !== undefined && typeof inactiveRaw !== 'boolean') {
    throw new Error('manifest: entry.inactive must be a boolean when present')
  }
  const inactive = inactiveRaw === true ? { inactive: true } : {}

  const etRaw = raw['et']
  if (t === 'vault') {
    if (!isNonEmptyString(etRaw)) {
      throw new Error("manifest: entry.et (the entry's type) is required for t='vault'")
    }
    return { t, id, ver, parent, ord, sch, et: etRaw, ...inactive }
  }
  if (etRaw !== undefined) {
    throw new Error(`manifest: entry.et must be absent for t='${t}'`)
  }
  return { t, id, ver, parent, ord, sch, ...inactive }
}

/** Parse + structurally validate a manifest from its decrypted plaintext bytes. Throws on any malformed field. */
export function parseManifest(bytes: Uint8Array): VaultManifest {
  const raw = parseJson(textDecoder.decode(bytes))
  if (!isRecord(raw)) throw new Error('manifest: not an object')

  const v = raw['v']
  if (!isNonNegativeInteger(v)) throw new Error('manifest: v must be a non-negative integer')

  const entriesRaw = raw['entries']
  if (!Array.isArray(entriesRaw)) throw new Error('manifest: entries must be an array')

  // One pass: validate the common (t,id), reject a duplicate (kind,id) at the trust
  // boundary, then bucket each row. Known kinds are fully validated; unknown (newer)
  // kinds are preserved verbatim (forward-compat). Dedup spans BOTH buckets — the
  // manifest is V-authenticated + client-authored, so a dup is a client bug, not a
  // server attack, but a shadowed entry would collapse in buildManifestLookup /
  // reconcileManifest and could MASK a delete/omit alarm for the shadowed row.
  const known: ManifestEntry[] = []
  const opaque: OpaqueManifestEntry[] = []
  const seen = new Set<string>()
  for (const entryRaw of entriesRaw) {
    if (!isRecord(entryRaw)) throw new Error('manifest: entry is not an object')
    const t = entryRaw['t']
    if (!isNonEmptyString(t)) throw new Error('manifest: entry.t must be a non-empty string')
    const id = entryRaw['id']
    if (!isNonEmptyString(id)) throw new Error('manifest: entry.id must be a non-empty string')

    const key = manifestEntryKey(t, id)
    if (seen.has(key)) throw new Error(`manifest: duplicate entry ${key}`)
    seen.add(key)

    if (isKind(t)) known.push(parseKnownEntry(entryRaw, t, id))
    else opaque.push({ t, id, raw: entryRaw })
  }
  return opaque.length > 0 ? { v, entries: known, opaque } : { v, entries: known }
}

// ── Generation (write side) — pure; the host supplies the live records and the
// encrypt-under-V step, which differs per platform (a browser may hold V as a
// non-extractable key handle where another runtime holds raw bytes).

/**
 * Build the manifest to WRITE after a local change. The caller passes the FULL set of
 * KNOWN-kind entries from its post-change view (a deleted row is simply absent; an
 * edited row carries its bumped `ver`) and the next counter `v`, and this carries the
 * previous manifest's forward-compat `opaque` rows **forward by construction**. That
 * makes "don't strand a newer client's kinds" an invariant of the write path rather
 * than a "remember to re-emit `opaque`" convention.
 *
 * `v` is the caller's already-incremented counter; the server CAS's `expectedVersion`
 * is the PREVIOUS `v`. A known entry can never collide with a carried-forward opaque
 * row — a kind this version understands is, by definition, never opaque to it — so the
 * merge is safe; `serializeManifest`/`parseManifest` still canonicalize + dedup.
 */
export function rebuildManifest(
  previous: VaultManifest,
  knownEntries: readonly ManifestEntry[],
  v: number,
): VaultManifest {
  const carried = previous.opaque ?? []
  return carried.length > 0
    ? { v, entries: knownEntries, opaque: carried }
    : { v, entries: knownEntries }
}

/**
 * A client item's identity + trusted metadata for manifest generation — everything a
 * {@link ManifestEntry} needs EXCEPT `ver`, which this module derives from the prior
 * manifest (never from server-supplied plaintext — the trusted version lives in the
 * manifest).
 */
export interface ManifestItemInput {
  readonly t: ManifestEntryKind
  readonly id: string
  readonly parent: string | null
  readonly ord: number | null
  readonly sch: EntryScheme
  /** Required for `t === 'vault'` (the entry type, which is the AAD type); omitted otherwise. */
  readonly et?: string
  /** `true` for an archived identity (parked — see {@link ManifestEntry.inactive}). */
  readonly inactive?: boolean
}

/**
 * Build the manifest to WRITE from the client's FULL current item set (post-change)
 * and the previous manifest. Per-entry `ver` is the trusted, CLIENT-authored version
 * (never a server-supplied one): carried from the previous manifest,
 * incremented for items whose ciphertext changed this write (`bumpedKeys`), and 1 for a
 * new item. Deleted items are simply absent from `items`. `opaque` (forward-compat)
 * rows carry forward, and `v` (the anti-rollback counter) increments — the CAS's
 * `expectedVersion` is the PREVIOUS `v` (`previous?.v ?? null`).
 *
 * `bumpedKeys` holds `manifestEntryKey(t,id)` for each item re-encrypted this write; a
 * metadata-only change must NOT bump it, so the caller excludes it.
 */
export function buildManifestFromItems(
  items: readonly ManifestItemInput[],
  previous: VaultManifest | null,
  bumpedKeys: ReadonlySet<string>,
): VaultManifest {
  const prior = previous === null ? new Map<string, ManifestEntry>() : buildManifestLookup(previous)
  const entries: ManifestEntry[] = items.map((item) => {
    const key = manifestEntryKey(item.t, item.id)
    const priorEntry = prior.get(key)
    const ver =
      priorEntry === undefined ? 1 : bumpedKeys.has(key) ? priorEntry.ver + 1 : priorEntry.ver
    // Omit `et`/`inactive` when absent/false (exactOptionalPropertyTypes; byte-stability).
    const base = { t: item.t, id: item.id, ver, parent: item.parent, ord: item.ord, sch: item.sch }
    const withEt = item.et === undefined ? base : { ...base, et: item.et }
    return item.inactive === true ? { ...withEt, inactive: true } : withEt
  })
  const v = (previous?.v ?? 0) + 1
  return rebuildManifest(previous ?? { v: 0, entries: [] }, entries, v)
}

/**
 * A single write's LOCAL change to apply to the prior manifest (read-modify-write).
 */
export interface ManifestDelta {
  /** Items added or updated this write (their full {@link ManifestItemInput}). */
  readonly upserts?: readonly ManifestItemInput[]
  /** `manifestEntryKey(t,id)` of items REMOVED (deleted) this write. */
  readonly removes?: ReadonlySet<string>
  /**
   * Of the `upserts`, which had their CIPHERTEXT re-encrypted this write (→ bump `ver`).
   * A metadata-only change (anything that leaves the ciphertext untouched) MUST be ABSENT here:
   * never bump `ver` without a ciphertext change, or the zk2 AAD would mismatch and
   * strand the entry undecryptable.
   */
  readonly bumped?: ReadonlySet<string>
}

/**
 * READ-MODIFY-WRITE the manifest: start from the PRIOR manifest's committed entries and
 * apply ONLY the local `delta`. A concurrent device's rows — present in `prior` but not
 * touched by this write — are PRESERVED, never dropped by a stale local cache, which
 * would orphan them. This is the primitive the write path uses once a
 * manifest exists; `buildManifestFromItems` (full-set build) is only for SEEDING the
 * very first manifest (`prior === null`), where there is nothing to preserve.
 *
 * Per-entry `ver` is client-authored: carried from prior, +1 for a re-encrypted
 * upsert (`bumped`), 1 for a new upsert. `opaque` carries forward; `v` increments; the
 * CAS's `expectedVersion` is the prior `v`.
 */
export function buildManifestFromPrior(
  prior: VaultManifest | null,
  delta: ManifestDelta,
): VaultManifest {
  const byKey = new Map<string, ManifestEntry>()
  if (prior !== null) {
    for (const e of prior.entries) byKey.set(manifestEntryKey(e.t, e.id), e)
  }
  for (const key of delta.removes ?? []) byKey.delete(key)
  const upsertedKeys = new Set<string>()
  for (const item of delta.upserts ?? []) {
    const key = manifestEntryKey(item.t, item.id)
    upsertedKeys.add(key)
    const priorEntry = byKey.get(key)
    const bumped = delta.bumped?.has(key) === true
    const ver = priorEntry === undefined ? 1 : bumped ? priorEntry.ver + 1 : priorEntry.ver
    // `sch` reflects the CIPHERTEXT's scheme, so it may change ONLY on a re-encrypt (i.e. when the
    // key is `bumped`). A metadata-only upsert (archive/restore flipping `inactive`) PRESERVES the
    // committed scheme — otherwise it would flip the manifest `sch` while the ciphertext stays put,
    // stranding the entry undecryptable (e.g. archiving a zk2 identity under a `sch:'zk1'` upsert).
    const sch = priorEntry !== undefined && !bumped ? priorEntry.sch : item.sch
    const base = { t: item.t, id: item.id, ver, parent: item.parent, ord: item.ord, sch }
    const withEt = item.et === undefined ? base : { ...base, et: item.et }
    // An archive/restore upsert flips `inactive`; NOT in `bumped`, so `ver` is preserved above.
    byKey.set(key, item.inactive === true ? { ...withEt, inactive: true } : withEt)
  }
  // A `bumped` key NOT restated in `upserts` is a metadata-preserving ver bump in place —
  // the shape of a content UPDATE, where only the ciphertext (⇒ ver) changes and the
  // entry's parent/ord/et/sch are untouched. The caller need only name the key, not
  // re-derive fields it isn't changing (which would risk a stale parent/ord from cache).
  for (const key of delta.bumped ?? []) {
    if (upsertedKeys.has(key)) continue
    const existing = byKey.get(key)
    if (existing !== undefined) byKey.set(key, { ...existing, ver: existing.ver + 1 })
  }
  const v = (prior?.v ?? 0) + 1
  return rebuildManifest(prior ?? { v: 0, entries: [] }, [...byKey.values()], v)
}

// ── Client wire contract (shared web/mobile) ─────────────────────────────────
// The per-platform decrypt/encrypt (V is raw bytes on one platform vs a
// non-extractable CryptoKey on another), the high-water-mark store, and the UI stay
// platform-specific; these shapes + the pure row-flatten do not.

/** The read-surface shape the server returns for the manifest. */
export interface ManifestBlob {
  readonly encrypted: string | null
  readonly nonce: string | null
  readonly tag: string | null
  readonly version: number | null
}

/** The base64 ciphertext triple a manifest WRITE carries. */
export interface EncryptedManifest {
  readonly encrypted: string
  readonly nonce: string
  readonly tag: string
}

/**
 * The `manifest` object a vault WRITE sends alongside the entry mutation: the fresh
 * ciphertext triple + the CAS `expectedVersion` (the PREVIOUS manifest `v`, or `null`
 * for the account's first manifest).
 */
export interface ManifestWritePayload extends EncryptedManifest {
  readonly expectedVersion: number | null
}

/**
 * A manifest that FAILED to authenticate/parse — a bad GCM tag (tampered ciphertext,
 * wrong user, or wrong version bound in the AAD) or malformed plaintext/response. A
 * POSITIVE tamper signal, NOT a transient error: the read path must alarm on it, never
 * swallow it as "check couldn't run". Distinct from a locked session or a network
 * failure, which are genuinely transient. Shared so the host's `decryptManifest`
 * (which throws it) and its integrity check (which catches it) agree on ONE class
 * across every platform.
 */
export class ManifestTamperError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ManifestTamperError'
  }
}

/**
 * A vault WRITE lost the manifest compare-and-swap (server 409:
 * `MANIFEST_CONFLICT` / `VAULT_EPOCH_MISMATCH` / `MANIFEST_REQUIRED`). A concurrent
 * device advanced the head; the write path re-reads the head, rebuilds on top of it,
 * and retries, bounded. A host maps its transport-layer conflict onto this error so the
 * retry orchestration can distinguish it from a real failure.
 */
export class ManifestConflictError extends Error {
  constructor(message = 'manifest write conflict (409)') {
    super(message)
    this.name = 'ManifestConflictError'
  }
}

/**
 * The three machine-readable 409 `error` codes a vault WRITE can lose the manifest CAS
 * with — ALL retryable by re-reading the head, rebuilding on top, and re-sending.
 * Shared as the single source so the server (which sends them) and every client
 * (which must tell a manifest 409 apart from an unrelated 409, so it never mis-retries
 * the latter) agree on ONE list.
 */
export const MANIFEST_CONFLICT = 'MANIFEST_CONFLICT'
export const MANIFEST_REQUIRED = 'MANIFEST_REQUIRED'
export const VAULT_EPOCH_MISMATCH = 'VAULT_EPOCH_MISMATCH'

const MANIFEST_CONFLICT_CODES: ReadonlySet<string> = new Set([
  MANIFEST_CONFLICT,
  MANIFEST_REQUIRED,
  VAULT_EPOCH_MISMATCH,
])

/**
 * True when a 409 response body's `error` code is one of the manifest-CAS codes. A
 * client turns ONLY these into a retryable `ManifestConflictError`; any other 409
 * (a future non-manifest conflict) must fail fast rather than loop the rebuild-retry.
 */
export function isManifestConflictCode(code: string | null | undefined): boolean {
  return typeof code === 'string' && MANIFEST_CONFLICT_CODES.has(code)
}

/**
 * Flatten the three decrypted vault lists into the `(kind, id)` key set the reconcile
 * compares the manifest against. The caller MUST pass the COMPLETE live rows of each
 * kind (all pages) — a partial set would flag the un-fetched rows as `missing`.
 */
/**
 * Whether an identity `status` is a live manifest member. Archived and deleted identities
 * are excluded (archive removes an entry, restore re-adds it), so a first-seed snapshot and
 * a delta-maintained manifest agree on membership. A missing status is treated as a member.
 */
export function isActiveManifestIdentity(status?: string): boolean {
  return status !== 'archived' && status !== 'deleted'
}

export function gatherServerRows(
  vaultEntries: readonly { readonly id: string }[],
  identities: readonly { readonly id: string; readonly status?: string }[],
  contacts: readonly { readonly id: string }[],
): EntryKey[] {
  return [
    ...vaultEntries.map((e): EntryKey => ({ t: 'vault', id: e.id })),
    ...identities
      .filter((i) => isActiveManifestIdentity(i.status))
      .map((i): EntryKey => ({ t: 'identity', id: i.id })),
    ...contacts.map((c): EntryKey => ({ t: 'contact', id: c.id })),
  ]
}

/**
 * Confirm a verdict before treating it as a tamper. A `rollback` is deterministic and
 * returned as-is; a `missing` set can be a transient read of stale rows, so it is
 * re-checked via `reconcileFresh` (a fresh reconcile the caller supplies) and only that
 * re-checked result is returned.
 */
export async function confirmVaultVerdict(
  verdict: ManifestVerdict,
  reconcileFresh: () => Promise<ManifestVerdict>,
): Promise<ManifestVerdict> {
  if (verdict.rollback || verdict.missing.length === 0) return verdict
  return reconcileFresh()
}

// The decrypted list-item fields the manifest generator reads (structurally the same
// on web + mobile, so this mapping is shared, not per-platform).
export interface VaultEntryItemInput {
  readonly id: string
  /** The parent identity id → the manifest entry's trusted `parent`. */
  readonly identityId: string
  /** The entry's type → the vault entry's AAD type (`et`). */
  readonly entryType: string
  /** The display order → the manifest entry's `ord`. */
  readonly sortOrder: number | null
}
export interface IdentityItemInput {
  readonly id: string
  /** Identity lifecycle status; archived/deleted are excluded from the manifest. */
  readonly status?: string
}
export interface ContactItemInput {
  readonly id: string
}

/**
 * Map the client's decrypted vault / identity / contact lists into
 * {@link ManifestItemInput}s for {@link buildManifestFromItems}. Shared across web +
 * mobile — the platforms differ in HOW they fetch/decrypt the lists, not in this
 * field mapping.
 *
 * `toManifestItems` seeds every item at `sch: 'zk1'`; a caller that has re-encrypted an
 * item under `zk2` sets `sch` itself (under `zk1` the per-entry `ver`/`ord` are not
 * load-bearing).
 */
export function toManifestItems(
  vaultEntries: readonly VaultEntryItemInput[],
  identities: readonly IdentityItemInput[],
  contacts: readonly ContactItemInput[],
): ManifestItemInput[] {
  return [
    ...vaultEntries.map(
      (e): ManifestItemInput => ({
        t: 'vault',
        id: e.id,
        parent: e.identityId,
        ord: e.sortOrder,
        sch: 'zk1',
        et: e.entryType,
      }),
    ),
    // Archived identities are KEPT (parked with `inactive:true`) so their `ver`/`sch` survive the
    // archive↔restore cycle and the archived-tab zk2 read has a trusted entry. Only a true DELETE
    // is a removal.
    ...identities
      .filter((i) => i.status !== 'deleted')
      .map(
        (i): ManifestItemInput =>
          i.status === 'archived'
            ? { t: 'identity', id: i.id, parent: null, ord: null, sch: 'zk1', inactive: true }
            : { t: 'identity', id: i.id, parent: null, ord: null, sch: 'zk1' },
      ),
    ...contacts.map(
      (c): ManifestItemInput => ({ t: 'contact', id: c.id, parent: null, ord: null, sch: 'zk1' }),
    ),
  ]
}

// ── Manifest AAD ────────────────────────────────────────────────────────────

/**
 * Domain tag leading the manifest AAD. Both the manifest and vault entries are
 * encrypted under the SAME key V, so their AADs must be domain-separated by
 * construction — not merely by incidental framing differences. The zk2 entry AAD
 * leads with `"zk2"` and the escrow attestation with its own domain; the manifest
 * leads with this. MUST NOT change once any manifest ciphertext exists.
 */
const MANIFEST_AAD_DOMAIN = 'vmanifest-v1'

/**
 * AAD for the manifest ciphertext: binds `"vmanifest-v1" || userId || version`, so a
 * manifest can't be decrypted as an entry (or vice
 * versa) under the shared V, can't be relocated to another account, and its
 * version can't be swapped. Returns an ArrayBuffer-backed view (Web Crypto
 * additionalData).
 */
export function buildManifestAad(
  userId: string,
  manifestVersion: number | bigint,
): Uint8Array<ArrayBuffer> {
  const framed = lengthPrefixedConcat([
    textEncoder.encode(MANIFEST_AAD_DOMAIN),
    textEncoder.encode(userId),
    u64be(manifestVersion),
  ])
  const out = new Uint8Array(framed.length)
  out.set(framed)
  return out
}

// ── Reconciliation — pure logic; the host's read path supplies the
// decrypted manifest, the server's returned rows, and the device high-water-mark,
// and enforces the verdict. No crypto or I/O here, so it's fully unit-testable.

/** Identifies a row in a server list response, for matching against the manifest. */
export interface EntryKey {
  readonly t: ManifestEntryKind
  readonly id: string
}

export interface ManifestReconciliation {
  /** The server handed back a manifest older than one this device has already seen. */
  readonly rollbackAlarm: boolean
  /** Rows the manifest lists that the server did NOT return — a delete / omit tamper. */
  readonly missing: readonly ManifestEntry[]
  /** Rows the server returned that are NOT in the manifest — server-injected; ignore, don't render. */
  readonly extra: readonly EntryKey[]
}

/** Index a manifest by `<kind>:<id>` so the read path can look up an entry's trusted ver/parent/ord/scheme. */
export function buildManifestLookup(manifest: VaultManifest): Map<string, ManifestEntry> {
  const lookup = new Map<string, ManifestEntry>()
  for (const entry of manifest.entries) lookup.set(manifestEntryKey(entry.t, entry.id), entry)
  return lookup
}

/**
 * Reconcile a decrypted manifest against the rows the (untrusted) server returned
 * and the device's stored high-water-mark. Reports rollback (version regressed),
 * missing (deleted/omitted) rows, and extra (server-injected) rows. The caller
 * turns these into alarms and drops the extras; per-entry rollback/re-parent is
 * caught separately at decrypt time by the zk2 AAD.
 */
export function reconcileManifest(
  manifest: VaultManifest,
  serverRows: readonly EntryKey[],
  deviceHighWaterMark: number,
): ManifestReconciliation {
  const serverSet = new Set(serverRows.map((k) => manifestEntryKey(k.t, k.id)))
  // `manifestSet` includes PARKED (inactive) entries, so an archived row that a server returns is
  // never flagged `extra`; `missing` EXCLUDES parked entries (they aren't in the active render set,
  // so their absence there is not a delete tamper — see ManifestEntry.inactive).
  const manifestSet = new Set(manifest.entries.map((e) => manifestEntryKey(e.t, e.id)))
  return {
    rollbackAlarm: manifest.v < deviceHighWaterMark,
    missing: manifest.entries.filter(
      (e) => e.inactive !== true && !serverSet.has(manifestEntryKey(e.t, e.id)),
    ),
    extra: serverRows.filter((k) => !manifestSet.has(manifestEntryKey(k.t, k.id))),
  }
}

/** The verdict the platform read path enforces after a manifest reconcile. */
export interface ManifestVerdict {
  /**
   * The server rolled the manifest BACK — served an older version than this device's
   * high-water-mark, OR deleted a manifest the device had already seen (`null`
   * manifest while `HWM >= 1`). Both are anti-rollback alarms.
   */
  readonly rollback: boolean
  /** Manifest-listed rows the server did NOT return — a delete/omit tamper. */
  readonly missing: readonly ManifestEntry[]
  /**
   * Rows the server returned that the manifest does NOT list — server-injected; the
   * caller MUST drop them (they'd also fail their own zk2 AAD). NOT on its own a
   * `tampered` alarm: a concurrent device's just-added row can appear here in a
   * benign race, so the read path re-fetches to rule that out before alarming.
   */
  readonly extra: readonly EntryKey[]
  /** A hard tamper (rollback or missing rows) was detected — the read path must alarm. */
  readonly tampered: boolean
  /**
   * The high-water-mark the caller should persist (`advanceManifestHwm`) after this
   * reconcile. Never below the input HWM: advances to the manifest version on a clean
   * (non-rollback) read, and holds the current floor on a rollback so a replay can't
   * lower it.
   */
  readonly nextHwm: number | null
}

/**
 * Orchestrate a full read-path manifest reconcile: compare the DECRYPTED manifest
 * (or `null` = the server claims there is none) against the rows the server returned
 * and the device's stored high-water-mark, and produce the {@link ManifestVerdict}
 * the platform enforces (alarm on tamper, drop `extra`, advance the HWM).
 *
 * This is where the case `decryptManifest` deferred is decided: a `null` manifest
 * while the device already holds a HWM (`>= 1`) is a manifest DELETION — a rollback
 * tamper — not the genuine pre-manifest (TOFU) state.
 *
 * Pure: the platform supplies the decrypted manifest, the server rows, and the HWM;
 * it never reads crypto or I/O here, so it is fully unit-testable and identical
 * across web + mobile.
 */
export function evaluateManifest(
  manifest: VaultManifest | null,
  serverRows: readonly EntryKey[],
  deviceHighWaterMark: number | null,
): ManifestVerdict {
  if (manifest === null) {
    // No manifest served. Never seen one (`null` HWM) → genuine pre-manifest state:
    // trust everything, advance nothing (TOFU). Seen one before → the server hid it:
    // rollback tamper, and hold the floor.
    const deleted = deviceHighWaterMark !== null
    return {
      rollback: deleted,
      missing: [],
      extra: [],
      tampered: deleted,
      nextHwm: deviceHighWaterMark,
    }
  }

  // TOFU (`null` HWM) uses the manifest's own version as the floor, so a first sight
  // never self-alarms; an established floor uses the stored HWM.
  const floor = deviceHighWaterMark === null ? manifest.v : deviceHighWaterMark
  const { rollbackAlarm, missing, extra } = reconcileManifest(manifest, serverRows, floor)
  return {
    rollback: rollbackAlarm,
    missing,
    extra,
    tampered: rollbackAlarm || missing.length > 0,
    // On a non-rollback read `manifest.v >= floor >= HWM`, so the manifest version is
    // the new floor. On a rollback, hold the current HWM (never let a replay lower it).
    nextHwm: rollbackAlarm ? deviceHighWaterMark : manifest.v,
  }
}

/**
 * Whether a reader that holds this manifest MUST decrypt this entry with `zk2` and
 * refuse a `zk1` fallback, so a server cannot force a downgrade. The host's decrypt
 * ladder consults this before allowing the legacy `zk1` path.
 */
export function mustUseZk2(entry: ManifestEntry): boolean {
  return entry.sch === 'zk2'
}

/**
 * The AAD `type`(s) of the blob(s) a row carries — what the zk2 AAD's `entryType`
 * must be for each ciphertext on the row. A vault row's type is its (trusted)
 * `et`; identity/contact types are fixed by kind (a contact carries both its data
 * blob and, when present, an avatar blob).
 */
export function aadTypesForEntry(entry: ManifestEntry): readonly string[] {
  switch (entry.t) {
    case 'vault':
      if (entry.et === undefined) {
        throw new Error('manifest: vault entry is missing et (its type)')
      }
      return [entry.et]
    case 'identity':
      return ['identity']
    case 'contact':
      return ['contact', 'contact-avatar']
  }
}

/**
 * Bridge a manifest entry + a blob's AAD type to {@link buildEntryAadV2}'s params,
 * feeding the TRUSTED version/parent from the manifest (never the server's plaintext
 * columns) and mapping a root row's `null` parent to the {@link ZK2_NO_PARENT}
 * sentinel.
 */
export function entryAadV2ParamsFor(entry: ManifestEntry, aadType: string): EntryAadV2Params {
  return {
    entryType: aadType,
    entryId: entry.id,
    entryVersion: entry.ver,
    parentId: entry.parent === null ? ZK2_NO_PARENT : entry.parent,
  }
}

/**
 * Order two entries by the manifest's trusted `ord` (so the client renders in the
 * manifest's order, not the server-held, re-orderable display order). A
 * `null` ord (a contact, which has no server order) sorts last; ties break by id
 * for a stable, deterministic order.
 */
export function compareManifestOrder(a: ManifestEntry, b: ManifestEntry): number {
  const ao = a.ord
  const bo = b.ord
  if (ao !== null && bo !== null && ao !== bo) return ao - bo
  if (ao === null && bo !== null) return 1
  if (ao !== null && bo === null) return -1
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}
