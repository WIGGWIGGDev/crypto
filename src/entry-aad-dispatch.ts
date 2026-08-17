/**
 * Per-entry AAD dispatch. Picks the AAD an entry's ciphertext is bound
 * to — and, on the read side, whether that AAD must be used EXCLUSIVELY — dispatched on the
 * FINALIZED manifest entry's committed scheme (`sch`):
 *   - `zk2` → v2 AAD binding `{type, id, ver, parent}` read from the trusted manifest entry
 *     (defeats single-entry rollback / re-parent).
 *   - `zk1`, OR no manifest entry (manifest layer inactive) → the frozen v1 AAD
 *     (`type + id`), byte-identical to every zk1 ciphertext.
 *
 * `ver`/`parent` come ONLY from the committed manifest entry — never server-supplied
 * plaintext — so a malicious server cannot skew the binding.
 *
 * These are pure functions over the manifest + the frozen AAD byte producers, identical on every
 * platform — so they live here (one shared copy) rather than hand-duplicated per app, where they
 * could drift and break cross-platform decrypt.
 */

import {
  entryAadV2ParamsFor,
  mustUseZk2,
  type ManifestEntry,
  type ManifestEntryKind,
  type VaultManifest,
} from './vault-manifest.js'
import { buildEntryAad, buildEntryAadV2 } from './zk-entry-aad.js'

/**
 * The committed manifest entry for a `(kind, id)` row, or `undefined` when the manifest layer
 * is inactive (`committed` undefined) or the row isn't tracked — in which case the caller
 * encrypts under the frozen v1 AAD.
 */
export function findCommittedEntry(
  committed: VaultManifest | undefined,
  t: ManifestEntryKind,
  id: string,
): ManifestEntry | undefined {
  return committed?.entries.find((e) => e.t === t && e.id === id)
}

/** The AAD one blob of a manifest-tracked entry is encrypted under, dispatched on `entry.sch`. */
export function entryWriteAad(
  entry: ManifestEntry | undefined,
  aadType: string,
  entryId: string,
): Uint8Array<ArrayBuffer> {
  if (entry !== undefined && mustUseZk2(entry)) {
    return buildEntryAadV2(entryAadV2ParamsFor(entry, aadType))
  }
  return buildEntryAad(aadType, entryId)
}

export interface EntryReadAad {
  readonly aad: Uint8Array<ArrayBuffer>
  /**
   * When true (committed `sch:'zk2'`), the decrypt ladder MUST try ONLY this v2 AAD and refuse
   * every fallback — a server cannot downgrade a zk2 row to zk1/no-AAD. A v2 AAD failure is
   * then a fail-CLOSED miss (stale-cache retry or hard undecryptable), never a wrong plaintext.
   */
  readonly exactAadOnly: boolean
}

/**
 * READ-path AAD dispatch: the AAD to decrypt under, plus whether the ladder must use it
 * EXCLUSIVELY. `zk2` committed entry → v2 AAD + `exactAadOnly:true`; `zk1` / no committed entry
 * → the frozen v1 AAD + `exactAadOnly:false` (the full dual-key ladder runs, byte-identical to
 * the zk1 path). Read sibling of {@link entryWriteAad}; same byte producer, plus the downgrade gate.
 */
export function entryReadAad(
  entry: ManifestEntry | undefined,
  aadType: string,
  entryId: string,
): EntryReadAad {
  if (entry !== undefined && mustUseZk2(entry)) {
    return { aad: buildEntryAadV2(entryAadV2ParamsFor(entry, aadType)), exactAadOnly: true }
  }
  return { aad: buildEntryAad(aadType, entryId), exactAadOnly: false }
}
