/**
 * `zk2` per-entry AAD — the version-2 stamp baked into a vault entry's AES-GCM
 * lock.
 *
 * The v1 stamp (wire format `zk1:<type>:<id>`) binds a ciphertext to its own
 * record, so a server can't swap blob A into record B. But it says nothing about
 * the *set*: a malicious server can still serve an OLDER ciphertext for a record
 * (rollback), or rewrite the stored parent reference to move an entry under a
 * different parent (re-parenting). Both go undetected under `zk1`.
 *
 * `zk2` closes those by extending the AAD to also bind the entry's monotonic
 * version and its parent id:
 *
 *   zk2 AAD = lengthPrefixedConcat([ "zk2", type, id, u64be(version), parentId ])
 *
 * The load-bearing rule: the `entryVersion` and `parentId` fed here come from the
 * client's authenticated vault manifest, NEVER from server-supplied plaintext.
 * Then:
 *   - Rollback: the server serves a blob encrypted at version 4; the client
 *     decrypts with the manifest's current version 7 as AAD → AES-GCM auth fails
 *     → the stale blob is detected. The server can't lie about the version too,
 *     because the version comes from the manifest authenticated under the vault
 *     key, not from a field the server controls.
 *   - Re-parent: the server rewrites the stored parent reference; the client
 *     decrypts with the manifest's parent → auth fails.
 *
 * MUST stay byte-identical across every platform that reads the data — an entry
 * encrypted on one has to decrypt on another, so all of them build the AAD
 * through this one function. It reuses the shared `lengthPrefixedConcat` framing
 * rather than re-implementing it, so the framing can never drift between them.
 *
 * A user id is intentionally NOT included, for the same reason as `zk1`: the
 * vault key is already per-account (cross-account swaps fail on the key) and the
 * entry UUID is globally unique.
 *
 * `zk1` and `zk2` are deliberately distinct schemes with distinct AAD bytes: a
 * record migrates zk1→zk2 lazily on its next write, and the stored scheme marker
 * records which applies. A reader holding a manifest MUST refuse the zk1 fallback
 * for any entry the manifest marks as zk2, so a server cannot force a downgrade.
 * That dual-scheme read dispatch belongs to the host application; this module is
 * the pure byte producer.
 */

import { lengthPrefixedConcat, u64be } from './bytes.js'

/** Scheme tag that leads the v2 AAD, distinguishing it from the `zk1:` prefix. */
const ZK2_SCHEME_TAG = 'zk2'

/**
 * Sentinel `parentId` for entries that have no parent. Only child records hang
 * off a parent; root records use this sentinel. A
 * real parent is always a UUID, so this reserved
 * non-UUID token can never collide with one, and — being length-prefixed like
 * every other field — it stays unambiguous. MUST NOT change once any `zk2`
 * ciphertext exists (it is part of the wire contract).
 */
export const ZK2_NO_PARENT = 'zk2-no-parent'

export interface EntryAadV2Params {
  /**
   * Entry kind — the same discriminator the v1 AAD takes as `entryType`
   * (e.g. `'password'`, `'identity'`, `'contact'`, `'contact-avatar'`).
   */
  readonly entryType: string
  /** The entry's globally-unique id (UUID). */
  readonly entryId: string
  /**
   * The entry's monotonic version. MUST come from the client's authenticated
   * manifest, NOT from server-supplied plaintext — that binding is what makes
   * rollback detectable. `number` for the common case; `bigint` if a counter ever
   * exceeds 2^53.
   */
  readonly entryVersion: number | bigint
  /**
   * The parent identity id (an identity UUID) for a vault entry, or
   * {@link ZK2_NO_PARENT} for a root entry (identity / contact). MUST come from
   * the manifest, not from server-supplied plaintext.
   */
  readonly parentId: string
}

const textEncoder = new TextEncoder()

/**
 * Build the `zk2` AAD bytes for an entry. Returns an ArrayBuffer-backed
 * `Uint8Array` (Web Crypto's `additionalData` requires it), matching the v1
 * builder's return type so the two are interchangeable at call sites.
 */
export function buildEntryAadV2(params: EntryAadV2Params): Uint8Array<ArrayBuffer> {
  const framed = lengthPrefixedConcat([
    textEncoder.encode(ZK2_SCHEME_TAG),
    textEncoder.encode(params.entryType),
    textEncoder.encode(params.entryId),
    u64be(params.entryVersion),
    textEncoder.encode(params.parentId),
  ])
  // Copy into a fresh ArrayBuffer-backed view: lengthPrefixedConcat is typed
  // Uint8Array<ArrayBufferLike>, and additionalData needs Uint8Array<ArrayBuffer>.
  const out = new Uint8Array(framed.length)
  out.set(framed)
  return out
}

/**
 * `zk1` per-entry AAD — the version-1 stamp. Binds a ciphertext to its own record
 * (`entryType + entryId`) so a server can't swap blob A into record B, but says
 * nothing about the entry's version or parent (see `buildEntryAadV2` for that).
 *
 * v1 wire format: UTF-8 of `zk1:<entryType>:<entryId>`. Returns an ArrayBuffer-backed
 * `Uint8Array` (Web Crypto's `additionalData` requires it).
 *
 * userId is intentionally NOT included: the vault key is already per-account, so
 * cross-user swaps fail on the key, and the entry's UUID is globally unique — so
 * `entryType + entryId` fully discriminates every entry within an account.
 *
 * MUST stay byte-identical across every platform that reads the data, and FROZEN:
 * existing ciphertexts depend on these exact bytes, so it MUST NOT change. Any other
 * implementation must reproduce `zk1:<type>:<id>` byte-for-byte; the test pins the wire
 * format so no copy can drift from the spec. This copy is the one the shared
 * `entry-aad-dispatch` helpers use.
 */
export function buildEntryAad(entryType: string, entryId: string): Uint8Array<ArrayBuffer> {
  const bytes = textEncoder.encode(`zk1:${entryType}:${entryId}`)
  const out = new Uint8Array(bytes.length)
  out.set(bytes)
  return out
}
