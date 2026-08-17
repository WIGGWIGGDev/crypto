/**
 * Scheme version registry.
 *
 * Each versioned dimension lets a primitive rotate without breaking blobs that
 * were written under an older scheme: readers dispatch on the version recorded
 * in the blob, and writers always use the matching `*_CURRENT_VERSION` constant.
 * Parameter sets per version live in ./params.ts.
 */

// Hybrid public-key scheme: X25519 ECDH, HKDF-SHA256, then XChaCha20-Poly1305.
export const ASYMMETRIC_SCHEME_CURRENT_VERSION = 1 as const

// A master key sealed to a recovery key, using the same construction as the
// asymmetric scheme over the 32-byte master key.
export const WRAPPED_MASTER_KEY_CURRENT_VERSION = 1 as const

// Recovery escrow, version 2: the SAME X25519 seal construction, but its
// plaintext is the 32-byte Vault Key V, NOT the master key M. V is preserved
// across KDF rotations and password changes, so a v2 escrow doesn't need
// re-sealing on every M-rotation — which eliminates the automatic re-seal paths a
// malicious server could target by substituting its own recovery key. This is a
// SEPARATE constant from WRAPPED_MASTER_KEY_CURRENT_VERSION on purpose: the sites
// that still seal M must stay pinned at 1, so a v2 escrow must never be produced
// by bumping the M constant. A recovering client dispatches on this value to
// decide whether the unsealed 32 bytes are V (===2) or M (else), then
// self-validates before trusting them.
export const WRAPPED_VAULT_ESCROW_VERSION = 2 as const

// Per-login challenge-response auth: the client derives a signing keypair from
// the master key and signs a fresh server challenge, and the server keeps only
// the public key. v1 is Ed25519 over HKDF-SHA256(masterKey); see ./auth-signing.
export const AUTH_SCHEME_CURRENT_VERSION = 1 as const

// Recovery-auth challenge-response: at recovery, the client signs a fresh server
// challenge with a keypair derived from the BIP39 mnemonic (NOT the master key),
// so a v2 escrow that yields V but no M can still authorize a password-change.
// v1 is Ed25519 over HKDF-SHA256 of the recovery seed (domain-separated from the
// X25519 seal key); see ./recovery/ed25519-auth-from-mnemonic.
export const RECOVERY_AUTH_SCHEME_CURRENT_VERSION = 1 as const

// Password-stretching KDF that turns a password or PIN into the master key (and
// other stretched keys).
//   v1: PBKDF2-SHA256, 600k iterations (legacy read path).
//   v2: Argon2id, memory-hard.
// Readers keep supporting every prior version until no blob is left on it.
export const KDF_CURRENT_VERSION = 2 as const

// Vault-key indirection.
//   v0: the master key encrypts vault data directly, so rotating the KDF means
//       re-encrypting every entry.
//   v1: a random per-account vault key encrypts the data and the master key only
//       wraps that vault key, so a KDF rotation re-wraps a single key.
export const VAULT_KEY_CURRENT_VERSION = 1 as const

// Server-side symmetric key for the operational fields the server must read.
// Tracked here for completeness; rotation happens server-side.
export const SERVER_KEY_CURRENT_VERSION = 1 as const

// Which key generation encrypted a given vault entry. Lets a re-encryption pass
// leave partial state (some entries on v1, some on v2) and resume cleanly.
export const ENCRYPTION_KEY_CURRENT_VERSION = 1 as const

// Stable labels for audit logs and support tooling, so a consumer can name a
// version without reaching for its parameters.

export const KDF_VERSION_LABELS: Readonly<Record<number, string>> = {
  1: 'pbkdf2-sha256-600k',
  2: 'argon2id-default',
}

export const VAULT_KEY_VERSION_LABELS: Readonly<Record<number, string>> = {
  0: 'direct-master-key',
  1: 'indirection-v1',
}

export const ASYMMETRIC_SCHEME_LABELS: Readonly<Record<number, string>> = {
  1: 'x25519-hkdf-xchacha20poly1305',
}

export const WRAPPED_MASTER_KEY_LABELS: Readonly<Record<number, string>> = {
  1: 'x25519-hkdf-xchacha20poly1305',
  2: 'x25519-hkdf-xchacha20poly1305-vault-key',
}

export const SERVER_KEY_LABELS: Readonly<Record<number, string>> = {
  1: 'aes-256-gcm-v1',
}

export const AUTH_SCHEME_LABELS: Readonly<Record<number, string>> = {
  1: 'ed25519-hkdf-sha256',
}

export const RECOVERY_AUTH_SCHEME_LABELS: Readonly<Record<number, string>> = {
  1: 'ed25519-recovery-hkdf-sha256',
}

const LABEL_TABLES = {
  kdf: KDF_VERSION_LABELS,
  vault_key: VAULT_KEY_VERSION_LABELS,
  asymmetric_scheme: ASYMMETRIC_SCHEME_LABELS,
  wrapped_master_key: WRAPPED_MASTER_KEY_LABELS,
  server_key: SERVER_KEY_LABELS,
  auth_scheme: AUTH_SCHEME_LABELS,
  recovery_auth_scheme: RECOVERY_AUTH_SCHEME_LABELS,
} as const

/**
 * Names a (dimension, version) pair for display. Returns `unknown(<n>)` for a
 * version it doesn't recognize rather than throwing, so logging never crashes on
 * a future version.
 */
export function describeVersion(dimension: keyof typeof LABEL_TABLES, version: number): string {
  return LABEL_TABLES[dimension][version] ?? `unknown(${version})`
}
