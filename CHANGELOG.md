# Changelog

Notable changes to this package are recorded here. It follows
[Semantic Versioning](https://semver.org).

## 0.3.0

- **Per-entry AAD dispatch** (`entry-aad-dispatch.ts`): picks the AAD an entry's ciphertext is
  bound to from the committed manifest entry's scheme, and on read refuses every fallback once
  an entry is committed to the `zk2` binding, so a server cannot downgrade it.
- **Conformance vectors** (`asymmetric/conformance-vectors.ts`): HChaCha20 and
  XChaCha20-Poly1305 known-answers plus one complete sealed envelope, shared with the native
  ports' test suites. The storage-level scheme id constant is named
  `ENVELOPE_STORAGE_SCHEME` to keep it visibly distinct from the envelope's version byte.
- **Documentation pass:** comments rewritten as documentation for an outside reader (no
  internal bookkeeping); README names the two independent version namespaces.

## 0.2.0

- **Recovery escrow seals the vault key** instead of the master key
  (`WRAPPED_VAULT_ESCROW_VERSION`). The vault key is stable across password changes, so the
  escrow no longer has to be automatically re-sealed — removing the re-seal a malicious
  server could target with a substituted recovery key.
- **Mnemonic-derived Ed25519 recovery-auth key** (`recovery/ed25519-auth-from-mnemonic.ts`),
  domain-separated from the X25519 escrow key, so a recovering client can prove possession of
  the phrase over a single-use server challenge.
- **Recovery escrow self-checks:** `vault-key-commitment.ts` (positive check that the
  unsealed key is the right one, including for accounts with no data rows) and
  `escrow-attestation.ts` (a phrase-signed attestation the _client_ verifies before trusting
  a server-supplied escrow).
- **Vault-collection integrity primitives:** `vault-manifest.ts`, the AEAD packing list of the
  vault authenticated under the vault key with a monotonic anti-rollback counter, and
  `zk-entry-aad.ts`, the `zk2` per-entry AAD binding a ciphertext to its row, version, and
  parent.
- **Shared framing:** `signed-payload.ts` (domain-tagged, length-prefixed Ed25519 payload
  framing used by every signing call site) and `bytes.ts` (constant-time equality).
- **Key-derivation split:** `kdf/subkey.ts`, domain-separated per-purpose subkeys from one
  strong key.
- **Decrypt-failure classification:** `encryption/decrypt-error.ts` distinguishes wrong-key,
  malformed-input, and AAD-mismatch failures for diagnostics while keeping the user-facing
  message identical.

## 0.1.0

Initial public release: Argon2id and PBKDF2 key derivation, AES-256-GCM, the X25519 sealed
box, Ed25519 authentication signing, BIP-39 recovery-key derivation, the PIN-unlock envelope,
and the scheme-version registry.
