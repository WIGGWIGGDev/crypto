# @wiggwigg/crypto

The cryptographic core of [WIGGWIGG](https://wiggwigg.ca), a privacy-first phone-number and
identity product. These are the key-derivation, encryption, sealing, and signing primitives that define how the
WIGGWIGG clients protect your data on your device. Both the web and the mobile app run this
code directly, and both delegate bulk AES-GCM and HMAC to their platform's accelerated
implementation (Web Crypto in the browser) at the same parameters and byte formats, so the two
interoperate exactly. The client-side algorithms, versions, and wire formats of the
zero-knowledge core are the ones defined here.

This repository is open so the cryptography can be reviewed independently of the rest of the
application, which is closed source. The
[security whitepaper](https://wiggwigg.ca/en/security/whitepaper/) describes how these
primitives fit together and where the guarantees end.

## What's here

- **Key derivation** (`kdf/`): Argon2id for password and PIN stretching, with PBKDF2-SHA256
  kept for reading data written under the older scheme. Both accept an injected native
  implementation and fall back to pure JS. `subkey.ts` splits one strong key into
  domain-separated per-purpose subkeys.
- **Symmetric encryption** (`encryption/`): AES-256-GCM over raw keys, plus a shared
  decrypt-failure error that classifies _why_ an AEAD open failed without becoming a
  padding-oracle.
- **Public-key sealing** (`asymmetric/`): a libsodium-style sealed box (X25519 ECDH,
  HKDF-SHA256, then XChaCha20-Poly1305).
- **Authentication signing** (`auth-signing/`): Ed25519 challenge-response derived from the
  master key.
- **Authentication proof** (`auth-proof/`): the legacy HMAC-SHA256 proof-of-knowledge that
  `auth-signing` supersedes, kept to read verifiers written under the earlier scheme.
- **Recovery** (`recovery/`): from one BIP-39 mnemonic, two domain-separated keys — an X25519
  key that the recovery escrow is sealed to, and an Ed25519 key that proves possession of the
  phrase. Plus the vault-key commitment and the client-verifiable escrow attestation that let
  a recovering client check the escrow before trusting it.
- **PIN unlock** (`pin-unlock/`): a master key wrapped under a PIN-derived AES key.
- **Vault integrity** (`vault-manifest.ts`, `zk-entry-aad.ts`, `entry-aad-dispatch.ts`): the
  AEAD "packing list" of the vault, authenticated under the vault key; the per-entry AAD that
  binds a ciphertext to its row, version, and parent; and the dispatch that picks the AAD an
  entry is bound to (and, on read, refuses any downgrade once an entry is committed to the
  v2 binding). Together they let a client detect a server that deletes, rolls back, or
  re-parents entries.
- **Conformance vectors** (`asymmetric/conformance-vectors.ts`): the known-answer vectors
  (HChaCha20, XChaCha20-Poly1305, and one complete sealed envelope) that the native ports pin
  their implementations to.
- **Shared framing** (`signed-payload.ts`, `bytes.ts`): domain-tagged, length-prefixed byte
  framing for everything Ed25519-signed, and constant-time byte equality.
- **Scheme versions** (`versions.ts`, `params.ts`): the registry that lets a primitive
  rotate without breaking data written under an older version.

It is built on [`@noble`](https://github.com/paulmillr/noble-curves) and
[`@scure`](https://github.com/paulmillr/scure-bip39). We do not implement our own
primitives.

## Design

- **No platform crypto at the boundary.** The package never imports Web Crypto, Node
  `crypto`, or a native module directly. Where a primitive needs a native implementation for
  speed (Argon2id, PBKDF2), the host registers it at startup and the package routes through
  it, falling back to pure JS otherwise. The one platform surface it does use is the
  standard CSPRNG, `crypto.getRandomValues`, for nonces and salts. The same source runs in
  browsers, Node, and React Native.
- **Domain-separated keys.** Every key derived from another is domain-separated — HKDF-SHA256
  under a distinct `info` tag, or HMAC-SHA256 over a distinct label — so compromise of one
  derived key never yields another. Note what is _not_ derived from the master key: the vault
  key is random and only wrapped by it, and the recovery keys come from the BIP-39 mnemonic.
- **Versioned schemes.** Each on-disk format carries a version; readers dispatch on it and
  writers use the current version, so a primitive can rotate without a rewrite. Two version
  namespaces are easy to conflate and are independent: the sealed envelope's own version byte
  (`ASYMMETRIC_SCHEME_CURRENT_VERSION`, 1 = this X25519 sealed box) identifies the envelope
  format, while a store may keep its own per-record scheme id (for example 2 = this sealed
  box, 1 = a legacy RSA-OAEP wrap) to dispatch a reader; `ENVELOPE_STORAGE_SCHEME` in the
  conformance vectors pins the two apart.

## Usage

```ts
import { seal, open, generateX25519Keypair } from '@wiggwigg/crypto/asymmetric'

const recipient = generateX25519Keypair()
const envelope = seal(recipient.publicKey, new TextEncoder().encode('hello'))
const plaintext = open(recipient.privateKey, recipient.publicKey, envelope)
```

Subpath exports mirror the directories: `@wiggwigg/crypto/kdf`, `/encryption`, `/asymmetric`,
`/auth-signing`, `/auth-proof`, `/recovery`, `/pin-unlock`, `/params`, `/versions`, plus the
package root, which also carries the vault-manifest, entry-AAD, signing-framing, and
byte-comparison helpers.

Publishing to npm is planned. For now, build from source:

```
npm install
npm run build
```

## Security review

This code is self-attested today and built on the established `@noble` and `@scure`
libraries rather than home-grown primitives. It has not had an independent third-party audit;
one is planned, and we will publish it when it is complete. Open source proves the design and
the client-side primitives; it does not by itself prove that any server runs them unmodified.
See the [whitepaper](https://wiggwigg.ca/en/security/whitepaper/) for the full scope.

To report a vulnerability, see [SECURITY.md](./SECURITY.md) or our
[vulnerability-disclosure policy](https://wiggwigg.ca/en/security/disclosure/).

## About this repository

This is a read-only mirror, generated from the WIGGWIGG monorepo where the code is developed
and tested. Issues are welcome; code changes land upstream and sync here. See
[CONTRIBUTING.md](./CONTRIBUTING.md) for how to report a bug or raise a question, and the
[Code of Conduct](./CODE_OF_CONDUCT.md) for the ground rules.

## License

[MIT](./LICENSE)
