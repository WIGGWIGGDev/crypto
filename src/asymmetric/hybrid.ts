/**
 * Hybrid public-key encryption: X25519 ECDH, HKDF-SHA256, then XChaCha20-Poly1305.
 *
 * Matches libsodium sealed-box semantics, so a single primitive seals both
 * inbound message content and the recovery master-key wrap.
 *
 * Envelope shape (wire and at-rest):
 *   version  (u8)           : 1
 *   ephPub   (32 bytes)     : ephemeral X25519 public
 *   nonce    (24 bytes)     : random XChaCha20 nonce
 *   ciphertext (variable)   : plaintext.length + 16 (AEAD tag)
 *
 * Everything is concatenated into a single `Uint8Array` via `serializeEnvelope`
 * so callers can base64-encode once and not think about field boundaries.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { ASYMMETRIC_SCHEME_CURRENT_VERSION } from '../versions.js'
import { generateX25519Keypair, x25519Ecdh } from './x25519.js'

export interface HybridEnvelope {
  readonly schemeVersion: number
  readonly ephemeralPublicKey: Uint8Array // 32 bytes
  readonly nonce: Uint8Array // 24 bytes
  readonly ciphertext: Uint8Array // plaintext.length + 16
}

/**
 * Domain-separation tag for the seal's HKDF. Exported so another implementation
 * can reproduce the key derivation byte-for-byte.
 */
export const HYBRID_HKDF_INFO = new TextEncoder().encode('wiggwigg-hybrid-v1')
const EPH_PUB_LEN = 32
const NONCE_LEN = 24

function deriveAeadKey(sharedSecret: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  // salt = recipientPk binds the derived key to the exact target we wrapped
  // for. Prevents an attacker who sees an ephemeral public from reusing the
  // transcript against a different recipient.
  return hkdf(sha256, sharedSecret, recipientPublicKey, HYBRID_HKDF_INFO, 32)
}

/**
 * Encrypt `plaintext` so only the holder of the X25519 private key
 * corresponding to `recipientPublicKey` can read it.
 *
 * Generates a fresh ephemeral keypair per call; an ephemeral is never reused.
 */
export function seal(recipientPublicKey: Uint8Array, plaintext: Uint8Array): HybridEnvelope {
  if (recipientPublicKey.length !== 32) {
    throw new Error(
      `hybrid.seal: recipient public key must be 32 bytes, got ${recipientPublicKey.length}`,
    )
  }

  const ephemeral = generateX25519Keypair()
  const shared = x25519Ecdh(ephemeral.privateKey, recipientPublicKey)
  const key = deriveAeadKey(shared, recipientPublicKey)
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN))

  const cipher = xchacha20poly1305(key, nonce)
  const ciphertext = cipher.encrypt(plaintext)

  // Wipe the ephemeral private now that it's been used. The shared secret and
  // derived key only live until GC reclaims them, which is as far as a pure-JS
  // implementation can go.
  ephemeral.privateKey.fill(0)
  shared.fill(0)
  key.fill(0)

  return {
    schemeVersion: ASYMMETRIC_SCHEME_CURRENT_VERSION,
    ephemeralPublicKey: ephemeral.publicKey,
    nonce,
    ciphertext,
  }
}

/**
 * Decrypt a `HybridEnvelope` produced by `seal`. Throws on AEAD tag failure
 * (wrong key or tampered blob) rather than returning junk bytes.
 *
 * `recipientPublicKey` must be the key the envelope was sealed to; derive it
 * from the same source as the private key (for the recovery path, the BIP39
 * mnemonic). A mismatch fails authentication deterministically.
 */
export function open(
  recipientPrivateKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  envelope: HybridEnvelope,
): Uint8Array {
  if (envelope.schemeVersion !== ASYMMETRIC_SCHEME_CURRENT_VERSION) {
    throw new Error(
      `hybrid.open: unsupported scheme version ${envelope.schemeVersion} (current: ${ASYMMETRIC_SCHEME_CURRENT_VERSION})`,
    )
  }
  if (envelope.ephemeralPublicKey.length !== EPH_PUB_LEN) {
    throw new Error(
      `hybrid.open: ephemeral public must be ${EPH_PUB_LEN} bytes, got ${envelope.ephemeralPublicKey.length}`,
    )
  }
  if (envelope.nonce.length !== NONCE_LEN) {
    throw new Error(`hybrid.open: nonce must be ${NONCE_LEN} bytes, got ${envelope.nonce.length}`)
  }

  const shared = x25519Ecdh(recipientPrivateKey, envelope.ephemeralPublicKey)
  const key = deriveAeadKey(shared, recipientPublicKey)
  const cipher = xchacha20poly1305(key, envelope.nonce)
  const plaintext = cipher.decrypt(envelope.ciphertext)

  shared.fill(0)
  key.fill(0)

  return plaintext
}

/**
 * Concatenate the envelope into a wire-friendly byte sequence. Base64 this
 * once for transport / DB storage. Prefer over manual field-by-field handling
 * so callers can't mis-order components.
 */
export function serializeEnvelope(envelope: HybridEnvelope): Uint8Array {
  const out = new Uint8Array(1 + EPH_PUB_LEN + NONCE_LEN + envelope.ciphertext.length)
  out[0] = envelope.schemeVersion
  out.set(envelope.ephemeralPublicKey, 1)
  out.set(envelope.nonce, 1 + EPH_PUB_LEN)
  out.set(envelope.ciphertext, 1 + EPH_PUB_LEN + NONCE_LEN)
  return out
}

/**
 * Convenience: seal `plaintext` to `recipientPublicKey` and return the
 * serialized envelope bytes in one step — the exact shape every caller needs
 * before base64-encoding for transport/DB. Equivalent to
 * `serializeEnvelope(seal(recipientPublicKey, plaintext))`; the recovery
 * master-key wrap and re-seal sites all want precisely this.
 */
export function sealSerialized(recipientPublicKey: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return serializeEnvelope(seal(recipientPublicKey, plaintext))
}

/**
 * Parse the serialized envelope back into its fields. Throws on under-length
 * input; does not validate crypto (pass to `open` for that).
 */
export function deserializeEnvelope(bytes: Uint8Array): HybridEnvelope {
  const minLen = 1 + EPH_PUB_LEN + NONCE_LEN + 16 /* empty-plaintext AEAD tag */
  if (bytes.length < minLen) {
    throw new Error(
      `hybrid.deserializeEnvelope: blob too short (${bytes.length} bytes, minimum ${minLen})`,
    )
  }
  const schemeVersion = bytes[0]
  if (schemeVersion === undefined) {
    throw new Error('hybrid.deserializeEnvelope: missing scheme version byte')
  }
  return {
    schemeVersion,
    ephemeralPublicKey: bytes.slice(1, 1 + EPH_PUB_LEN),
    nonce: bytes.slice(1 + EPH_PUB_LEN, 1 + EPH_PUB_LEN + NONCE_LEN),
    ciphertext: bytes.slice(1 + EPH_PUB_LEN + NONCE_LEN),
  }
}
