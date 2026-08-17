/**
 * Per-login challenge-response authentication signing (Ed25519).
 *
 * The verifier is asymmetric: the client derives an Ed25519 signing keypair from
 * the master key, the server stores only the public key, and login proves
 * possession by signing a fresh server-issued challenge. A leak of the stored
 * public key forges nothing, and a single-use, time-boxed challenge stops
 * replay. This succeeds a static shared-secret proof, where the stored value
 * equalled what the client sent and a leak was login-equivalent.
 *
 * Derivation (deterministic, so the client stores no new secret):
 *   masterKey (32 bytes)
 *   -> HKDF-SHA256(salt: AUTH_HKDF_SALT, info: AUTH_HKDF_INFO, len: 32)
 *   -> Ed25519 secret seed, then Ed25519 public key
 *
 * The HKDF info domain-separates this key from every other master-key-derived
 * key (comms, recovery, vault), so compromise of one never yields another. The
 * auth key signs only; it never decrypts.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

import {
  buildSignedPayload,
  ED25519_PUBLIC_LEN,
  ED25519_SEED_LEN,
  signEd25519,
  verifyEd25519,
} from '../signed-payload.js'
import { AUTH_SCHEME_CURRENT_VERSION } from '../versions.js'

/**
 * Domain-separation tags for the auth signing key. These must not change once
 * keys exist: every stored public key is derived under them, so changing one
 * would lock those users out. Rotate through AUTH_SCHEME_CURRENT_VERSION instead.
 */
const AUTH_HKDF_SALT = new TextEncoder().encode('wiggwigg-auth-v1')
const AUTH_HKDF_INFO = new TextEncoder().encode('wiggwigg-auth-sign-v1')

/**
 * Domain tag mixed into every signed login payload. Binds a signature to the
 * login protocol so a captured signature cannot be relayed to a different
 * scheme that happens to sign similar bytes.
 */
const LOGIN_PAYLOAD_DOMAIN = 'wiggwigg-login-v1'

export interface AuthSigningKeypair {
  /** 32-byte Ed25519 secret seed; the caller wipes it after use. */
  readonly privateKey: Uint8Array
  /** 32-byte Ed25519 public key, the only half the server ever sees. */
  readonly publicKey: Uint8Array
}

/**
 * Derive the deterministic Ed25519 auth signing keypair from a 32-byte master
 * key. Same master key always yields the same keypair, so no per-device state
 * is needed and the public key can be re-derived on any device after unlock.
 *
 * The caller is responsible for wiping `privateKey` once it has signed.
 */
export function deriveAuthSigningKeypair(masterKey: Uint8Array): AuthSigningKeypair {
  if (masterKey.length !== 32) {
    throw new Error(`auth-signing: master key must be 32 bytes, got ${masterKey.length}`)
  }
  const seed = hkdf(sha256, masterKey, AUTH_HKDF_SALT, AUTH_HKDF_INFO, ED25519_SEED_LEN)
  const publicKey = ed25519.getPublicKey(seed)
  return { privateKey: seed, publicKey }
}

/**
 * Derive only the Ed25519 auth public key from a master key. This is what the
 * client uploads and the server stores. Wipes the transient private seed before
 * returning.
 */
export function deriveAuthPublicKey(masterKey: Uint8Array): Uint8Array {
  const { privateKey, publicKey } = deriveAuthSigningKeypair(masterKey)
  privateKey.fill(0)
  return publicKey
}

/**
 * Build the exact byte string both client and server feed to sign/verify, so the
 * two sides can't disagree on field order or separators:
 *
 *   payload = utf8(LOGIN_PAYLOAD_DOMAIN) || 0x00 || utf8(accountId) || 0x00 || challengeBytes
 *
 * `challenge` is the raw server-issued challenge bytes. Binding `accountId` stops
 * a signature for one account being relayed as another, and the domain tag stops
 * cross-protocol reuse.
 */
export function buildAuthChallengePayload(challenge: Uint8Array, accountId: string): Uint8Array {
  return buildSignedPayload(LOGIN_PAYLOAD_DOMAIN, new TextEncoder().encode(accountId), challenge)
}

/**
 * Domain tag for the proof-of-possession a client provides when it uploads a
 * new auth public key (register / lazy migration / password change). Distinct
 * from the login-challenge domain so a login signature can never be replayed as
 * a provisioning proof or vice-versa.
 */
const PROVISION_PAYLOAD_DOMAIN = 'wiggwigg-auth-provision-v1'

/**
 * Build the self-certifying provisioning payload a client signs to prove it
 * controls the private key for the public key it is uploading:
 *
 *   payload = utf8(PROVISION_PAYLOAD_DOMAIN) || 0x00 || publicKey
 *
 * The server stores an auth public key only after `verifyAuthChallenge` over
 * this payload succeeds, so it can never persist a key the client cannot sign
 * with (which would silently lock the user out of challenge-response login).
 * Replaying a captured proof is harmless: it re-asserts the same key the
 * already-authenticated uploader owns.
 */
export function buildAuthKeyProvisioningPayload(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== ED25519_PUBLIC_LEN) {
    throw new Error(
      `auth-signing: public key must be ${ED25519_PUBLIC_LEN} bytes, got ${publicKey.length}`,
    )
  }
  return buildSignedPayload(PROVISION_PAYLOAD_DOMAIN, publicKey)
}

/**
 * Sign a login challenge payload with the Ed25519 auth private seed. Returns
 * the 64-byte signature. Build `payload` with `buildAuthChallengePayload`.
 */
export function signAuthChallenge(privateKey: Uint8Array, payload: Uint8Array): Uint8Array {
  return signEd25519(privateKey, payload)
}

/**
 * Verify an Ed25519 signature over a login challenge payload against the stored
 * public key. Returns a boolean; it only throws on a malformed key or signature
 * length, never on a well-formed but invalid signature. The server treats
 * `false` as an auth failure.
 */
export function verifyAuthChallenge(
  publicKey: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
): boolean {
  return verifyEd25519(publicKey, payload, signature)
}

/** The auth scheme version this client/server writes. */
export const authSchemeCurrentVersion = AUTH_SCHEME_CURRENT_VERSION
