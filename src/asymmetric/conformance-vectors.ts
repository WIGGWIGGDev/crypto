/**
 * Cross-implementation conformance vectors for the X25519+HKDF+XChaCha20-Poly1305
 * hybrid scheme. THIS FILE IS THE CANONICAL SOURCE OF THE BYTES — every native
 * port pins to these exact values so independent implementations can never
 * silently drift. The reference implementation is this package's `hybrid` module
 * (sealing with @noble/ciphers), verified in `conformance-vectors.test.ts`;
 * Swift and Kotlin ports pin known-answer tests to the same constants.
 *
 * If you change the hybrid scheme, change it HERE and re-run every port's KATs
 * against the new vectors.
 */

// HChaCha20 — RFC draft-irtf-cfrg-xchacha-03 §2.2.1 known-answer. Anchors the
// Swift/Kotlin hand-rolled HChaCha20 subkey (CryptoKit/BouncyCastle lack
// extended-nonce ChaCha); also exercised in TS via @noble's `hchacha` in
// conformance-vectors.test.ts, so a typo here fails the suite, not just the KATs.
export const HCHACHA20_RFC_KEY_HEX =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
export const HCHACHA20_RFC_INPUT_HEX = '000000090000004a0000000031415927'
export const HCHACHA20_RFC_EXPECTED_HEX =
  '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc'

// XChaCha20-Poly1305-IETF AEAD open: a ciphertext produced by @noble/ciphers
// (the exact primitive `hybrid.ts` seals with) must open to this plaintext.
// `ciphertext` is the combined `ct ‖ 16-byte tag` layout; AAD is empty.
export const XCHACHA_KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
export const XCHACHA_NONCE_HEX = '01080f161d242b323940474e555c636a71787f868d949ba2'
export const XCHACHA_CIPHERTEXT_HEX =
  'ba44faaaa7cb55a9e161495a642559499b23a86cd4a4d06fb9e0880f1c29ab61ec0b918c0212cf6e994d4ddeeeda4e016d9683a7'
export const XCHACHA_PLAINTEXT_HEX =
  '77696767776967672d73657373696f6e2d6b65792d746573742d766563746f722d333221'

// ── Full ENVELOPE vector (the layer above the primitives) ─────────────────
//
// A complete encrypted envelope in the shape a sender emits: an
// AES-256-GCM(16-byte IV) payload under a random session key, with that key
// wrapped by hybrid seal + serializeEnvelope (X25519 + HKDF-SHA256 under the
// "wiggwigg-hybrid-v1" info tag, salt = recipient public key, then
// XChaCha20-Poly1305, wire version byte 1).
//
// Why this exists on top of the primitive KATs: those can all pass while THIS
// layer drifts (scheme dispatch, envelope offsets, HKDF salt/info, base64,
// UTF-8). Generated once with this package's sealer, then decrypted by each
// port's test suite through its real production decrypt path, not a
// re-implementation. The recipient keypair below is a throwaway generated for
// this vector; it protects nothing.
export const ENVELOPE_RECIPIENT_PRIVATE_B64 = 'TtGSIjul0ooAEpJEaja5HEUjxK1JYO8H34vf7qtnkvw='
export const ENVELOPE_RECIPIENT_PUBLIC_B64 = 'UFjiJ536X0gCnAX9hCzXrHi8kc5Gs7+WAN4GOT+y5wU='
export const ENVELOPE_E_B64 =
  'Dk1kb4TLZJ/u4aug34SVAmrAxSb13opqy6jMYU7KpPEfJSSzDitFr7Z1L/Udp9D7hJB0jSSI8X5vddvDFttuC8nebhfjJYNU5F/i8gimCA=='
export const ENVELOPE_N_B64 = 'PLRLZDpySJxkX9t8W5CobA=='
export const ENVELOPE_T_B64 = '2FZxHGO4EI4ie0CFVfWSWg=='
export const ENVELOPE_SK_B64 =
  'AbL+u0UDXOoGHdQIgzgIqPaJapvKpzQGkx/2ykO1KvF6QKE1y7ag/JQgEd03LbssW/yS/6OcAmykhqEpmBvmbYM+UGzRq/iQoGoT2CRdQisno+eohkPqcsoxAMAJbUvk0aKlDsRz85VE'
// Storage-level scheme id a store may keep per record (2 = this sealed box; a
// store may use 1 for a legacy RSA-OAEP wrap). Distinct from the envelope's own
// version byte (1) — the two namespaces are independent.
export const ENVELOPE_STORAGE_SCHEME = 2
export const ENVELOPE_SENDER_NUMBER = '+18195550142'
export const ENVELOPE_MESSAGE_PREVIEW = 'Allô! Vecteur canonique ✓'
