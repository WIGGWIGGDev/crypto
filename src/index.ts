/**
 * Cryptographic primitives for the WIGGWIGG clients.
 *
 * The package has no platform-specific code at its boundary: where a primitive
 * needs a native implementation (Argon2id, PBKDF2), the host injects it. Its only
 * runtime dependencies are @noble/* and @scure/bip39.
 */

export * from './asymmetric/index.js'
export * from './auth-signing/index.js'
export * from './bytes.js'
export * from './signed-payload.js'
export * from './encryption/index.js'
export * from './kdf/index.js'
export * from './params.js'
export * from './pin-unlock/index.js'
export * from './recovery/index.js'
export * from './versions.js'
export * from './auth-proof/index.js'
export * from './zk-entry-aad.js'
export * from './vault-manifest.js'
export * from './entry-aad-dispatch.js'
