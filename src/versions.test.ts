import { describe, expect, it } from 'vitest'

import { describeVersion, RECOVERY_AUTH_SCHEME_CURRENT_VERSION } from './versions.js'

describe('version registry (describeVersion)', () => {
  it('names the current recovery-auth scheme', () => {
    expect(describeVersion('recovery_auth_scheme', RECOVERY_AUTH_SCHEME_CURRENT_VERSION)).toBe(
      'ed25519-recovery-hkdf-sha256',
    )
  })

  it('falls back to unknown(n) for an unregistered version rather than throwing', () => {
    expect(describeVersion('recovery_auth_scheme', 99)).toBe('unknown(99)')
  })

  it('names the other crypto dimensions', () => {
    expect(describeVersion('kdf', 2)).toBe('argon2id-default')
    expect(describeVersion('auth_scheme', 1)).toBe('ed25519-hkdf-sha256')
    expect(describeVersion('asymmetric_scheme', 1)).toBe('x25519-hkdf-xchacha20poly1305')
  })
})
