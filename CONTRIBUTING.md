# Contributing

Thanks for taking an interest in WIGGWIGG's cryptographic core.

This repository is a **read-only mirror**, generated from the WIGGWIGG monorepo where
the code is developed and tested. Pull requests opened here can't be merged directly,
but your reports and ideas reach us and get applied upstream, then sync back. The
fastest, most reliable way to contribute is an issue.

## What's most useful

- **Security vulnerabilities** go to **security@wiggwigg.ca**, not a public issue. See
  [SECURITY.md](./SECURITY.md) for the disclosure policy and our safe-harbor commitment.
- **Bugs** in a primitive (wrong output, a failing edge case, a platform that won't
  build) are welcome as issues. A minimal reproduction and the package version help.
- **Design questions and feedback** on the constructions are welcome too. We wrote this
  to be reviewed; if something looks wrong or underspecified, tell us.

## Worth knowing before you dig in

- We build on [`@noble`](https://github.com/paulmillr/noble-curves) and
  [`@scure`](https://github.com/paulmillr/scure-bip39). We don't implement our own
  primitives, and proposals to do so won't land.
- The domain-separation strings (the `wiggwigg-*` tags) and the on-disk scheme versions
  are **load-bearing**: stored data depends on them. They change through the versioning
  mechanism in `versions.ts`, never by editing a constant in place.
- Every derived key is domain-separated, by a distinct HKDF `info` tag or a distinct
  HMAC label. Keep that property intact: a change that lets two purposes share a tag
  re-introduces the key reuse the split exists to prevent.

## Building locally

```sh
npm install
npm run all      # type-check, test, build
```

The package targets browsers, Node, and React Native, so nothing at the module boundary
imports a platform-specific crypto API. Native implementations (Argon2id, PBKDF2) are
injected by the host.

## Conduct

Participation is covered by our [Code of Conduct](./CODE_OF_CONDUCT.md).
