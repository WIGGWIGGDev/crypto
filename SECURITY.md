# Security Policy

## Reporting a vulnerability

Two ways, whichever you prefer:

- **Email** **security@wiggwigg.ca** (in French, **securite@wiggwigg.ca**) with enough detail to
  reproduce the issue.
- **GitHub private vulnerability reporting**: on this repository, open the **Security** tab and use
  **"Report a vulnerability."** It stays private between you and us until we publish an advisory.

You will get an acknowledgement within one business day.

We offer a good-faith safe harbor for responsible disclosure: if you make a sincere effort to
follow this policy, we will not pursue or support legal action against you for your research.

Please keep the issue private until a fix has shipped, or 90 days have passed, whichever comes
first. For a complex fix we may ask for a bit more time, and we will agree on a date together.

Once `@wiggwigg/crypto` is published to npm, security fixes will ship with a GitHub Security Advisory
and a CVE request, so anyone depending on the package gets a Dependabot alert and can upgrade.

## Scope

This repository holds the cryptographic primitives. Findings in the primitives themselves
(key derivation, encryption, sealing, signing, recovery) belong here. Findings in the WIGGWIGG
application or its hosted services can go to the same address; just note that they are
application-level. Our full company policy, including scope and rules of engagement, is at
**https://wiggwigg.ca/en/security/disclosure/**.

## A note on constants

The domain-separation strings and on-disk scheme versions in this code are load-bearing:
stored data depends on them. They change through the versioning mechanism in `versions.ts`,
never by editing a constant in place.
