# Security policy

## Reporting a vulnerability

Report privately through GitHub's
[security advisories](https://github.com/SanaAfshani/warden/security/advisories/new).
**Please do not open a public issue**, because the report would describe a
working attack against everyone who has already installed the package.

Useful in a report: which package and version, the smallest code that shows the
problem, and what an attacker gets out of it. A proof of concept is welcome but
not required — a precise description of the flaw is worth more than an exploit.

Expect an acknowledgement within a few days. Fixes ship as a patch release with
an advisory naming the affected versions.

## What counts as a vulnerability here

A control that fails **open** — anything that lets a request through a guard
that should have stopped it, or returns a value a decorator should have
refused. Specifically:

- a `Decorator` that lets a request past a check it was supposed to make
- a token, session, signature or upload accepted when it should be rejected
- a bypass of `safeFetch`'s address filtering, or of the URL/HTML validators
- plaintext reaching storage that an `encrypted()` store was meant to protect
- a lint rule that silently stops reporting a pattern it documents as banned

## What does not

Some of these are real limits, and they are limits by design rather than bugs.

**Anything the browser cannot enforce.** The CSR track runs on a machine the
user controls. `access` decides what the UI shows, never what is allowed. An
XSS that runs while the tab is open can call `get()` exactly as your own code
does — the `encrypted()` store stops scripts that dump storage wholesale and
keeps plaintext off disk; it is not an XSS defence. Session tokens belong in
an httpOnly cookie, which only a server can set.

**Lint false positives.** A rule reporting code that is in fact safe is a bug,
but not a security one. A rule failing to report unsafe code is the serious
direction, and that is in the list above.

**Out of scope by design**, stated in the README so nobody assumes coverage:
MFA, password-reset flows, a database, WAF, TLS, secrets-manager integration,
and alerting.

**Misconfiguration**, where the library gave you the tools and the application
did not use them — a `required` lint rule waived everywhere, a chain missing
`csrf.protect()`, a secret shorter than `assertStrongSecret` accepts. Report it
anyway if the documentation led you there, because that is a documentation bug,
and the docs in this repository are treated as load-bearing.

## Supported versions

While the project is pre-1.0, only the latest minor receives fixes. All
packages share one version, enforced by a test, so an advisory for one package
tells you the version to move to for all of them.
