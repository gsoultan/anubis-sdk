# Changelog

The four language packages are versioned together: one version number means
the same wire contract in Go, Node, PHP and Java. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html), and while the major
version is 0 the API may still move.

## [0.1.0] — 2026-09-03

First release.

### Added

- **Offline verification.** `Verifier` checks a PASETO `v4.public` access
  token's Ed25519 signature against the issuer's published keys, with no
  network call on the request path. `audience` is mandatory — a verifier
  without one accepts tokens minted for other services.
- **Key document handling** bounded in four directions: a TTL so a withdrawn
  key stops verifying, a separate min-refetch interval so an unknown `kid`
  cannot turn attacker-supplied tokens into outbound requests, single-flight
  fetches that hold no lock, and `not_before` / `not_after` windows. A failed
  fetch keeps the previous document — stale keys beat no keys. The document is
  bound to its issuer, plaintext `http` is refused off loopback, and anything
  past 1 MiB is refused rather than buffered.
- **PKCE sign-in.** `beginLogin` / `completeLogin`, with the verifier, state
  and cookie handling owned by the SDK rather than left to the caller.
- **Decisions.** `Authorize`, `Require`, and `Explain`, plus `BeginStepUp` for
  the refusal that is not a denial. `AuthorizeMany` (Go only for now) batches
  asks with bounded concurrency.
- **Refresh with rotation** and reuse detection, single-flight per token
  source.
- **Sign-out**, including receiving back-channel logout.
- **Client credentials**, for when no user is present.
- **Typed refusals** in all four languages — denied, step-up required,
  enrolment required, refresh reuse, state mismatch, rate limited,
  unavailable, verification failure — because each has a different correct
  response.
- **`admin/`** (Go), roughly 120 operator procedures for provisioning tools
  and the console, including `Entitlements` for what a *person* holds as
  against what a *session* carries.
- **`anubiskit/`** (Go), go-kit middleware with HTTP, gRPC and AMQP transports
  sharing one service and endpoint layer.
- **`anubistest/`** (Go), an in-process server for testing integrations.
- [`docs/WIRE.md`](docs/WIRE.md), the normative cross-language contract, and
  [`docs/MIGRATION.md`](docs/MIGRATION.md) for callers moving off the server's
  internal `pkg/anubis`.

### Published

Go (`github.com/gsoultan/anubis-sdk`), Node (`@gsoultan/anubis-sdk`) and PHP
(`gsoultan/anubis-sdk`, from the read-only mirror that
`scripts/release/php-split.sh` produces — Packagist reads `composer.json` only
from a repository root, and this one lives in `php/`).

Java is built and tested from this tag but is not on Maven Central yet:
Sonatype namespace verification and artefact signing are their own piece of
work. Until then, `mvn install` in `java/`.

`anubiskit` is deliberately untagged. Its `replace` directives are ignored by
downstream modules, so `require github.com/gsoultan/anubis-sdk v0.0.0` would
fail to resolve for anyone consuming it.

[0.1.0]: https://github.com/gsoultan/anubis-sdk/releases/tag/v0.1.0
