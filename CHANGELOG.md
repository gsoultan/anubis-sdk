# Changelog

Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html), and while the major
version is 0 the API may still move.

## [0.1.0] — 2026-09-15

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
  the refusal that is not a denial. `AuthorizeMany` batches asks with bounded
  concurrency.
- **Refresh with rotation** and reuse detection, single-flight per token
  source.
- **Sign-out**, including receiving back-channel logout.
- **Client credentials**, for when no user is present.
- **Typed refusals** — denied, step-up required, enrolment required, refresh
  reuse, state mismatch, rate limited, unavailable, verification failure —
  because each has a different correct response.
- **`admin/`**, roughly 120 operator procedures for provisioning tools
  and the console, including `Entitlements` for what a *person* holds as
  against what a *session* carries.
  - `ScopeNodes` is **paged** — an axis can hold hundreds of thousands of
    nodes, and the unpaged form returned the first page as though it were the
    whole axis, with no error. `AllScopeNodes` walks every page and is what a
    scope picker wants; `ScopeNodes` hands back `NextPage` for callers doing
    their own. `anubistest` pages too, because a fake that answers every
    listing in one page is what let this through.
  - `Identity.RetentionDeadline()` reads the statutory retention limit's
    deadline, and `Role.Deprecated` marks a role retired from the catalog —
    still deciding for the grants that name it, but a dead end in a picker.
  - **Catalog sources** — `CatalogSources`, `CreateCatalogSource`,
    `UpdateCatalogSource`, `DeleteCatalogSource`, `RunCatalogSource`,
    `CatalogRuns`: where an application's permissions and roles are read from
    when nobody is pushing them. An application is pinned at creation, so
    `CatalogSourceUpdate` has no field for it. Run a source dry first — it
    reports and writes nothing, and does not become the source's last status.
  - **`SetSyncSchedule`** changes *when* a scope sync source runs and nothing
    else. Updating a source replaces its config wholesale, and a client is
    never sent that source's dsn or auth header to send back, so a
    read-modify-write through the update call would blank them.
  - **Auth pages** — `AuthPages`, `AuthPage`, `UpdateAuthPage`. A page binds
    to an application **or** a realm, never both; naming two is refused here
    with `ErrAuthPageBinding` rather than by a database constraint whose error
    does not say which binding was the accident.
  - Schedules are zero (manual) or at least `MinScheduleInterval`. Anything
    shorter is refused without a round trip, with a message that says what the
    floor is.
- **`anubiskit/`**, go-kit middleware with HTTP, gRPC and AMQP transports
  sharing one service and endpoint layer.
- **`anubistest/`**, an in-process server for testing integrations.
- [`docs/WIRE.md`](docs/WIRE.md), the normative contract, and
  [`docs/MIGRATION.md`](docs/MIGRATION.md) for callers moving off the server's
  internal `pkg/anubis`.

### Published

`github.com/gsoultan/anubis-sdk`. The tag is the whole release: the module
proxy reads it, no version lives in a manifest, and there is no registry to
push to.

`anubiskit` is deliberately untagged. Its `replace` directives are ignored by
downstream modules, so `require github.com/gsoultan/anubis-sdk v0.0.0` would
fail to resolve for anyone consuming it.

### Not shipped

PHP, Node and Java clients were written, tested and then removed before this
release — PHP at `d52d0c5`, Node and Java at `3443a1d`. None was ever
published, so there is nothing on Packagist, npm or Maven Central to
deprecate.

Applications in those languages go against [`docs/WIRE.md`](docs/WIRE.md),
which is normative and was always the contract those clients were written to.
They were a convenience, not the interface, and removing them took only
release machinery with it — three CI jobs, the npm publish job, the
version-agreement check and the Packagist split-mirror script.

[0.1.0]: https://github.com/gsoultan/anubis-sdk/releases/tag/v0.1.0
