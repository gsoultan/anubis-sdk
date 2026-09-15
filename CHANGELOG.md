# Changelog

Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html), and while the major
version is 0 the API may still move.

## [anubiskit/v0.1.0] — 2026-09-15

First release of the go-kit module, `github.com/gsoultan/anubis-sdk/anubiskit`.

The code shipped with v0.1.0 and is unchanged. What was wrong was the module,
not the middleware: it required `github.com/gsoultan/anubis-sdk v0.0.0` behind
a local `replace`, and **a replace directive is ignored in a module that is
being consumed** — so a tag would have resolved to a version that does not
exist and failed for everybody but us. Nothing was published until there was a
root release to require, which is why this comes after v0.1.0 rather than with
it.

### Fixed

- `require github.com/gsoultan/anubis-sdk v0.1.0`, and both `replace`
  directives removed.
- A second `replace` pinned `google.golang.org/genproto`, because go-kit
  v0.13.0 requires the pre-split monolith, which still carries `googleapis/rpc`
  and makes `grpc/status` ambiguous. That is real — but only inside a
  **workspace**, which resolves one build list across every module in it.
  Standalone the ambiguity does not arise: `google.golang.org/genproto/
  googleapis/rpc` is a longer module path and wins for the packages beneath it.

  So the pin moved to `go.work`, where it belongs — it is a property of this
  workspace, not of the published module, and a `replace` in a published module
  is ignored by consumers regardless. Both views are verified: the workspace
  build via `scripts/ci/local.sh`, and the consumer build with `GOWORK=off` on
  go1.26.6 and go1.27.1.
- `release.yml` now gates an `anubiskit/*` tag on the module resolving with
  `GOWORK=off`. `go.work` makes anubiskit build against the root module in the
  working tree — which is what a developer wants, and exactly why CI could not
  see that its own `go.mod` was broken. It runs on tags rather than on every
  push, because the real cost of a released nested module is that its require
  must name a version that exists, and paying that on every branch would block
  any root change anubiskit uses until the root is released.
- `actions/checkout` and `actions/setup-go` moved to v7; the pinned majors were
  running on the deprecated Node 20 runner.

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
  - **Manifests** — `ApplyManifest`, `DryRunManifest`,
    `ApplyManifestDocument`, and a `Manifest` builder. A manifest is an
    application's catalog: its permissions, the roles that bundle them, and
    the route rules. Applying one reconciles rather than inserts.

    The section a document *declares* is what gets touched, and an undeclared
    section must be an absent JSON key — the server detects sections with
    pointers, so `"routes": []` is "delete my routes" while no `routes` key at
    all is "leave them alone". `Manifest` makes that a type-level decision:
    only sections you set are written. Permissions the document stops naming
    are deprecated and roles are retired — never deleted, and no existing
    grant stops working — but routes are replaced wholesale, and unlike the
    other two the server has no rail against emptying them. `WithRoutes()`
    with no routes is refused; emptying the table on purpose is
    `ClearRoutes()`.

    `Validate` catches locally what the server would reject, including the
    mistake the server calls out by name: roles and routes name permissions as
    `resource:action` without the application slug, and the error says which
    form to use rather than "invalid argument" against a value that looks
    right. `ManifestReport` is typed rather than a JSON string, and prints a
    readable summary meant for after a dry run.
  - **Provisioning** — tenants, realms, applications and API keys, plus the
    rest of the auth-page surface (`CreateAuthPage`, `DeleteAuthPage`,
    `SetDefaultAuthPage`). Three values come back exactly once and cannot be
    recovered — an application's client secret, a rotated one, and an API key
    — so they are fields on `NewApplication` and `NewAPIKey` rather than bare
    strings, and no listing returns them.

    `RenameTenant` is named for what it does, because a tenant's slug is in
    URLs, tokens and hosted page paths and nothing changes it. Realm codes are
    validated separately from slugs, since a code may not contain a hyphen and
    a slug may. `Applications` is paged and reports `Total`;
    `AllApplications` walks it.
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

[anubiskit/v0.1.0]: https://github.com/gsoultan/anubis-sdk/releases/tag/anubiskit%2Fv0.1.0
[0.1.0]: https://github.com/gsoultan/anubis-sdk/releases/tag/v0.1.0
