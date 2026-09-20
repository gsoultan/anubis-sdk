# Profiles

Non-trivial changes here are worked as a pair: adopt the **Driver** that owns
the code you are touching, then re-read your own diff as the **Challenger**
whose budget the change most likely breaks, and answer its vetoes. Name both in
the summary — `Driver: contract · Challenger: sec`.

The roster is small on purpose. These four are the constituencies this SDK
actually has, and each one has already been surprised at least once.

---

## `contract` — the wire

**Owns** `proto/`, `docs/WIRE.md`, every hand-written client, `anubistest/`.

**Vetoes** a field added to a vendored proto and not answered in the client;
a new procedure documented in `WIRE.md` but not in the Procedures table; a fake
that answers a shape the real server does not send; snake_case where protojson
sends lowerCamelCase, or a bare JSON number where it sends a quoted int64.

**Proof** the drift check in DESIGN §6 run against the sibling server checkout,
and a test that exercises the new field through `anubistest` rather than
through a struct literal — a struct literal proves the Go type, not the wire.

## `sec` — the thing being protected

**Owns** `verifier.go`, `keys/`, `paseto/`, `authz.go`, `cache.go`, credential
attachment.

**Vetoes** a fast path that skips a check; a cache key that omits an input the
answer depended on (a cache that ignores who asked is a data leak wearing a
performance costume); anything that lets one tenant's state reach another; a
length or count taken from the far end and allocated on without a bound; a
signal from Anubis read as permission rather than as invalidation.

**Proof** a test that fails with the check removed. For anything cross-tenant,
a test with two tenants — one tenant proves nothing.

## `offline` — the request path, and the dependency promise

**Owns** the root module's dependency-free guarantee, `Verifier` and everything
it calls per request.

**Vetoes** a `require` in the root `go.mod`, whatever the justification — CI
fails the build for it, and the SDK's central claim is that a service which
only verifies tokens inherits no dependency tree. Also: an allocation added to
per-request verification, and a check that reaches the network on the hot path.

**Proof** `scripts/ci/local.sh` (it asserts the `go.mod` gate the tests cannot),
and `verifier_bench_test.go` for the allocation claim.

## `integrator` — the person wiring this into an application

**Owns** `README.md`, `doc.go`, `examples/`, `anubiskit/`, error types.

**Vetoes** a refusal that cannot be acted on — no code, no failing axis, no
typed error to match; two reasons collapsed into one string when they need
opposite fixes; a correctness requirement that exists only in a doc comment
when it could have been made structural; an example that does not compile and
run in CI.

**Proof** the example builds and is tested, and the error is reachable with
`errors.As` from the shape the README shows.

---

## Standing truths

- Every bug fix ships a test that fails before and passes after, with the root
  cause named in one sentence in the test's own comment.
- A drifted proto is a bug hunt, not a copy. Ask what the client does with the
  fields that changed; a new scalar on a message the SDK already decodes is the
  dangerous shape, because it compiles and decodes and does nothing.
- A check worth having is made structurally unskippable rather than documented.
  `NewVerifier` refusing to build without an audience is the pattern.
