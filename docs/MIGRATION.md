# Migrating from `pkg/anubis`

## Why the dependency has to invert

`pkg/anubis` lives inside the Anubis server repository. Once that repository is
private, no relying party can import it — and moving it out is not as simple as
deleting a directory, because the server imports it too. Nine files do:

```
internal/auth/app/paseto_token_issuer.go          internal/auth/app/token/introspect_interactor.go
internal/auth/app/token/revoke_interactor.go      internal/auth/app/session/backchannel_logout.go
internal/auth/app/clientcreds/client_credentials_interactor.go
internal/auth/adapter/http/wellknown_handler.go   internal/gate/adapter/http/gate_handler.go
internal/api/connect/authn_interceptor.go         internal/control/app/platform_auth_interactor.go
```

It is not a client-only package. It is the shared definition of the token
format, and both sides use it. So the dependency inverts:

```
before   app → anubis/pkg/anubis            impossible once the server is private
after    app → anubis-sdk  ←  anubis        the server depends on the SDK
```

That is the right direction independently of the privacy question. The SDK
holds the **contract** — PASETO `v4.public`, the claim set, the key ring, the
error vocabulary — and the server is one implementation of it. Inverting also
means the server cannot change the token format without changing the public
artefact that defines it, which is a feature rather than a cost.

## Moving the server across

`go.work` already treats `pkg/anubis` as its own module, so the transition is a
`replace` and then a version.

1. In the server repository, add the dependency and point it at a local
   checkout while the change is in flight:

   ```
   go get github.com/gsoultan/anubis-sdk@v0.1.0
   go mod edit -replace github.com/gsoultan/anubis-sdk=../anubis-sdk
   ```

2. Rewrite the imports. The package name is unchanged — `anubis` — so only the
   path moves:

   ```
   github.com/gsoultan/anubis/pkg/anubis         → github.com/gsoultan/anubis-sdk
   github.com/gsoultan/anubis/pkg/anubis/paseto  → github.com/gsoultan/anubis-sdk/paseto
   github.com/gsoultan/anubis/pkg/anubis/keys    → github.com/gsoultan/anubis-sdk/keys
   ```

   ```bash
   grep -rl 'gsoultan/anubis/pkg/anubis' internal cmd \
     | xargs sed -i '' 's|github.com/gsoultan/anubis/pkg/anubis|github.com/gsoultan/anubis-sdk|g'
   ```

3. Delete `pkg/anubis` and drop it from `go.work`.

4. Run the suites. `paseto.Sign` is still exported, which is what the token
   issuer and the back-channel logout signer need; nothing on the signing path
   changes shape.

5. Drop the `replace` and tag.

## What changed for consumers

Nothing, on the offline path. `Config`, `NewVerifier`, `Verify`, `Middleware`,
`RequireAMR`, `FromContext`, `Claims` and every sentinel error keep their names
and behaviour — including the one that matters, which is that a verifier
without an `Audience` refuses to be built.

What is **new** is the second half: a `Client` for sign-in, refresh, decisions
and introspection, and `anubistest` for testing without a server. Neither is
imported unless you use it, and neither adds a dependency: the module is still
standard library only.

```go
// before — from inside the server repository
import "github.com/gsoultan/anubis/pkg/anubis"

// after — from anywhere
import anubis "github.com/gsoultan/anubis-sdk"
```

## Status

Implemented and tested: 79 cases across the root, `keys`, `paseto`, `admin`
and the examples, plus 21 in `anubiskit`, race-clean. `paseto/` asserts the
specification's PAE golden vectors, so token handling is pinned byte for byte
against the format.

```bash
scripts/ci/local.sh   # gofmt, vet and -race over both modules
```

## The claim set is not the API

Both halves of the SDK now hand back domain types rather than the primitives
the wire uses. `Claims` still mirrors the token exactly — that is its job, and
the times are unix seconds there because they are unix seconds in the token —
but everything derived from it is a method, and `identity()` assembles the
whole thing into the view most callers want:

```go
// before
p, _ := anubis.FromContext(ctx)
sub := p.Claims.Subject                                  // string
authAge := time.Since(time.Unix(p.Claims.AuthTime, 0))   // by hand, every time
isClerk := slices.Contains(p.Claims.Roles, "billing.clerk")

// after
id, _ := anubis.IdentityFromContext(ctx)
id.Subject          // SubjectID, and .IsApplication() knows app_ from usr_
id.AuthAge()        // time.Duration
id.HasRole("billing.clerk")
```

`Claims` keeps its fields, so nothing that read them stops working — they are
typed now (`Roles`, `Scopes`, `AuthMethods`), which is a compile error at the
call sites that were treating them as bare strings, and that is the point.
