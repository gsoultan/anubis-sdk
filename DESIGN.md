# anubis-sdk — API design

Clients for integrating an application with an [Anubis](https://github.com/gsoultan/anubis)
installation, in Go and PHP.

Anubis is a private repository. That single fact decides the shape of this SDK:
an application can no longer `go get github.com/gsoultan/anubis-sdk`, so
everything a relying party needs — the token format, the claim set, the key
ring, the wire contract — has to live **here**, in the open, and the server has
to depend on this module rather than the other way round.

The SDK speaks [the wire contract](docs/WIRE.md). It does not depend on the
server's source, which is also what you want if you would rather POST JSON
yourself.

---

## 1. The one decision everything else follows from

Anubis's own design splits an integration cleanly in two, and the halves have
nothing in common:

| | **Verify** | **Ask** |
| :--- | :--- | :--- |
| When | Every request | Before a privileged action |
| Cost | ~µs of CPU | A network round trip |
| Network | None | Anubis is in the path |
| Failure mode | Reject the request | Fail closed, or degrade |
| Dependencies | Must be zero | An HTTP client is fine |

So the SDK ships **two objects, not one**:

- **`Verifier`** — offline PASETO `v4.public` verification. Zero dependencies,
  no I/O on the request path, safe to embed in anything.
- **`Client`** — everything that talks to Anubis: sign-in, refresh, `Authorize`,
  introspection.

A service that only consumes tokens (the common case for an internal API)
imports the `Verifier` and never constructs a `Client`. That is the property
worth protecting: **what every service embeds must not drag a dependency tree
behind it.**

Both languages can verify with no third-party crypto, which keeps
[ADR-0002](https://github.com/gsoultan/anubis/blob/main/docs/adr/0002-dependency-policy.md)'s
constraint intact on the client side too:

| Language | Ed25519 from | Runtime deps |
| :--- | :--- | :--- |
| Go | `crypto/ed25519` | none — stdlib only |
| PHP | `sodium_crypto_sign_verify_detached` (bundled since 7.2) | ext-sodium, ext-json |

## 2. What is in scope

An application integrating with Anubis does at most six things. Those six are
the SDK:

1. Send a user to sign in, and handle the callback — **PKCE**
2. Verify the access token on every request — **offline**
3. Ask whether they may do something — **`Authorize`**
4. Keep the session alive — **refresh with rotation**
5. Sign out, including receiving back-channel logout
6. Get a token with no user present — **client credentials**

**The admin plane is a separate package.** `TenantAdminService`,
`ScopeAdminService`, `IdentityAdminService`, `AuthzAdminService`,
`PlatformAdminService` are roughly 120 RPCs serving a different audience —
provisioning tools and the console, not the payments service. Shipping them in
the package a payments service embeds is a disservice to both. They go in
`anubis-sdk/admin`, versioned together, imported by the handful of callers that
need them.

```
github.com/gsoultan/anubis-sdk          # integration — hand-written, stdlib only
github.com/gsoultan/anubis-sdk/admin    # management  — hand-written, stdlib only
```

---

## 3. Go — the reference API

Go is written first and the other three follow it. `panmail-sdk` set the
precedent: the Go package lives at the repository root.

### 3.1 Verifying — the hot path

Unchanged from `pkg/anubis`, because it is already right. It moves here whole.

```go
import anubis "github.com/gsoultan/anubis-sdk"

v, err := anubis.NewVerifier(anubis.Config{
    Issuer:   "https://anubis.internal",
    Audience: "billing-api",   // mandatory — see below
    KeysURL:  "https://anubis.internal/.well-known/anubis-keys.json",
})

mux.Handle("/api/", v.Middleware(apiHandler))
mux.Handle("/api/payments/", v.Middleware(anubis.RequireAMR("otp")(payments)))

// inside a handler
p, _ := anubis.FromContext(r.Context())
p.Claims.Subject   // usr_…
p.Claims.Roles     // ["billing.clerk"]
p.Claims.AMR       // ["pwd","otp"]
```

`Audience` has no default and no "skip" flag. A verifier without one accepts
tokens minted for the HR application in the payments application — the classic
confused deputy — so the constructor refuses to build. This is the template for
every other security check in the SDK: **make it structurally unskippable
rather than documented.**

### 3.2 Signing a user in — PKCE that cannot be got wrong

The authorization-code dance is where integrations actually break, and always
in the same two places: the `state` check is skipped, or the `code_verifier` is
stored somewhere the callback cannot reach. So the SDK owns both.

```go
client, err := anubis.New("https://anubis.internal",
    anubis.WithApplication("billing-web", os.Getenv("ANUBIS_CLIENT_SECRET")),
)

// 1. the sign-in redirect
func handleLogin(w http.ResponseWriter, r *http.Request) {
    redirect, err := client.BeginLogin(w, anubis.LoginParams{
        RedirectURI: "https://billing.example.com/callback",
        Scope:       []string{"openid", "profile"},
    })
    if err != nil { … }
    http.Redirect(w, r, redirect.URL, http.StatusFound)
}

// 2. the callback
func handleCallback(w http.ResponseWriter, r *http.Request) {
    tokens, err := client.CompleteLogin(r.Context(), w, r)
    if err != nil { … }          // state mismatch is an error you cannot skip
    session.Set(tokens)
}
```

`BeginLogin` takes the `ResponseWriter` and `CompleteLogin` takes the
`*Request`, because the verifier and state have to survive a browser round trip
and the only place that always works is a cookie the SDK sets and reads itself.
`CompleteLogin` compares `state` before it exchanges anything, and returns
`ErrStateMismatch` — the check is not the caller's to forget.

Bring your own storage when a cookie is wrong for you (a server-side session
store, a distributed cache):

```go
client, _ := anubis.New(baseURL,
    anubis.WithApplication("billing-web", secret),
    anubis.WithLoginStore(myRedisStore),   // Put(ctx, state, Pending) / Take(ctx, state)
)
```

`Take`, not `Get`: a login state is single-use, and a store that hands the same
one out twice reopens the replay the `state` parameter exists to close.

**First-party native and CLI apps** skip the browser:

```go
result, err := client.Login(ctx, anubis.Credentials{
    Tenant: "impack", Username: "alice", Password: pw,
    ClientID: "billing-cli", DeviceFP: fingerprint,
})
switch {
case result.NeedsMFA():
    tokens, err := client.VerifyMFA(ctx, result.MFA.Token, code)
case result.EnrolmentRequired != nil:
    // no session, but the means to earn one — result.EnrolmentRequired.GrantToken
default:
    tokens := result.Tokens
}
if result.EnrolmentDue != nil {
    // signed in, and warned: this user loses access on .Deadline
}
```

`Login` returns a result, not a token, because `LoginResponse` is a `oneof` and
three of its four outcomes are steps rather than failures. Modelling "MFA
required" as an error would be a lie about what happened. `EnrolmentDue` rides
alongside the tokens exactly as the proto does — it is the field every client
will ignore, so it is a field, not a log line.

### 3.3 Asking — `Authorize` without the footguns

The decision call has one genuine trap. [ADR-0004](https://github.com/gsoultan/anubis/blob/main/docs/adr/0004-authorization-semantics.md)
makes an omitted axis on a strict axis a **denial**, and `subject`, `amr` and
`auth_time` all have to come off the token the middleware already verified. A
developer copying those three by hand will drop `amr` and `auth_time`, and
silently lose every step-up decision — a deny that arrives as a mystery.

So the SDK reads them from the request context and the caller supplies only
what is genuinely theirs: the permission and the axes the action touches.

```go
if err := client.Require(ctx, "billing:invoice:approve", anubis.Scopes{
    "org":      invoice.OrgID,
    "customer": invoice.CustomerID,
}); err != nil {
    var stepUp *anubis.StepUpRequiredError
    if errors.As(err, &stepUp) {
        redirect, _ := client.BeginStepUp(w, err, anubis.LoginParams{RedirectURI: cb})
        http.Redirect(w, r, redirect.URL, http.StatusFound)
        return
    }
    var denied *anubis.DeniedError
    if errors.As(err, &denied) {
        http.Error(w, denied.Message, http.StatusForbidden)   // .FailingAxis names the axis
        return
    }
    return err
}
```

`BeginStepUp` closes the loop the integration guide says "do not guess" about: it
turns the machine-readable refusal into the `/v1/authorize` URL that satisfies
`required_amr`, and the retry is the caller's ordinary flow.

Two shapes, because both read naturally in different places:

```go
// guard clause — a deny is an error
err := client.Require(ctx, permission, scopes)

// data — a deny is an answer
d, err := client.Authorize(ctx, permission, scopes)
d.Allow          // bool
d.Reason         // "scope_mismatch" | "step_up_required" | "identity_inactive" | …
d.FailingAxis    // the axis that failed, always named
```

Self-scoped access spells out the reserved key so it is greppable and typo-proof:

```go
client.Require(ctx, "ats:application:read_own", anubis.Owner(p.Claims.Subject))
```

And `Explain` returns the evaluation tree, for the deny nobody understands:

```go
x, _ := client.Explain(ctx, permission, scopes)
x.Allow, x.FailingAxis, x.Detail   // same tree the console's playground renders
```

**Middleware form**, for the routes where the axes come off the request:

```go
mux.Handle("/api/invoices/", v.Middleware(
    client.Requires("billing:invoice:approve", anubis.AxesFrom(func(r *http.Request) anubis.Scopes {
        return anubis.Scopes{"org": r.PathValue("org")}
    }))(approveHandler)))
```

Scopes come from a function rather than a static map because they are derived
per request. A static map would only be right for the routes where scoping does
not matter — and those are the routes that do not need this.

### 3.4 Refresh — the invariant the SDK owns

Refresh tokens are single-use and rotate. Two concurrent requests that both
notice an expired access token will both refresh; one wins, and the other
presents a consumed token. Anubis reads that, correctly, as theft — and revokes
the family and the session. **A naive client logs its own users out and pages a
human while doing it.**

That is not a documentation problem. The SDK serialises it:

```go
ts := client.TokenSource(tokens)      // safe for concurrent use

tok, err := ts.Token(ctx)             // refreshes once, behind single-flight;
                                      // every waiter gets the same new pair
ts.OnRotate(func(t anubis.Tokens) {   // persist before the old one is dropped
    session.Save(t)
})
```

`OnRotate` fires **before** `Token` returns, so a process that dies between the
two has already stored the new pair. Storing after would lose the rotation on a
crash and produce the same self-inflicted theft signal.

Genuine reuse is its own error type, and its documentation is one sentence long:

```go
var reuse *anubis.RefreshReuseError
if errors.As(err, &reuse) {
    // Do not retry. Two parties held this token; one was an attacker.
    // The family and session are already revoked. Drop the session, alert.
}
```

`RefreshReuseError` is the only error in the SDK that carries no retry advice,
because there is none.

### 3.5 Signing out — including the half everyone skips

```go
http.Redirect(w, r, client.LogoutURL(anubis.LogoutParams{
    Tenant:                "impack",
    PostLogoutRedirectURI: "https://billing.example.com/goodbye",
}), http.StatusFound)
```

And the back-channel receiver, which is shipped as a handler rather than
described in a document — because an app that skips it keeps users signed in
after they signed out everywhere, and apps skip what they have to write
themselves:

```go
mux.Handle("/anubis/backchannel-logout", client.BackchannelLogout(
    func(ctx context.Context, ev anubis.LogoutEvent) error {
        return sessions.KillBySID(ctx, ev.SessionID)   // ev.Subject, ev.Tenant too
    }))
```

The handler verifies the signed logout token against the same key ring the
`Verifier` uses, so the callback runs only on a real event.

### 3.6 No user present

```go
ts, err := client.ClientCredentials(ctx, anubis.ClientCredentialsParams{
    Tenant: "impack", ClientID: "billing-batch",
    ClientSecret: secret, Audience: "reporting-api",
})
req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
```

It returns a `TokenSource`, not a token, because these tokens are short-lived
and have no refresh — the source re-mints on expiry, which is the only correct
handling and therefore should not be the caller's to write.

A trusted back end asking about *its users* uses the tenant API key instead:

```go
client, _ := anubis.New(baseURL, anubis.WithAPIKey(os.Getenv("ANUBIS_API_KEY")))
```

`WithApplication` and `WithAPIKey` are mutually exclusive and the constructor
says so. They are different callers, and a client holding both would pick one
by accident.

### 3.7 Introspection, and the cache question

```go
in, err := client.Introspect(ctx, token)   // service credentials required
in.Active, in.Subject, in.Roles, in.AMR
```

Offline verification cannot see revocation. Introspection can, at the cost of
putting Anubis in the hot path — so it stays an explicit call, never something
the middleware does for you.

**Decision caching is off by default.** When enabled it is bounded and
explained, because a cache that ignores who asked is a data leak and a cache of
allows delays deprovisioning by exactly its TTL:

```go
anubis.WithDecisionCache(anubis.CacheConfig{
    TTL:     2 * time.Second,   // how long a disabled identity keeps its access
    MaxSize: 10_000,
})
```

Keyed on the full `(subject, permission, scopes, amr, auth_time)` tuple. Denies
carrying `step_up_required` are never cached — they become stale the moment the
user re-authenticates, which is the entire point of them.

### 3.8 Testing

An SDK that cannot be tested against gets integrated once and never touched
again.

```go
srv := anubistest.NewServer(t)          // signs real tokens, answers real RPCs
defer srv.Close()

srv.Allow("usr_1", "billing:invoice:approve", anubis.Scopes{"org": "o1"})
srv.Deny("usr_2", "billing:invoice:approve", anubis.Reason("scope_mismatch"))

token := srv.MintToken(anubis.Claims{Subject: "usr_1", Audience: []string{"billing-api"}})
client, _ := anubis.New(srv.URL, …)
```

`anubistest` is a separate package so the test server never links into
production binaries.

---

## 4. Errors

One taxonomy, both languages, mapped from the `ErrorInfo.code` the server puts
in the Connect error detail — the body is authoritative over the HTTP status,
because a proxy is free to rewrite a status and some do.

| Error | Means | Safe to retry? |
| :--- | :--- | :--- |
| `DeniedError` | `allow: false`. Carries `Reason`, `FailingAxis`, `Message` | No — the answer is no |
| `StepUpRequiredError` | Carries `RequiredAMR`, `MaxAuthAge`, `CurrentAMR`, `AuthAge` | After re-auth, via `BeginStepUp` |
| `RefreshReuseError` | Token theft. Family and session already revoked | **Never.** Alert a human |
| `AuthError` | Credential missing, rejected, or lacking scope | No |
| `RateLimitedError` | Carries `RetryAfter` | Yes, after the delay |
| `StateMismatchError` | Callback `state` did not match | No — treat as an attack |
| `EnrolmentRequiredError` | Realm requires an unenrolled factor. Carries `GrantToken` | After enrolling |
| `UnavailableError` | Anubis unreachable or not ready | Yes, with backoff |
| `APIError` | Anything else. Carries `Code`, `Message`, `RequestID`, `Status` | Depends on `Code` |

Every error carries `RequestID`, which correlates to `audit_log` and traces —
the first thing anyone asks for when an integration misbehaves.

Idiomatic per language: `errors.As` in Go, exception subclasses in PHP. A
client written by hand branches on `error.code`, which is the same information
under a different spelling — see `docs/WIRE.md`.

---

## 5. The second language

Same six capabilities, same names, idiomatic bindings.

### PHP — PSR-15 middleware, Laravel service provider

```php
use Anubis\Verifier;
use Anubis\Client;
use Anubis\Exception\StepUpRequiredException;

$verifier = new Verifier(issuer: 'https://anubis.internal',
                         audience: 'billing-api',
                         keysUrl:  'https://anubis.internal/.well-known/anubis-keys.json');

$app->add(new AnubisMiddleware($verifier));          // PSR-15

try {
    $client->require('billing:invoice:approve',
                     ['org' => $invoice->orgId, 'customer' => $invoice->customerId]);
} catch (StepUpRequiredException $e) {
    return redirect($client->stepUpUrl($e, $callbackUri));
}
```

Laravel gets a guard and a `Route::middleware('anubis:billing:invoice:approve')`
so the common case is a route annotation.

---

## 6. Repository layout

Mirrors `panmail-sdk`, so anyone who has seen one has seen both.

```
anubis-sdk/
  DESIGN.md              this document
  README.md              the quick starts, one table of packages
  doc.go  verifier.go  claims.go  keys/  paseto/     # Go: offline half
  client.go  login.go  authz.go  tokensource.go      # Go: online half
  errors.go  options.go
  anubistest/            # in-process fake Anubis
  admin/                 # grants, roles, scope nodes — operator credentials only
  anubiskit/             # separate module: go-kit over HTTP, gRPC and AMQP
  examples/billing-web/  # a worked browser application, end-to-end tested
  scripts/ci/local.sh    # every suite in one command
  php/                   # the second binding, self-contained
  proto/anubis/v1/       # vendored contract, the single source for codegen
  docs/
    WIRE.md              the contract, for people not using an SDK
    MIGRATION.md         pkg/anubis → anubis-sdk
    COMPATIBILITY.md     SDK version ↔ Anubis version
  scripts/gen.sh         regenerate every language from proto/
```

`proto/` is vendored here rather than fetched from the private server repo,
which is the point: the contract is public even though the implementation is
not, and it is what a client in any language is written against.
`scripts/gen.sh` regenerates the admin clients from it, so drift is a diff
rather than a discovery.

---

## 7. Three decisions this design asks you to make

### 7.1 The dependency has to invert

`pkg/anubis` is imported by **nine files** in the server — the token issuer,
the introspect and revoke interactors, the well-known handler, the gate handler,
the Connect authn interceptor, back-channel logout, client credentials and the
platform auth interactor. It is not a client-only package; it is the shared
definition of the token format, and both sides use it.

When the server goes private, `pkg/anubis` goes private with it, and moving it
out breaks those nine files unless the dependency inverts:

```
before:   app → anubis/pkg/anubis          (impossible once private)
after:    app → anubis-sdk  ←  anubis      (server depends on the SDK)
```

That is the correct direction anyway. The SDK holds the *contract* — PASETO
`v4.public`, the claim set, the key ring, the error vocabulary — and the server
is one implementation of it. Inverting also means the server cannot change the
token format without changing the public artefact that defines it, which is a
feature.

`go.work` already treats `pkg/anubis` as its own module, so the move is a
`replace` directive during the transition and a version bump after.

### 7.2 `docs/api.md` and the running server disagree

`docs/api.md` documents a REST surface — `POST /v1/auth/login`,
`POST /v1/authorize`, `GET /v1/me`, `GET /v1/sessions`,
`POST /v1/auth/token/refresh`. Grepping the route registrations turns up only:

```
/.well-known/anubis-keys.json   /p/   /v1/authorize   /v1/token
/v1/login   /v1/logout   /v1/gate/check   /healthz   /readyz   /metrics
```

Everything else is Connect RPC at `POST /anubis.v1.<Service>/<Method>`, which is
what `integration.md` describes and what the protos define. `integration.md`
matches the code; `api.md` reads like an earlier design that the transport
decision in [ADR-0008](https://github.com/gsoultan/anubis/blob/main/docs/adr/0008-transport-and-framework.md)
superseded.

**The SDK is built against Connect-over-JSON plus those browser paths**, and
`docs/WIRE.md` will pin exactly that. It is worth reconciling `api.md` in the
server repo either way — an SDK author who trusts it writes a client that 404s
on every call.

### 7.3 There is no batch decision RPC

`AuthorizeRequest` carries one permission and one scope set. Rendering a list of
200 invoices with a per-row "may approve" is 200 round trips, and the SDK cannot
hide that — a client-side loop is an N+1 with a nicer signature.

Three ways out, in the order I would take them:

1. **`AuthorizeBatch`** on `AuthzService` — repeated asks, repeated decisions,
   one round trip. Smallest change, solves the common case.
2. **`ListAuthorized(subject, permission, axis)`** — returns the nodes on an
   axis where the subject holds the permission, so the caller filters or, better,
   pushes it into their own `WHERE`. This is the one that scales.
3. Leave it, and have the SDK expose `AuthorizeMany` with bounded concurrency
   and a documented cost.

The SDK should ship (3) now and adopt (1) or (2) the moment the server has it.
Flagging it here because it is a server-side gap that will surface as "the SDK
is slow".

---

## 8. What building it changed

A design document that quietly pretends it predicted everything is less useful
than one that records where reality pushed back. Five things moved.

**The admin plane is a package, not a module.** §2 assumed it would be
generated from proto and therefore drag in connect-go. Hand-written against the
wire it needs nothing but the standard library, so isolating it in its own
module buys nothing. It stays a separate *package* for the reason that actually
holds: 120 procedures should not be in what a payments service embeds.

**It is also not for applications at all.** This is the big one, and §2 had it
wrong by implication. Anubis's `Guard.Require` refuses every non-platform
caller *before* it looks at a permission — "a different population… no tenant
grant can confer them". So "what roles does user X hold" is not a thing an
application is missing a grant for; there is no grant to ask for. And a tenant
key and an operator key are the same shape, so the package cannot refuse the
wrong one statically. It recognises the server's hint and raises
`ErrNotPlatformOperator` instead.

**`StepUpURL` became `BeginStepUp`.** Satisfying a step-up means a fresh
authorization request — new PKCE, new state — so it cannot be a pure function
returning a string. It needs the ResponseWriter, exactly as `BeginLogin` does.

**The primitives became a vocabulary.** §3 was written in `string`,
`[]string` and `map[string]string`. Every one of those was a place to pass the
right shape with the wrong meaning, so `Permission`, `Role`/`Roles`, `Axis`,
`Scopes`, `AuthMethods` and `Identity` now exist in both languages. Scope
*values* stayed plain strings: they are the caller's own identifiers, and
wrapping them would add a conversion at every call site to prevent nothing.

**go-kit got its own module, and three transports.** Not foreseen here at all.
`anubiskit` is separate because go-kit *is* a dependency and the root's promise
is that it has none — the argument that turned out not to apply to `admin`
applies exactly to this. Its service and endpoint layers are shared verbatim
across HTTP, gRPC and AMQP, which is the claim go-kit makes and the reason the
Anubis middleware is written once rather than three times.

## 9. Assumptions

- **Four languages**, matching `panmail-sdk`: Go, PHP, Java, Node. *Did not
  hold.* Node and Java were built, tested and then cut before the first
  release: applications in those languages go against `docs/WIRE.md` directly.
  This was the assumption most worth stating, because it did change the shape
  of the repository more than anything else in this document — two of the four
  CI jobs, the npm half of the release workflow, and the version-agreement
  check that existed only because `package.json` and `pom.xml` carried a
  version number, all went with them. What survived unchanged is the thing
  that mattered: `docs/WIRE.md` is normative, so removing a binding removes a
  convenience rather than an interface.
- **Integration first, admin second.** Held: the six capabilities in §2 landed
  first, `admin/` after. Admin is Go-only, which suits operator tooling; PHP
  has the integration half only.
