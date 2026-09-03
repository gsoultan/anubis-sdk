# anubis-sdk

Clients for integrating an application with an [Anubis](https://github.com/gsoultan/anubis)
identity service, in Go and PHP.

Both are the same small library in two languages: **verify offline, ask before
you act**, typed refusals you can branch on, and a refusal to let you skip the
checks that matter. Neither depends on the server's source — they speak
[the wire contract](docs/WIRE.md).

| Language | Package | Install | Runtime deps |
| --- | --- | --- | --- |
| **Go** | `github.com/gsoultan/anubis-sdk` | `go get github.com/gsoultan/anubis-sdk` | none — stdlib only |
| **PHP** | `gsoultan/anubis-sdk` | `composer require gsoultan/anubis-sdk` | ext-curl, ext-json, ext-sodium |

PHP publishes from a read-only mirror, because Packagist reads `composer.json`
only from a repository root and this one lives in `php/`. `anubiskit` is
deliberately untagged — see [CHANGELOG.md](CHANGELOG.md).

No third-party cryptography in either: Ed25519 comes from `crypto/ed25519` and
ext-sodium. PASETO `v4.public` is a format, and formats are written here;
primitives are not.

## Any other language

There is no client library for your language here, and you do not need one.
Everything an SDK does is HTTP against a documented contract:
[**`docs/WIRE.md`**](docs/WIRE.md) is normative — routes, the two JSON naming
conventions and the seam between them, the claim set, the keys document, the
error envelope. It is written to be implemented against, and anything in it
can be spoken with `curl`.

Read [Four things worth knowing before you ship](#four-things-worth-knowing-before-you-ship)
first. Those four are what a hand-written client most often gets wrong, and
three of them are silent when they are wrong.

## The shape of an integration

It is two jobs, and they have nothing in common.

**Verify** runs on every request. Pure CPU, microseconds, no network, no
database — the SDK checks the token's Ed25519 signature against published keys.

**Ask** runs before a privileged action. Whether somebody *may* do something
depends on grants, scopes and identity state that only Anubis holds and that
change without your application redeploying, so it is a call.

So each SDK gives you two objects: a `Verifier` you embed everywhere, and a
`Client` you reach for when you need Anubis to decide something. A service that
only consumes tokens never constructs the second one.

## Getting set up

Register your application in the console under **Access → Applications**. You
need its `slug` — which is also its `client_id`, and the `aud` its tokens carry
— plus exact `redirect_uris`, a separate `post_logout_redirect_uris` allowlist,
and a `backchannel_logout_uri`. `web`, `server` and `service` kinds get a client
secret, shown once.

A trusted back end that asks about its users wants a tenant API key instead
(`anb_live_…`), from the same screen. It is the tenant's credential, not a
person's.

## Go

```go
import anubis "github.com/gsoultan/anubis-sdk"

// every request, offline
v, err := anubis.NewVerifier(anubis.Config{
    Issuer:   "https://anubis.internal",
    Audience: "billing-api",     // mandatory — see below
    KeysURL:  "https://anubis.internal/.well-known/anubis-keys.json",
})
mux.Handle("/api/", v.Middleware(apiHandler))

// before a privileged action
client, _ := anubis.New("https://anubis.internal", anubis.WithAPIKey(key))

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
        http.Error(w, denied.Message, http.StatusForbidden)  // .FailingAxis names the axis
        return
    }
    return err
}
```

Browser sign-in is two calls, and the SDK owns the PKCE verifier and the state:

```go
redirect, _ := client.BeginLogin(w, anubis.LoginParams{RedirectURI: cb})
http.Redirect(w, r, redirect.URL, http.StatusFound)

// …at the callback
tokens, err := client.CompleteLogin(ctx, w, r)   // state is checked before anything is exchanged
```

Testing needs no server: `anubistest.NewServer(t)` signs real tokens and
answers the real wire shapes in-process.

Using go-kit? [`anubiskit/`](anubiskit) is the adapter, in the shape of
go-kit's own `auth/jwt`: a `RequestFunc` lifts the credential inward and
`endpoint.Middleware` does the rest — over **HTTP, gRPC and AMQP**, with the
service and endpoint layers written once and shared by all three. It is a
separate module so the root stays dependency-free.

## PHP

```php
use Anubis\Client;
use Anubis\Verifier;
use Anubis\Exception\DeniedException;
use Anubis\Exception\StepUpRequiredException;

$verifier = new Verifier(
    issuer:   'https://anubis.internal',
    audience: 'billing-api',
    keysUrl:  'https://anubis.internal/.well-known/anubis-keys.json',
);
$claims    = $verifier->verify(Verifier::bearer($_SERVER['HTTP_AUTHORIZATION'] ?? null));
$principal = new Anubis\Principal($claims, $token);

try {
    $client->require($principal, 'billing:invoice:approve', [
        'org' => $invoice->orgId, 'customer' => $invoice->customerId,
    ]);
} catch (StepUpRequiredException $e) {
    $redirect = $client->beginStepUp($e, ['redirectUri' => $callbackUri]);
    header('Set-Cookie: ' . $redirect['cookie']);
    header('Location: ' . $redirect['url']);
} catch (DeniedException $e) {
    http_response_code(403);   // $e->failingAxis names the axis that failed
}
```

## Four things worth knowing before you ship

**The audience check is not optional.** A verifier without one accepts tokens
minted for the HR application in the payments application — the classic
confused deputy. Every one of these SDKs refuses to construct a verifier
without an audience, and none of them has a flag to skip it.

**Supply every axis the action touches.** On a strict axis an omitted axis is
*denied*, not ignored. "I forgot an axis" and "they may not do this" look
identical from outside, so a forgotten axis shows up as a permissions bug that
is really a client bug.

**Never refresh from two places at once.** Refresh tokens are single-use and
rotate. Two concurrent handlers that both refresh will produce
`refresh_token_reuse_detected`, which Anubis correctly reads as theft and
answers by revoking the family and the session — your own users, logged out, by
your own client. In Go use `TokenSource`, which serialises refreshes behind a
single flight. In PHP the contention is between *processes*, which no
in-process lock can fix: take a lock in whatever your sessions already share —
and that is the shape of the problem in any language whose runtime is
per-request, so a hand-written client needs the same lock.

**Mount the back-channel logout receiver.** It is the half of sign-out
applications skip, because it is the half they have to write themselves — and
an application with its own session cookie keeps a user signed in after they
have signed out everywhere. Each SDK ships it as a handler; wire it to the URI
you registered.

## Repository layout

```
.                 Go: the offline half and the client, one module, no dependencies
admin/            grants, roles and scope nodes — operator credentials only
anubistest/       an in-process Anubis for tests, integration plane and admin
anubiskit/        go-kit adapter for HTTP, gRPC and AMQP — a SEPARATE module
examples/         a worked browser application, end-to-end tested
php/              the PHP client, self-contained, published from a split mirror
proto/anubis/v1/  the vendored contract, the single source for codegen
docs/WIRE.md      the contract in prose, for people not using an SDK
docs/MIGRATION.md pkg/anubis → anubis-sdk, and the dependency inversion
DESIGN.md         why the SDK is shaped this way
```

## The vocabulary

None of these is a `string`, a `string[]` or a map, in either language. Each
was, once, and each was a place to pass the right shape with the wrong
meaning:

| Type | What it knows | The mistake it makes visible |
| :--- | :--- | :--- |
| `Permission` | `app`, `resource`, `action`, `manifest()` | a manifest writes `invoice:approve`, a token carries `billing:invoice:approve` |
| `Role` / `Roles` | `app`, `name`, `ofApp()`, `has()` | roles come back prefixed — comparing against the manifest name silently never matches |
| `Scopes` | `with()`, `merge()`, `node()`, `axes()` | a mistyped axis is not rejected, it is *unsupplied*, and unsupplied on a strict axis is **denied** |
| `AuthMethods` | `has()`, `hasAll()` | `hasAll` is the local step-up check; `hasAny` would be the wrong one |
| `Identity` | roles, scopes, `authenticatedAt`, `authAge`, `isApplication` | authentication time is not issue time — a refresh mints without fresh proof |

`Identity` is the answer to "how do I get the roles and scopes for this
caller": one accessor off the verified request, no claim-set spelunking.

```go
id, _ := anubis.IdentityFromContext(ctx)   // Go
id.Roles.OfApp("billing")
id.ActiveScope("org")
id.AuthAge()
```

Scope *values* stay plain strings on purpose: they are your own identifiers out
of your own database, and wrapping them would add a conversion at every call
site to prevent nothing.

> **`Identity` is a view of a SESSION, not of a person.** `roles` and `scopes`
> are what the token was minted with — the roles held at issuance, and the ONE
> node per axis the session is acting as. It is not everything the person is
> entitled to. That lives in grants, which carry many nodes per axis with
> inheritance, and grants are the admin plane's business. There is no procedure
> today that lists the scope nodes somebody may switch to, so a scope picker
> cannot be built without it.

## Status

Both languages are implemented and tested — offline verification, PKCE
sign-in, decisions with step-up, rotation with reuse detection, back-channel
logout, client credentials:

| | Tests | Runner |
| :--- | ---: | :--- |
| Go | 79 (root, `keys`, `paseto`, `admin`, examples) + 21 (`anubiskit`) | `go test -race ./...` |
| PHP | 39 | `php tests/run.php` |

Two languages and two Go modules, one command:

```bash
scripts/ci/local.sh              # everything this machine can run
scripts/ci/local.sh go           # or just the one you touched
```

A missing toolchain is reported as **SKIP** and exits non-zero. A green tick
that only means "php was not installed" is worse than no suite at all.
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) gives each language its
own job so that branch cannot be taken in CI, and asserts one thing the tests
cannot: that the root `go.mod` still has no `require` block.

Both PASETO implementations assert the same PAE golden vectors from the
specification, so token handling is pinned byte for byte — and those vectors
are the thing to check a hand-written client against too.

Node and Java clients were built and then removed before the first release;
they are in the history at `3443a1d` if they are ever wanted back. Applications
in those languages go against [`docs/WIRE.md`](docs/WIRE.md) directly.

## Entitlement is a different question, and a different credential

`Identity` tells you what a *session* holds. What a *person* is entitled to
lives in grants, and [`admin/`](admin) reads those:

```go
rpc, _ := anubis.New(url, anubis.WithAPIKey(operatorKey), anubis.WithTenant("impack"))
ops, _ := admin.New(rpc)

ent, _ := ops.Entitlements(ctx, "usr_1")
ent.Roles()          // every role their live grants confer
ent.Nodes("org")     // every org they may act on — what a scope picker renders
ent.Axes()           // which axes constrain them at all
ent.IsUnscoped()     // or whether a grant reaches everything
```

`Nodes(axis)` is the thing the integration SDK cannot answer. A token carries
the **one** node per axis a session is acting as; a person may hold many, on
the same axis, with inheritance. Feed the result to `SwitchScope`.

Grants are not booleans — they have validity windows and revocations —
so `Grants` returns revoked ones too (an access review that cannot see what was
taken away is not a review) and `Entitlements` keeps only what `Grant.IsLive`
accepts.

> **This needs a platform operator, not an application.** Anubis's guard
> refuses every non-platform caller before it looks at a permission: *"Not a
> policy lookup that happens to deny — a different population. The permission
> strings this plane checks exist only in the operator role allow-lists; no
> tenant grant can confer them."* The `anb_live_` key your application holds is
> denied here at any scope, and there is no grant to ask for that would change
> it. Worse, a tenant key and an operator key are **the same shape** — the
> server decides by which store issued it. So the package cannot refuse the
> wrong one statically; it turns the server's refusal into
> `admin.ErrNotPlatformOperator` instead, which says what is actually wrong.

`admin` is a package, not a separate module: hand-written against the wire it
needs nothing but the standard library, so isolating it buys nothing. It stays
separate so the 120-procedure surface is not in the package a payments service
embeds. The rest of that surface — creating tenants, applying manifests,
syncing scope sources — is not wrapped yet.
