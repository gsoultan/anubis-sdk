# anubis-sdk

The Go client for integrating an application with an
[Anubis](https://github.com/gsoultan/anubis) identity service: **verify
offline, ask before you act**, typed refusals you can branch on, and a refusal
to let you skip the checks that matter.

```bash
go get github.com/gsoultan/anubis-sdk
```

**No dependencies.** Not "few" — the root module's `go.mod` has no `require`
block at all, and CI fails if one appears. A service that only wants to verify
a token should not inherit a dependency tree for it. Ed25519 is
`crypto/ed25519`; PASETO `v4.public` is a format, and the format is written
here while the primitives are not.

It does not depend on the server's source either. It speaks
[the wire contract](docs/WIRE.md).

## Any other language

There is no client library for your language here, and you do not need one.
Everything this SDK does is HTTP against a documented contract:
[**`docs/WIRE.md`**](docs/WIRE.md) is normative — routes, the two JSON naming
conventions and the seam between them, the claim set, the keys document, the
error envelope. It is written to be implemented against, and anything in it
can be spoken with `curl`.

Read [Four things worth knowing before you ship](#four-things-worth-knowing-before-you-ship)
first. Those four are what a hand-written client most often gets wrong, and
three of them are silent when they are wrong. For PASETO itself,
[`paseto/paseto_test.go`](paseto/paseto_test.go) asserts the specification's
PAE golden vectors — check a hand-written implementation against those rather
than against this one.

## The shape of an integration

It is two jobs, and they have nothing in common.

**Verify** runs on every request. Pure CPU, microseconds, no network, no
database — the SDK checks the token's Ed25519 signature against published keys.

**Ask** runs before a privileged action. Whether somebody *may* do something
depends on grants, scopes and identity state that only Anubis holds and that
change without your application redeploying, so it is a call.

So the SDK gives you two objects: a `Verifier` you embed everywhere, and a
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

## Using it

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

## Four things worth knowing before you ship

**The audience check is not optional.** A verifier without one accepts tokens
minted for the HR application in the payments application — the classic
confused deputy. `NewVerifier` refuses to construct one without an audience,
and there is no flag to skip it.

**Supply every axis the action touches.** On a strict axis an omitted axis is
*denied*, not ignored. "I forgot an axis" and "they may not do this" look
identical from outside, so a forgotten axis shows up as a permissions bug that
is really a client bug.

**Never refresh from two places at once.** Refresh tokens are single-use and
rotate. Two concurrent handlers that both refresh will produce
`refresh_token_reuse_detected`, which Anubis correctly reads as theft and
answers by revoking the family and the session — your own users, logged out, by
your own client. Use `TokenSource`, which serialises refreshes behind a single
flight. Writing your own client does not remove the constraint, and in a
runtime whose processes are per-request it is harder: no in-process lock helps,
so take one in whatever your sessions already share.

**Mount the back-channel logout receiver.** It is the half of sign-out
applications skip, because it is the half they have to write themselves — and
an application with its own session cookie keeps a user signed in after they
have signed out everywhere. The SDK ships it as a handler; wire it to the URI
you registered.

## Repository layout

```
.                 Go: the offline half and the client, one module, no dependencies
admin/            grants, roles, scope nodes and their sources — operators only
anubistest/       an in-process Anubis for tests, integration plane and admin
anubiskit/        go-kit adapter for HTTP, gRPC and AMQP — a SEPARATE module
examples/         a worked browser application, end-to-end tested
proto/anubis/v1/  the vendored contract, for reference — nothing generates
docs/WIRE.md      the contract in prose, for people not using an SDK
docs/MIGRATION.md pkg/anubis → anubis-sdk, and the dependency inversion
DESIGN.md         why the SDK is shaped this way
```

## The vocabulary

None of these is a `string`, a `[]string` or a map. Each was, once, and each
was a place to pass the right shape with the wrong meaning:

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

Implemented and tested — offline verification, PKCE sign-in, decisions with
step-up, rotation with reuse detection, back-channel logout, client
credentials:

| Module | Tests | |
| :--- | ---: | :--- |
| root (`.`, `keys`, `paseto`, `admin`, `examples`) | 101 | `go test -race ./...` |
| `anubiskit` (HTTP, gRPC, AMQP) | 21 | `cd anubiskit && go test -race ./...` |

Two modules, one command:

```bash
scripts/ci/local.sh
```

It runs gofmt, vet and the race detector over both, and asserts the thing the
tests cannot: that the root `go.mod` still has no `require` block.
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) does the same, with the
toolchain pinned, so a missing `go` on a developer machine cannot read as a
pass.

`paseto/` asserts the specification's PAE golden vectors, which pins token
handling byte for byte against the format rather than against this
implementation of it.

PHP, Node and Java clients were built and then removed before the first
release. They are in the history — PHP at `d52d0c5`, Node and Java at
`3443a1d` — if they are ever wanted back. Applications in those languages go
against [`docs/WIRE.md`](docs/WIRE.md) directly, which is normative and was
always the contract those clients were written to.

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
embeds.

It also configures where roles and scope nodes are read from, and which door a
population signs in through:

```go
ops.CatalogSources(ctx)                        // where an app's roles are read from
ops.RunCatalogSource(ctx, id, true)            // dry run first: reports, writes nothing
ops.SetSyncSchedule(ctx, "syn_1", 6*time.Hour) // when an org chart is re-read
ops.AuthPages(ctx, "signin")                   // the sign-in pages a tenant serves
```

Three rules there are enforced here rather than discovered:
`SetSyncSchedule` changes *when* a source runs and nothing else, because the
update call replaces config wholesale and a client is never sent a source's dsn
or auth header to send back. A schedule is either zero — manual — or at least
`admin.MinScheduleInterval`, and anything shorter is refused without a round
trip. An auth page binds to an application **or** a realm, never both, so
`UpdateAuthPage` returns `ErrAuthPageBinding` rather than letting the database
answer with a constraint name.

A catalog source's application is pinned when it is created, which is why
`CatalogSourceUpdate` has no field for it. The rest of the surface — creating
tenants — is not wrapped.

### Manifests: where permissions come from

Nobody types `billing:invoice:approve` into a console. An application
*declares* the permissions it has, the roles that bundle them, and the route
rules that say which paths need which permission. That declaration is a
**manifest**, and applying one is a reconcile — the server diffs the document
against what is installed and moves the catalog to match, the way a migration
does.

A manifest has three sections, and **they are independent**. What decides
whether a section is touched is whether the document *declares* it — not
whether it has content:

```go
m := admin.Manifest{}.WithRoles(
    admin.ManifestRole{Name: "clerk", Permissions: []string{"invoice:approve"}},
)
// {"roles":[{"name":"clerk","permissions":["invoice:approve"]}]}
```

That document changes roles and touches nothing else. It is **not** saying the
application has no permissions and no routes — an absent key means "leave that
alone", which is why a CSV export of roles is a legal manifest.

Inside a declared section, whatever the document stops naming is retired
rather than removed. Except routes:

| Section | Named | Stopped naming |
| :--- | :--- | :--- |
| `permissions` | upserted | **deprecated** — never deleted, nobody loses one |
| `roles` | upserted | **retired** — existing grants keep deciding, nobody new can be granted |
| `routes` | — | the whole table is **replaced** by what the document says |

That asymmetry is the sharp edge. The server refuses a `permissions` or `roles`
section that is present but empty — it will not deprecate a whole catalog in
one apply. **The route table has no such rail**: an empty routes section
empties it. So `WithRoutes()` with no routes is refused here, and emptying the
table on purpose is spelled `ClearRoutes()`.

Run a dry run first and print it. The server executes the whole apply in a
transaction it then rolls back, so the report is the real diff:

```go
rep, _ := ops.DryRunManifest(ctx, "billing", m)
fmt.Print(rep)
```

```
dry run — nothing was written
  permissions  1 applied, 1 deprecated (kept, not deleted)
  roles        1 applied, 1 retired (existing grants keep working)
  routes       not declared — left alone
```

One more trap, caught locally because the server's own code calls it out:
roles and routes name permissions as `resource:action` — **without** the
application slug, since the manifest is already scoped to one application.
Write `invoice:approve`, not `billing:invoice:approve`. `Validate` rejects the
full key and tells you which form to use.

Have a JSON file or a spreadsheet export already? `ApplyManifestDocument` takes
the bytes and a format (`json` or `csv`). A CSV carries one section per file,
decided by its header; routes are JSON only, because a route's ordering and
scope bindings do not survive being flattened into cells.
