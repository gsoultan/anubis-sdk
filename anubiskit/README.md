# anubiskit

Anubis for [go-kit](https://gokit.io) services — over **HTTP, gRPC and AMQP**.

```
go get github.com/gsoultan/anubis-sdk/anubiskit
```

A **separate module**, on purpose. go-kit is a dependency and the SDK it wraps
promises to have none: a service that only verifies tokens should not pull in a
framework it does not use.

## One rule, three transports

The point of putting authentication and authorization at the endpoint layer is
that they are written once. In [`examples/`](examples), the `billing` package —
service *and* endpoints, including every Anubis middleware — is shared verbatim
by three transports. Only the codecs differ.

```go
// examples/billing/endpoints.go — this is the whole integration, for all three
Approve: authenticate(
    loadInvoice(svc)(
        anubiskit.Authorize(c, "billing:invoice:approve", ScopesOfInvoice)(
            makeApproveEndpoint(svc)))),
```

| | HTTP | gRPC | AMQP |
| :--- | :--- | :--- | :--- |
| credential arrives in | `Authorization` header | `authorization` metadata | `authorization` message header |
| lift it inward | `HTTPToContext()` | `GRPCToContext()` | `AMQPToContext()` |
| forward it outward | `ContextToHTTP()` | `ContextToGRPC()` | `ContextToAMQP()` |
| wire it with | `ServerBefore` | `ServerBefore` | `SubscriberBefore` |
| render a refusal | `ErrorEncoder` | `GRPCError(ctx, err)` | `NackErrorEncoder` |

Common to all three: `Authenticate(v)` verifies offline and puts the principal
in the context; `Authorize(c, perm, scopes)` asks Anubis; `RequireAMR(…)` is a
step-up gate read straight off the token without asking.

## Scopes come from the request, not the URL

```go
type ScopeFunc func(ctx context.Context, request any) anubis.Scopes
```

No `*http.Request` — deliberately, and this is what makes one rule serve three
transports. The axes an action is scoped on are a property of the action, not
of the URL it arrived on, so the same `ScopesOfInvoice` works for a path
parameter, a protobuf field and a JSON message body.

The axes usually live on a record you have to load first, which is an ordering
problem: you cannot ask "may they approve this invoice" until you know whose
invoice it is. Put the lookup in a middleware between `Authenticate` and
`Authorize` and read it back off the context — doing it in a transport decoder
puts a database call in a function whose job is parsing bytes, and doing it
inside the service puts the decision after the work has started.
[`examples/billing/endpoints.go`](examples/billing/endpoints.go) does exactly
this, and all three transport tests assert both axes arrived.

## What a refusal becomes

### HTTP

| Refusal | Status | Body |
| :--- | :--- | :--- |
| `StepUpRequiredError` | **401** + `WWW-Authenticate` | `step_up_required`, with `required_amr` and `max_auth_age` |
| `DeniedError` | 403 | the reason Anubis gave, with `failing_axis` |
| bad or missing token | 401 + `WWW-Authenticate` | `unauthenticated`, and nothing else |
| `RateLimitedError` | 429 + `Retry-After` | `rate_limited` |
| `UnavailableError` | 503 | `unavailable` |

Step-up is **401 rather than 403** because the caller can do something about
it, and 403 tells them not to bother trying.

### gRPC

gRPC has no 401/403 split. `Unauthenticated` means the credential is not good
enough — which is exactly what a step-up refusal says, and it is fixable —
while `PermissionDenied` means we know who you are and the answer is no.

| Refusal | Code | Trailer |
| :--- | :--- | :--- |
| `StepUpRequiredError` | `Unauthenticated` | `anubis-error`, `anubis-required-amr`, `anubis-max-auth-age` |
| `DeniedError` | `PermissionDenied` | `anubis-error`, `anubis-failing-axis` |
| bad or missing token | `Unauthenticated` | `anubis-error: unauthenticated` |
| `RateLimitedError` | `ResourceExhausted` | `anubis-error: rate_limited` |
| `UnavailableError` | `Unavailable` | `anubis-error: unavailable` |

The structured part rides in **trailer metadata** rather than status details,
because status details are proto messages and reading "which axis failed"
should not require generating a schema.

### AMQP — the only question is whether to requeue

A queue answers nobody. There is no status code to return, only a choice
between putting the message back and giving up on it, and getting it backwards
is expensive both ways: requeue a permanent failure and the queue spins on it
forever; dead-letter a transient one and you have thrown away work because a
dependency blinked.

```go
func Retryable(err error) bool   // rate-limited or unavailable → yes; everything else → no
```

`NackErrorEncoder` nacks with `requeue = Retryable(err)`. A refused credential
and a denial are permanent — **a message does not become authorised by being
delivered again** — so they dead-letter. Anubis being unreachable does not.

The case peculiar to queues: a message can be consumed long after it was
published, so a user's short-lived token may well have expired in the queue.
That is permanent too, and requeuing it is an infinite loop that time only
makes worse. Publish a client-credentials token with enough life instead.

## In both directions

`ContextToGRPC` and `ContextToAMQP` put the credential back on an outgoing
call, for a service acting on a caller's behalf. The forwarded token keeps its
original audience, so the receiving service — which pins its own — refuses it
unless it was minted for that service. Forwarding authority should not silently
widen it.

## The examples

```
examples/billing/    service + endpoints — transport-free, shared by all three
examples/http/       net/http transport
examples/grpc/       protoc-generated, real server over a real socket
examples/amqp/       an AMQP worker, tested with no broker
```

```
go test ./examples/...     # 21 cases, race-clean
```

None of them needs an Anubis: `anubistest` runs one in-process. The AMQP suite
needs no broker either — go-kit's `Subscriber.ServeDelivery(Channel)` takes the
two interfaces a broker would have supplied, and what a broker adds is network,
which is not what goes wrong here.
