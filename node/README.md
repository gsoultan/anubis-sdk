# @gsoultan/anubis-sdk

Node client for integrating an application with an [Anubis](https://github.com/gsoultan/anubis)
identity service: **verify offline, ask before you act**, with typed refusals
you can branch on.

No dependencies. Ed25519 comes from `node:crypto` and HTTP from `fetch` —
PASETO `v4.public` is a format, and the format is implemented here; the
primitives are not.

```bash
npm i @gsoultan/anubis-sdk
```

Requires Node 18+.

## Two objects, two jobs

**Verify** runs on every request. Pure CPU, microseconds, no network — the
token's Ed25519 signature is checked against the issuer's published keys.

**Ask** runs before a privileged action. Whether somebody *may* do a thing
depends on grants, scopes and identity state that only Anubis holds and that
change without your application redeploying, so it is a call.

A service that only consumes tokens never constructs a `Client`.

## Verify

```ts
import { Verifier, requireToken } from "@gsoultan/anubis-sdk";

const verifier = new Verifier({
  issuer: "https://anubis.internal",
  audience: "billing-api",
  keysUrl: "https://anubis.internal/.well-known/anubis-keys.json",
});

app.use(requireToken(verifier)); // sets req.anubis
```

`audience` is mandatory. A verifier without one accepts tokens minted for
other services, which is a confused deputy waiting to happen.

Keys are fetched once and cached. A TTL bounds how stale the document may get,
so a key withdrawn upstream stops verifying; a separate min-refetch interval
bounds what an unknown `kid` can provoke, because `kid` arrives inside
attacker-supplied tokens. Fetches are single-flight, and a failed one leaves
the previous document in place — stale keys beat no keys.

Whoever answers `keysUrl` decides which keys you trust, so plaintext `http` is
refused unless the host is loopback, and a document naming a different issuer
than you configured is refused outright.

## Ask

```ts
import { Client, requires, isStepUpRequired } from "@gsoultan/anubis-sdk";

app.post(
  "/invoices/:id/approve",
  requires(client, "billing:invoice:approve", (req) => ({ org: req.params.org })),
  handler,
);
```

Or by hand, when you want to handle the refusal yourself:

```ts
try {
  await client.require(req.anubis, "billing:invoice:approve", { org, customer });
} catch (e) {
  if (isStepUpRequired(e)) {
    const redirect = client.beginStepUp(e, { redirectUri: cb });
    res.setHeader("Set-Cookie", redirect.cookie);
    return res.redirect(redirect.url);
  }
  throw e;
}
```

## Refusals are typed

A denial is not an exception you log and move past — each one has a different
correct response, so each is its own class.

| Error | What the caller should do |
| :--- | :--- |
| `DeniedError` | 403. They may not do this. |
| `StepUpRequiredError` | `beginStepUp` — re-authenticate, then retry. |
| `EnrolmentRequiredError` | Send them to enrol a factor. |
| `RefreshReuseError` | The refresh token was replayed. Kill the session. |
| `StateMismatchError` | The callback did not match the request. Do not retry. |
| `RateLimitedError` | Back off. |
| `UnavailableError` | Anubis is down. Fail closed. |
| `VerificationError` | The token is not valid. 401. |

`isDenied`, `isStepUpRequired` and `isRefreshReuse` are narrowing guards for
the three you will branch on most.

## Sign-in, refresh, sign-out

`Client` covers the rest of the integration: `beginLogin` / `completeLogin`
for PKCE, `TokenSource` for refresh with rotation and reuse detection,
`clientCredentials` for when no user is present, and `logoutUrl` /
`logoutAll` for sign-out including the back-channel half.

## The rest

This package is one of four — Go, PHP, Java and Node — built from
[gsoultan/anubis-sdk](https://github.com/gsoultan/anubis-sdk) against one
normative contract, [`docs/WIRE.md`](https://github.com/gsoultan/anubis-sdk/blob/main/docs/WIRE.md).
Read that if you would rather POST the JSON yourself.

MIT.
