# gsoultan/anubis-sdk

PHP client for integrating an application with an [Anubis](https://github.com/gsoultan/anubis)
identity service: **verify offline, ask before you act**, with typed refusals
you can catch separately.

No third-party cryptography and no HTTP library. Ed25519 comes from
`ext-sodium` and requests from `ext-curl` — PASETO `v4.public` is a format, and
the format is implemented here; the primitives are not.

```bash
composer require gsoultan/anubis-sdk
```

Requires PHP 8.2+ with `ext-sodium`, `ext-curl` and `ext-json`.

## Two objects, two jobs

**Verify** runs on every request. Pure CPU, microseconds, no network — the
token's Ed25519 signature is checked against the issuer's published keys.

**Ask** runs before a privileged action. Whether somebody *may* do a thing
depends on grants, scopes and identity state that only Anubis holds and that
change without your application redeploying, so it is a call.

A service that only consumes tokens never constructs a `Client`.

## Verify

```php
use Anubis\Verifier;
use Anubis\Principal;

$verifier = new Verifier(
    issuer:   'https://anubis.internal',
    audience: 'billing-api',
    keysUrl:  'https://anubis.internal/.well-known/anubis-keys.json',
);

$token     = Verifier::bearer($_SERVER['HTTP_AUTHORIZATION'] ?? null);
$claims    = $verifier->verify($token);
$principal = new Principal($claims, $token);
```

`audience` is mandatory. A verifier without one accepts tokens minted for
other services, which is a confused deputy waiting to happen.

Keys are fetched once and cached. A TTL bounds how stale the document may get,
so a key withdrawn upstream stops verifying; a separate min-refetch interval
bounds what an unknown `kid` can provoke, because `kid` arrives inside
attacker-supplied tokens. A failed fetch leaves the previous document in place
— stale keys beat no keys.

Whoever answers `keysUrl` decides which keys you trust, so plaintext `http` is
refused unless the host is loopback, and a document naming a different issuer
than you configured is refused outright.

## Ask

```php
use Anubis\Exception\DeniedException;
use Anubis\Exception\StepUpRequiredException;

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

## Refusals are typed

A denial is not an exception you log and move past — each one has a different
correct response, so each is its own class under `Anubis\Exception\`.

| Exception | What the caller should do |
| :--- | :--- |
| `DeniedException` | 403. They may not do this. |
| `StepUpRequiredException` | `beginStepUp` — re-authenticate, then retry. |
| `EnrolmentRequiredException` | Send them to enrol a factor. |
| `RefreshReuseException` | The refresh token was replayed. Kill the session. |
| `StateMismatchException` | The callback did not match the request. Do not retry. |
| `RateLimitedException` | Back off. |
| `UnavailableException` | Anubis is down. Fail closed. |
| `VerificationException` | The token is not valid. 401. |

## Sign-in, refresh, sign-out

`Client` covers the rest: `beginLogin` / `completeLogin` for PKCE, `refresh`
for rotation with reuse detection, `clientCredentials` for when no user is
present, and `logoutUrl` / `logoutAll` for sign-out including the
back-channel half.

## The rest

This package is one of two — Go and PHP — built from
[gsoultan/anubis-sdk](https://github.com/gsoultan/anubis-sdk) against one
normative contract, [`docs/WIRE.md`](https://github.com/gsoultan/anubis-sdk/blob/main/docs/WIRE.md).
Read that if you would rather POST the JSON yourself.

> This repository is a **read-only mirror**. Packagist reads `composer.json`
> from a repository root and the PHP package lives in `php/` of the monorepo,
> so this is split out of it. File issues and pull requests
> [upstream](https://github.com/gsoultan/anubis-sdk/issues).

MIT.
