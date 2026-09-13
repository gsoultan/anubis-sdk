# The wire contract

What an Anubis installation actually serves, pinned to the running server
rather than to the design documents. Anything here can be spoken with `curl`;
the SDK is a convenience, not a requirement.

Base URL is the installation's origin — `https://anubis.internal`. Everything
is on one port.

## Two protocols, and the seam between them

| | **Connect RPC** | **Browser HTTP** |
| :--- | :--- | :--- |
| Route | `POST /anubis.v1.<Service>/<Method>` | `/v1/authorize`, `/v1/token`, `/v1/login`, `/v1/logout`, `/v1/gate/check` |
| Body | JSON | form-encoded, or query string |
| Response field names | **lowerCamelCase** | **snake_case** |
| Error shape | Connect error object | the plain envelope |

That naming seam is real and it bites. `AuthService.Refresh` answers
`{"tokens":{"accessToken":…,"expiresIn":600}}`, while `POST /v1/token` answers
`{"access_token":…,"expires_in":600}` — the same pair, spelled two ways,
because the Connect procedures are rendered by protojson and the browser
endpoint writes its JSON by hand. The SDK carries two decoders for one
concept, and that is why — so does anything else that speaks both.

**Requests may use either spelling.** protojson accepts both the proto field
name and lowerCamelCase on input, so `client_id` and `clientId` both work. The
The SDK sends proto names, which is what the API documentation shows.

**int64 is a JSON string.** protojson renders 64-bit integers quoted, because a
JSON number cannot hold the range:

```jsonc
{ "enrolmentRequired": { "deadline": "1787000000" } }   // string, not number
{ "active": true, "exp": "1735689600" }                 // string, not number
```

A client that assumes a number gets `0` on a field that decides whether
somebody keeps their access. Affected fields: `deadline`, `exp`, `auth_time`,
`created_at`, `last_seen_at`, `expires_at`.

**protojson discards unknown fields.** A misspelt request field is silently
ignored rather than rejected, so a typo in a client shows up as a decision that
quietly loses an axis. Field names are worth testing against a real server.

## Authenticating a caller

| Caller | Header |
| :--- | :--- |
| End user | `Authorization: Bearer <access token>` |
| Trusted back end, on behalf of its users | `Authorization: Bearer anb_live_<prefix>_<secret>` |
| Application as itself | `Authorization: Bearer <client-credentials access token>` |
| Browser, on the SSO flows | the `__Host-anubis_sso` cookie, set on Anubis's origin |

A tenant key and a **platform operator key are the same shape** — both
`anb_live_…`. Nothing in the string says which you hold; the server tries the
platform key store first and falls back to the tenant one, so which population
you are in is decided by where your key was issued, not by how it looks.

That distinction is absolute on the admin plane. `Guard.Require` refuses any
non-platform principal outright — *"Not a policy lookup that happens to deny —
a different population. The permission strings this plane checks exist only in
the operator role allow-lists; no tenant grant can confer them."* An
application holding a tenant key cannot read another identity's grants at any
scope, and no permission can be granted to change that.

A platform operator naming the tenant they are administering adds
`X-Anubis-Tenant: <slug>`. Sending **no** such header on an admin audit query
is how you ask about the installation itself rather than about a tenant.

## Errors

Two envelopes, one vocabulary. The **body is authoritative over the HTTP
status**: a proxy is free to rewrite a status, and some do.

Plain HTTP:

```jsonc
{ "error": "invalid_pkce", "message": "…", "request_id": "req_01HXY…", "details": {} }
```

Connect:

```jsonc
{
  "code": "unauthenticated",              // coarse transport class
  "message": "Token family revoked. Re-authentication required.",
  "details": [{
    "type": "anubis.v1.ErrorInfo",
    "value": "<base64 protobuf>"          // the STABLE domain code lives here
  }]
}
```

Connect's own `code` field carries only the transport class, so the code you
actually branch on — `refresh_token_reuse_detected` and the rest — is inside
the `ErrorInfo` detail, base64-encoded protobuf. It is three fields and decodes
in about forty lines without a protobuf runtime:

```
string code = 1;  string request_id = 2;  map<string,string> details = 3;
```

The SDK does exactly that, rather than take on the dependency. Reading
`value` is worth the effort: without it, a stolen-token signal is
indistinguishable from a bad password.

### Stable codes

`invalid_credentials` · `invalid_token` · `invalid_pkce` ·
`invalid_redirect_uri` · `invalid_refresh_token` · **`refresh_token_reuse_detected`** ·
`step_up_required` · `mfa_required` · `mfa_invalid` · `session_revoked` ·
`account_locked` · `account_disabled` · `device_challenge_invalid` ·
`registration_closed` · `password_policy` · `no_tenant_selected` ·
`rate_limited` · `permission_denied` · `unauthenticated` · `not_found` ·
`conflict` · `feed_unavailable` · `internal`

`refresh_token_reuse_detected` is the one that must page a human. It means two
parties presented the same refresh token; the family and session are already
revoked. It is not retryable.

## The flows

### Browser sign-in

```
GET /v1/authorize
  ?response_type=code
  &client_id=<application slug>
  &redirect_uri=<exact match against the registered allowlist>
  &state=<random, bound to the browser>
  &code_challenge=<BASE64URL(SHA256(verifier))>
  &code_challenge_method=S256
  &scope=openid
  &tenant=…&realm=…&page=…&nonce=…&prompt=…&acr_values=…&max_age=…
```

`redirect_uri` is compared **exactly**: no wildcards, no prefixes. An open
redirect here is full account takeover.

Then the exchange — **form-encoded**, not JSON:

```
POST /v1/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=…&code_verifier=…&redirect_uri=…&client_id=…
```

```jsonc
// 200, snake_case
{ "access_token": "v4.public.…", "refresh_token": "anb_rt_…",
  "token_type": "Bearer", "expires_in": 600, "session_id": "ses_…" }
```

> **The token endpoint does not currently verify `client_secret`.** The
> discovery document advertises `client_secret_post`, and the handler reads
> `grant_type`, `code`, `code_verifier`, `redirect_uri` and `client_id` — but
> never the secret. PKCE is what binds the exchange today. The SDK sends the
> secret anyway, so they are already correct when the server starts checking
> it; do not rely on it as proof of client identity until then.

### Verifying an access token — offline

```
GET /.well-known/anubis-keys.json
```

```jsonc
{ "issuer": "https://anubis.internal",
  "keys": [{ "kid": "…", "alg": "Ed25519", "public_key": "<base64url, 32 bytes>",
             "not_before": …, "not_after": … }] }
```

Fetch it over a channel you trust: whoever answers this URL decides which keys
a verifier accepts, and therefore who can mint tokens it honours. Plaintext
`http` is refused unless the host is loopback.

`issuer` binds the document to a deployment. A verifier that loads whatever
keys its URL happens to serve cannot notice it was pointed at staging, so it
matches this field against its own configured issuer and refuses a mismatch.

`not_before` / `not_after` bound when a **verifier trusts** the key — not when
the issuer stops signing with it. A token minted a second before `not_after` is
rejected the moment it passes, so publish `not_after` at least one maximum
token lifetime after the key's last signing time or a rotation will reject
tokens that are still live. Either bound at zero is unbounded.

Tokens are PASETO `v4.public`: `v4.public.<b64url(message||signature)>.<b64url(footer)>`,
signature over `PAE(["v4.public.", message, footer, implicit])`, footer
`{"kid":"…"}`. Verify with any Ed25519 implementation, then check `iss` and —
**not optional** — `aud`. Without the audience check, a token minted for one
application is accepted by another.

`PAE` is pre-authentication encoding, and getting it subtly wrong produces a
parser that verifies its own tokens and nothing else — the failure is silent
until it meets a token it did not mint. The specification's golden vectors are
asserted in [`paseto/paseto_test.go`](../paseto/paseto_test.go); check a new
implementation against those rather than against this one, since the vectors
belong to the format and this SDK does not.

`kid` arrives inside an attacker-supplied token, so it may only ever index a
bounded, already-loaded map. Refetch on an unknown kid at most once per
interval; a stream of garbage kids must not become a stream of outbound
requests.

Two clocks govern that cache, and only one of them is the kid budget:

| | Bounds | Consequence of omitting it |
| :--- | :--- | :--- |
| TTL | how stale the document may get | a cache that refetches **only** on an unknown kid never sees a key removed — rotation works, revocation silently does not |
| min-refetch | fetches an unknown kid may provoke | a stream of garbage kids becomes a stream of outbound requests |

Fetches must be single-flight, and must not hold a lock that the cache-hit path
also needs: a slow keys endpoint should cost one request its latency, not stall
every concurrent verification behind it. A failed fetch leaves the previous
document in place — stale keys beat no keys, and the unknown-kid rejection
still stands.

Claims:

```jsonc
{ "iss":…, "sub":"usr_…", "aud":["billing-api"], "exp":…, "iat":…, "nbf":…,
  "jti":…, "sid":"ses_…", "tid":"tnt_…", "roles":["billing.clerk"],
  "scopes":{"org":"…"}, "realm":…, "ial":2, "amr":["pwd","otp"],
  "auth_time":…, "epoch":1, "ver":1 }
```

Offline verification cannot see revocation: a token stays valid until `exp`
even if its session died. That is what short lifetimes are for, and what
`TokenService.Introspect` is for when the window is unacceptable.

### Decisions

```
POST /anubis.v1.AuthzService/Authorize
```

```jsonc
{ "subject": "usr_…", "permission": "billing:invoice:approve",
  "scopes": { "org": "…", "customer": "…" },
  "amr": ["pwd","otp"], "auth_time": 1735689000 }
```

```jsonc
{ "allow": false, "reason": "scope_mismatch", "failingAxis": "customer",
  "message": "no grant at or above customer node …" }

{ "allow": false, "reason": "step_up_required",
  "requiredAmr": ["otp"], "maxAuthAge": "2m",
  "currentAmr": ["pwd"], "authAge": "41m" }
```

Supply every axis the action touches. On a strict axis an **omitted axis is
denied, not ignored**. Self-scoped access passes the record owner under the
reserved key `_owner`; a self-scoped grant with no `_owner` is denied.

`amr` and `auth_time` come from the caller's verified token. Leaving them out
does not fail loudly — it makes every step-up rule a permanent denial.

### Refresh — single use, rotating

```
POST /anubis.v1.AuthService/Refresh    { "refresh_token": "anb_rt_…" }
```

Returns a rotated pair; the presented token is dead. Presenting a consumed one
revokes the family and the session and answers
`refresh_token_reuse_detected`.

**Serialise refreshes.** Two concurrent requests that both refresh will produce
this refusal against your own users. It is not a race to tolerate — it is
indistinguishable, from the server, from a stolen token.

### Back-channel logout

Anubis POSTs to each application's registered `backchannel_logout_uri`:

```
POST <your backchannel_logout_uri>
Content-Type: application/x-www-form-urlencoded

logout_token=<v4.public PASETO>
```

```jsonc
{ "iss":…, "aud": ["<your slug>"], "iat":…, "exp": iat+120, "jti":…,
  "sub": "usr_…", "sid": "ses_…",
  "events": { "http://schemas.openid.net/event/backchannel-logout": {} } }
```

Verify it with the same key ring and audience as an access token — **and then
check the `events` claim**. An access token passes every other check on that
list, because the same issuer minted it for the same audience; without the
event check, anyone holding a user's access token can sign them out at will.

### Forward auth

```
POST /v1/gate/check
X-Original-URI · X-Original-Method · X-Original-Host · X-Anubis-Tenant
+ the SSO cookie or X-Original-Authorization
```

`204` allow, with `X-Anubis-Subject`, `X-Anubis-Session`, `X-Anubis-Scope` ·
`401` needs login, with `Location` · `403` denied.

## Procedures

| Service | Methods used by the SDK |
| :--- | :--- |
| `AuthService` | `Login` `VerifyMfa` `Refresh` `Logout` `LogoutAll` `LogoutSession` `ClientCredentials` `BeginTotpEnrollment` `ConfirmTotpEnrollment` `Register` |
| `AuthzService` | `Authorize` `Explain` `SwitchScope` |
| `TokenService` | `Introspect` `Revoke` |
| `SessionService` | `GetMe` `ListSessions` `RevokeSession` |

Administration — `TenantAdminService`, `IdentityAdminService`,
`ScopeAdminService`, `AuthzAdminService`, `PlatformAdminService`,
`ProvisioningService` — is a separate audience and a separate package.

## Health

`GET /healthz` — process alive. `GET /readyz` — database reachable, snapshot
within its maximum age, active signing key present. An instance whose snapshot
has gone stale fails readiness *before* it starts denying, so it leaves the
load balancer first.

## A note on `docs/api.md` in the server repository

That page documents a REST surface — `POST /v1/auth/login`,
`POST /v1/authorize`, `GET /v1/me`, `POST /v1/auth/token/refresh` — which the
running server does not serve. The routes it registers are the ones listed at
the top of this page; everything else is Connect RPC. `docs/integration.md`
matches the code.

This document is pinned to the code.
