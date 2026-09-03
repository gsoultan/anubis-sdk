<?php

declare(strict_types=1);

namespace Anubis;

use Anubis\Exception\ApiException;
use Anubis\Exception\AuthException;
use Anubis\Exception\EnrolmentRequiredException;
use Anubis\Exception\RateLimitedException;
use Anubis\Exception\RefreshReuseException;
use Anubis\Exception\StateMismatchException;
use Anubis\Exception\StepUpRequiredException;
use Anubis\Exception\UnavailableException;

/**
 * Talks to an Anubis installation: sign-in, refresh, decisions, introspection.
 *
 * This is the cold half of the SDK. Verifying a token on the request path needs
 * a Verifier instead, and needs no Client at all.
 */
final class Client
{
    private const PROC_LOGIN = '/anubis.v1.AuthService/Login';
    private const PROC_VERIFY_MFA = '/anubis.v1.AuthService/VerifyMfa';
    private const PROC_REFRESH = '/anubis.v1.AuthService/Refresh';
    private const PROC_LOGOUT_ALL = '/anubis.v1.AuthService/LogoutAll';
    private const PROC_CLIENT_CREDENTIALS = '/anubis.v1.AuthService/ClientCredentials';
    private const PROC_AUTHORIZE = '/anubis.v1.AuthzService/Authorize';
    private const PROC_EXPLAIN = '/anubis.v1.AuthzService/Explain';
    private const PROC_INTROSPECT = '/anubis.v1.TokenService/Introspect';

    private const PATH_AUTHORIZE = '/v1/authorize';
    private const PATH_TOKEN = '/v1/token';
    private const PATH_LOGOUT = '/v1/logout';

    public const LOGIN_COOKIE = 'anubis_login';
    private const LOGIN_TTL = 600;

    private readonly string $baseUrl;
    private readonly Transport $transport;
    private readonly \Closure $now;

    /**
     * @param array{clientId?:string, clientSecret?:string, apiKey?:string,
     *   tenant?:string, timeout?:int, headers?:array<string,string>,
     *   transport?:Transport, now?:callable} $options
     */
    public function __construct(string $baseUrl, private readonly array $options = [])
    {
        $scheme = parse_url($baseUrl, PHP_URL_SCHEME);
        $host = parse_url($baseUrl, PHP_URL_HOST);
        if ($scheme === null || $host === null) {
            throw new \InvalidArgumentException(
                "anubis: base url \"{$baseUrl}\" must be an absolute origin like https://anubis.internal"
            );
        }
        if ($scheme !== 'https' && $host !== 'localhost' && $host !== '127.0.0.1') {
            throw new \InvalidArgumentException(
                "anubis: base url \"{$baseUrl}\" must be https — browser sign-in needs it, and so does a credential"
            );
        }
        $apiKey = $options['apiKey'] ?? '';
        if ($apiKey !== '' && !str_starts_with($apiKey, 'anb_live_')) {
            throw new \InvalidArgumentException('anubis: an api key looks like "anb_live_<prefix>_<secret>"');
        }
        if ($apiKey !== '' && ($options['clientSecret'] ?? '') !== '') {
            // Two credentials means two identities: the tenant's system, and
            // the application acting as itself. A client holding both picks one
            // by accident, and the audit trail names the wrong caller.
            throw new \InvalidArgumentException(
                'anubis: an api key and a client secret are different callers — use one client for each'
            );
        }
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->transport = $options['transport'] ?? new CurlTransport($options['timeout'] ?? 10);
        $this->now = \Closure::fromCallable($options['now'] ?? static fn (): int => time());
    }

    // ---- sign-in ----------------------------------------------------------

    /**
     * Start an authorization-code sign-in with PKCE.
     *
     * The verifier and state are generated here and stored in the returned
     * cookie, so the callback can check them. Neither is the caller's to manage.
     *
     * @param array{redirectUri:string, scope?:string[], realm?:string,
     *   page?:string, tenant?:string, nonce?:string, prompt?:string,
     *   acrValues?:string[], maxAge?:int} $params
     * @return array{url:string, state:string, cookie:string}
     */
    public function beginLogin(array $params): array
    {
        $clientId = (string) ($this->options['clientId'] ?? '');
        if ($clientId === '') {
            throw new \InvalidArgumentException('anubis: beginLogin needs a clientId (the application slug)');
        }
        if (($params['redirectUri'] ?? '') === '') {
            throw new \InvalidArgumentException(
                'anubis: beginLogin needs a redirectUri, and it must be one registered on the application'
            );
        }
        $state = Paseto::b64urlEncode(random_bytes(32));
        $verifier = Paseto::b64urlEncode(random_bytes(32));
        $challenge = Paseto::b64urlEncode(hash('sha256', $verifier, true));

        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $params['redirectUri'],
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'scope' => implode(' ', $params['scope'] ?? ['openid']),
        ];
        $optional = [
            'tenant' => $params['tenant'] ?? ($this->options['tenant'] ?? ''),
            'realm' => $params['realm'] ?? '',
            'page' => $params['page'] ?? '',
            'nonce' => $params['nonce'] ?? '',
            'prompt' => $params['prompt'] ?? '',
            'acr_values' => implode(' ', $params['acrValues'] ?? []),
            'max_age' => isset($params['maxAge']) ? (string) $params['maxAge'] : '',
        ];
        foreach ($optional as $k => $v) {
            if ($v !== '') {
                $query[$k] = $v;
            }
        }
        $pending = json_encode([
            's' => $state,
            'v' => $verifier,
            'r' => $params['redirectUri'],
            'c' => ($this->now)(),
        ], JSON_THROW_ON_ERROR);

        return [
            'url' => $this->baseUrl . self::PATH_AUTHORIZE . '?' . http_build_query($query),
            'state' => $state,
            // Lax rather than Strict: the browser returns from Anubis's origin
            // by top-level navigation, and Strict would withhold the cookie on
            // exactly the request that needs it.
            'cookie' => self::LOGIN_COOKIE . '=' . Paseto::b64urlEncode($pending)
                . '; Path=/; Max-Age=' . self::LOGIN_TTL . '; HttpOnly; Secure; SameSite=Lax',
        ];
    }

    /**
     * Handle the callback: check the state, exchange the code, return tokens.
     *
     * The state comparison happens before anything is exchanged, and there is
     * no option that turns it off. A caller cannot forget a check that was
     * never theirs to make.
     *
     * @param array<string, string> $query  Typically $_GET.
     * @param array<string, string> $cookies Typically $_COOKIE.
     */
    public function completeLogin(array $query, array $cookies): Tokens
    {
        if (($query['error'] ?? '') !== '') {
            throw new ApiException($query['error'], $query['error_description'] ?? '', '', 400);
        }
        $raw = $cookies[self::LOGIN_COOKIE] ?? '';
        if ($raw === '') {
            throw new StateMismatchException('no login in progress for this browser');
        }
        $pending = json_decode(Paseto::b64urlDecode($raw), true);
        if (!is_array($pending)) {
            throw new StateMismatchException('login cookie is unreadable');
        }
        if (($this->now)() - (int) ($pending['c'] ?? 0) > self::LOGIN_TTL) {
            throw new StateMismatchException('the sign-in took longer than 10 minutes');
        }
        // Constant time: the comparison is against an attacker-supplied value,
        // and a state that leaks byte by byte is a state that can be guessed.
        if (!hash_equals((string) ($pending['s'] ?? ''), (string) ($query['state'] ?? ''))) {
            throw new StateMismatchException('callback state is not the one this browser was sent with');
        }
        $code = (string) ($query['code'] ?? '');
        if ($code === '') {
            throw new StateMismatchException('callback carried no code');
        }

        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'code_verifier' => (string) $pending['v'],
            'redirect_uri' => (string) $pending['r'],
            'client_id' => (string) ($this->options['clientId'] ?? ''),
        ];
        // Sent because the discovery document advertises client_secret_post.
        // The token endpoint does not currently verify it — PKCE is what binds
        // the exchange — so this is forward compatibility, not the proof.
        if (($this->options['clientSecret'] ?? '') !== '') {
            $form['client_secret'] = (string) $this->options['clientSecret'];
        }
        $body = $this->request(
            self::PATH_TOKEN,
            ['content-type' => 'application/x-www-form-urlencoded'],
            http_build_query($form),
        );
        return Tokens::fromHttp($body, ($this->now)());
    }

    /** The Set-Cookie value that clears the login cookie after a callback. */
    public function clearLoginCookie(): string
    {
        return self::LOGIN_COOKIE . '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax';
    }

    /**
     * Sign in directly. First-party native and CLI applications only — a
     * password typed anywhere but Anubis's origin is one you now own.
     *
     * @return array{tokens?:Tokens, mfa?:array{token:string, methods:string[], expiresIn:int},
     *   enrolmentDue?:array{factors:string[], deadline:int}}
     */
    public function login(string $username, string $password, array $extra = []): array
    {
        $out = $this->rpc(self::PROC_LOGIN, [
            'tenant' => $extra['tenant'] ?? ($this->options['tenant'] ?? ''),
            'realm' => $extra['realm'] ?? '',
            'username' => $username,
            'password' => $password,
            'client_id' => $extra['clientId'] ?? ($this->options['clientId'] ?? ''),
            'device_fp' => $extra['deviceFp'] ?? '',
        ], null);

        if (isset($out['enrolmentRequired'])) {
            $e = $out['enrolmentRequired'];
            throw new EnrolmentRequiredException(
                new AuthMethods((array) ($e['factors'] ?? [])),
                // protojson renders int64 as a JSON string, so this is quoted.
                (int) ($e['deadline'] ?? 0),
                (string) ($e['grantToken'] ?? ''),
            );
        }
        $result = [];
        if (isset($out['tokens'])) {
            $result['tokens'] = Tokens::fromConnect($out['tokens'], ($this->now)());
        }
        if (isset($out['mfa'])) {
            $result['mfa'] = [
                'token' => (string) ($out['mfa']['mfaToken'] ?? ''),
                'methods' => new AuthMethods((array) ($out['mfa']['methods'] ?? [])),
                'expiresIn' => (int) ($out['mfa']['expiresIn'] ?? 0),
            ];
        }
        if (isset($out['enrolmentDue'])) {
            // Sign-in worked, and this is the warning. A client that ignores it
            // costs its user access on the deadline with no notice.
            $result['enrolmentDue'] = [
                'factors' => new AuthMethods((array) ($out['enrolmentDue']['factors'] ?? [])),
                'deadline' => (int) ($out['enrolmentDue']['deadline'] ?? 0),
            ];
        }
        return $result;
    }

    public function verifyMfa(string $mfaToken, string $code): Tokens
    {
        $out = $this->rpc(self::PROC_VERIFY_MFA, ['mfa_token' => $mfaToken, 'code' => $code], null);
        if (!isset($out['tokens'])) {
            throw new ApiException('', 'anubis: mfa verification returned no tokens');
        }
        return Tokens::fromConnect($out['tokens'], ($this->now)());
    }

    // ---- decisions --------------------------------------------------------

    /**
     * Ask whether the verified caller may do something; throw if not.
     *
     * The subject, amr and auth_time are read from the principal the verifier
     * produced. A caller assembling this by hand leaves amr and auth_time out,
     * and that turns every step-up rule into a silent permanent denial that
     * looks like a permissions bug.
     *
     * @param Scopes|array<string, string>|null $scopes
     */
    public function require(Principal $principal, Permission|string $permission, Scopes|array|null $scopes = null): void
    {
        $this->authorize($principal, $permission, $scopes)->orThrow();
    }

    /**
     * The same question, answered as data.
     *
     * @param Scopes|array<string, string>|null $scopes
     */
    public function authorize(Principal $principal, Permission|string $permission, Scopes|array|null $scopes = null): Decision
    {
        $p = Permission::of($permission);
        if (!$p->isValid()) {
            // Caught here rather than answered with a denial, because a denial
            // for a permission that cannot exist is indistinguishable from one
            // for a permission the caller does not hold.
            throw new \InvalidArgumentException(
                "anubis: \"{$p}\" is not a permission key — expected app:resource:action"
            );
        }
        $identity = $principal->identity();
        $out = $this->rpc(self::PROC_AUTHORIZE, [
            'subject' => $identity->subject,
            'permission' => $p->key,
            'scopes' => (object) Scopes::of($scopes)->toWire(),
            'amr' => $identity->methods->toStrings(),
            'auth_time' => $principal->claims->authTime,
        ], $principal->token);

        return Decision::fromArray($out, $p);
    }

    /**
     * The full evaluation tree. Reach for it the moment a denial is not
     * obvious: past two axes, "why" stops being answerable by reading grants.
     *
     * @param Scopes|array<string, string>|null $scopes
     * @return array<string, mixed>
     */
    public function explain(Principal $principal, Permission|string $permission, Scopes|array|null $scopes = null): array
    {
        return $this->rpc(self::PROC_EXPLAIN, [
            'subject' => $principal->subject(),
            'permission' => Permission::of($permission)->key,
            'scopes' => (object) Scopes::of($scopes)->toWire(),
        ], $principal->token);
    }

    /**
     * Turn a step-up refusal into the sign-in redirect that satisfies it. It is
     * a fresh authorization request, because that is what re-authentication is.
     *
     * @param array{redirectUri:string} $params
     * @return array{url:string, state:string, cookie:string}
     */
    public function beginStepUp(StepUpRequiredException $e, array $params): array
    {
        $params['prompt'] = 'login';
        $params['acrValues'] ??= $e->requiredAmr->toStrings();
        $params['maxAge'] ??= $e->maxAuthAgeSeconds();
        if ($params['maxAge'] === null) {
            unset($params['maxAge']);
        }
        return $this->beginLogin($params);
    }

    // ---- sessions ---------------------------------------------------------

    /**
     * Rotate a pair once.
     *
     * Refresh tokens are single-use. In PHP the danger is not threads but
     * PROCESSES: two concurrent requests in two workers will both refresh, and
     * the loser presents a consumed token, which Anubis correctly reads as
     * theft. An in-process lock cannot fix that. Serialise refreshes on
     * whatever your sessions already share — a row lock, a Redis lock — around
     * this call.
     */
    public function refresh(string $refreshToken): Tokens
    {
        if ($refreshToken === '') {
            throw new \InvalidArgumentException('anubis: refresh needs a refresh token');
        }
        $out = $this->rpc(self::PROC_REFRESH, ['refresh_token' => $refreshToken], null);
        if (!isset($out['tokens'])) {
            throw new ApiException('', 'anubis: refresh returned no tokens');
        }
        return Tokens::fromConnect($out['tokens'], ($this->now)());
    }

    public function clientCredentials(string $audience = ''): Tokens
    {
        if (($this->options['clientId'] ?? '') === '' || ($this->options['clientSecret'] ?? '') === '') {
            throw new \InvalidArgumentException('anubis: client credentials need a clientId and clientSecret');
        }
        $out = $this->rpc(self::PROC_CLIENT_CREDENTIALS, [
            'tenant' => $this->options['tenant'] ?? '',
            'client_id' => $this->options['clientId'],
            'client_secret' => $this->options['clientSecret'],
            'audience' => $audience,
        ], null);
        return new Tokens(
            accessToken: (string) ($out['accessToken'] ?? ''),
            tokenType: (string) ($out['tokenType'] ?? 'Bearer'),
            expiresIn: (int) ($out['expiresIn'] ?? 0),
            issuedAt: ($this->now)(),
        );
    }

    /** @return array<string, mixed> */
    public function introspect(string $token, ?Principal $principal = null): array
    {
        return $this->rpc(self::PROC_INTROSPECT, ['token' => $token], $principal?->token);
    }

    public function logoutAll(Principal $principal): void
    {
        $this->rpc(self::PROC_LOGOUT_ALL, new \stdClass(), $principal->token);
    }

    /**
     * Where to send the browser to sign out.
     *
     * Anubis answers the GET by rendering its sign-out page and ASKING. That
     * confirmation is not politeness: a bare GET that ends sessions is
     * reachable from any page on the internet with an <img> tag.
     *
     * @param array{tenant?:string, postLogoutRedirectUri?:string, page?:string} $params
     */
    public function logoutUrl(array $params = []): string
    {
        $query = array_filter([
            'tenant' => $params['tenant'] ?? ($this->options['tenant'] ?? ''),
            'post_logout_redirect_uri' => $params['postLogoutRedirectUri'] ?? '',
            'page' => $params['page'] ?? '',
        ], static fn (string $v): bool => $v !== '');

        return $this->baseUrl . self::PATH_LOGOUT . ($query === [] ? '' : '?' . http_build_query($query));
    }

    /**
     * Verify a back-channel logout token and return the event.
     *
     * The event-claim check is what stops somebody replaying a captured ACCESS
     * token here to sign a user out at will: an access token passes every other
     * check, because the same issuer minted it for the same audience.
     *
     * @return array{sessionId:string, subject:string, tenant:string}
     */
    public static function verifyLogoutToken(Verifier $verifier, string $token): array
    {
        $claims = $verifier->verify($token);
        // Safe to read the raw message now: the signature covering it is checked.
        $parsed = Paseto::parse($token);
        $body = json_decode($parsed['message'], true);
        $events = is_array($body) ? ($body['events'] ?? []) : [];
        if (!is_array($events) || !isset($events['http://schemas.openid.net/event/backchannel-logout'])) {
            throw new ApiException('', 'anubis: not a back-channel logout token (no logout event claim)');
        }
        return [
            'sessionId' => (string) ($body['sid'] ?? $claims->session),
            'subject' => $claims->subject,
            'tenant' => $claims->tenant,
        ];
    }

    // ---- transport --------------------------------------------------------

    /**
     * Request fields go out with their proto names (snake_case). protojson
     * accepts those as well as lowerCamelCase, and they are what the API
     * documentation shows.
     *
     * @return array<string, mixed>
     */
    private function rpc(string $procedure, mixed $body, ?string $bearer): array
    {
        $headers = ['content-type' => 'application/json'];
        if ($bearer !== null || ($this->options['apiKey'] ?? '') !== '') {
            $credential = ($this->options['apiKey'] ?? '') ?: $bearer;
            $headers['authorization'] = 'Bearer ' . $credential;
        }
        return $this->request($procedure, $headers, json_encode($body, JSON_THROW_ON_ERROR));
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, mixed>
     */
    private function request(string $path, array $headers, string $body): array
    {
        foreach ((array) ($this->options['headers'] ?? []) as $k => $v) {
            $headers[strtolower((string) $k)] = (string) $v;
        }
        if (($this->options['tenant'] ?? '') !== '') {
            $headers['x-anubis-tenant'] = (string) $this->options['tenant'];
        }
        $response = $this->transport->send('POST', $this->baseUrl . $path, $headers, $body);

        if ($response['status'] !== 200) {
            throw self::classify(
                self::parseWireError($response['body'], $response['status']),
                $response['headers'],
            );
        }
        if (trim($response['body']) === '') {
            return [];
        }
        $decoded = json_decode($response['body'], true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Turn a refusal into something a caller can act on.
     *
     * Reuse detection is checked first and deliberately not folded in with the
     * other authentication failures: every other one means "try again with a
     * better credential", and this one means "stop, you have been robbed".
     *
     * @param array<string, string> $headers
     */
    private static function classify(ApiException $e, array $headers): \Throwable
    {
        $code = $e->errorCode;
        if ($code === '') {
            $code = match ($e->status) {
                429 => 'rate_limited',
                401 => 'unauthenticated',
                403 => 'permission_denied',
                503 => 'unavailable',
                default => '',
            };
        }
        return match (true) {
            $code === 'refresh_token_reuse_detected' => new RefreshReuseException($e),
            $code === 'rate_limited' => new RateLimitedException(
                (int) ($headers['retry-after'] ?? 0),
                $e,
            ),
            $code === 'unavailable' => new UnavailableException($e->getMessage()),
            in_array($code, [
                'unauthenticated', 'invalid_token', 'invalid_credentials',
                'permission_denied', 'session_revoked', 'invalid_refresh_token',
            ], true) => new AuthException($code, $e->getMessage(), $e->requestId, $e->status, $e->details),
            default => $e,
        };
    }

    /**
     * Covers both shapes Anubis answers with: the Connect error object and the
     * plain-HTTP envelope. One vocabulary, two transports — but not one field
     * name for the code.
     */
    private static function parseWireError(string $raw, int $status): ApiException
    {
        $w = json_decode($raw, true);
        if (!is_array($w)) {
            return new ApiException('', substr(trim($raw), 0, 512), '', $status);
        }
        $code = (string) ($w['error'] ?? $w['code'] ?? '');
        $requestId = (string) ($w['request_id'] ?? '');
        $details = [];

        $rawDetails = $w['details'] ?? null;
        if (is_array($rawDetails) && array_is_list($rawDetails)) {
            // Connect puts the stable domain code in a base64 protobuf
            // anubis.v1.ErrorInfo, because its own `code` field carries only
            // the coarse transport class.
            foreach ($rawDetails as $d) {
                if (!is_array($d) || !str_ends_with((string) ($d['type'] ?? ''), 'ErrorInfo')) {
                    continue;
                }
                $info = self::decodeErrorInfo((string) ($d['value'] ?? ''));
                $code = $info['code'] !== '' ? $info['code'] : $code;
                $requestId = $info['requestId'] !== '' ? $info['requestId'] : $requestId;
                $details = $info['details'];
            }
        } elseif (is_array($rawDetails)) {
            $details = array_map('strval', $rawDetails);
        }
        return new ApiException($code, (string) ($w['message'] ?? ''), $requestId, $status, $details);
    }

    /**
     * Read anubis.v1.ErrorInfo straight off the protobuf wire.
     *
     * Depending on a protobuf runtime to read three fields would cost every
     * consumer a dependency tree, and the point of this package is that it
     * costs them ext-curl and ext-json.
     *
     *     string code = 1; string request_id = 2; map<string,string> details = 3;
     *
     * @return array{code:string, requestId:string, details:array<string,string>}
     */
    private static function decodeErrorInfo(string $b64): array
    {
        $out = ['code' => '', 'requestId' => '', 'details' => []];
        $raw = base64_decode($b64, true);
        if ($raw === false) {
            return $out;
        }
        $i = 0;
        $len = strlen($raw);
        while ($i < $len) {
            [$tag, $n] = self::varint($raw, $i);
            if ($n === 0 || ($tag & 7) !== 2) {
                return $out;
            }
            $i += $n;
            [$size, $n] = self::varint($raw, $i);
            if ($n === 0) {
                return $out;
            }
            $i += $n;
            $payload = substr($raw, $i, $size);
            if (strlen($payload) < $size) {
                return $out;
            }
            $i += $size;

            $field = $tag >> 3;
            if ($field === 1) {
                $out['code'] = $payload;
            } elseif ($field === 2) {
                $out['requestId'] = $payload;
            } elseif ($field === 3) {
                // A map entry is key = field 1, value = field 2: the same shapes.
                $entry = self::decodeErrorInfo(base64_encode($payload));
                if ($entry['code'] !== '') {
                    $out['details'][$entry['code']] = $entry['requestId'];
                }
            }
        }
        return $out;
    }

    /** @return array{0:int, 1:int} value and byte count, or [0, 0] on truncation. */
    private static function varint(string $b, int $at): array
    {
        $value = 0;
        $shift = 0;
        $len = strlen($b);
        for ($i = $at; $i < $len && $i - $at < 10; $i++) {
            $byte = ord($b[$i]);
            $value |= ($byte & 0x7F) << $shift;
            if (($byte & 0x80) === 0) {
                return [$value, $i - $at + 1];
            }
            $shift += 7;
        }
        return [0, 0];
    }

}
