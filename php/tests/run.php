<?php

/**
 * A dependency-free test run: `php tests/run.php`.
 *
 * Deliberately not PHPUnit. This package's whole claim is that it needs three
 * bundled extensions and nothing else, and a test suite that cannot run until
 * you have installed a dependency tree is a poor way to demonstrate that.
 */

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    if (!str_starts_with($class, 'Anubis\\')) {
        return;
    }
    $path = __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, strlen('Anubis\\'))) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

use Anubis\AuthMethods;
use Anubis\Claims;
use Anubis\Client;
use Anubis\Identity;
use Anubis\Permission;
use Anubis\Permissions;
use Anubis\Role;
use Anubis\Roles;
use Anubis\Scopes;
use Anubis\Exception\DeniedException;
use Anubis\Exception\RefreshReuseException;
use Anubis\Exception\StateMismatchException;
use Anubis\Exception\StepUpRequiredException;
use Anubis\Exception\VerificationException;
use Anubis\Paseto;
use Anubis\Principal;
use Anubis\Transport;
use Anubis\Verifier;

$passed = 0;
$failed = 0;

function check(string $name, callable $fn): void
{
    global $passed, $failed;
    try {
        $fn();
        $passed++;
        echo "  ok   {$name}\n";
    } catch (\Throwable $e) {
        $failed++;
        echo "  FAIL {$name}\n       {$e->getMessage()}\n";
    }
}

function assertTrue(bool $cond, string $message = 'assertion failed'): void
{
    if (!$cond) {
        throw new \RuntimeException($message);
    }
}

function assertSame(mixed $want, mixed $got, string $what = 'value'): void
{
    if ($want !== $got) {
        throw new \RuntimeException(sprintf(
            '%s: want %s, got %s',
            $what,
            var_export($want, true),
            var_export($got, true),
        ));
    }
}

function assertThrows(string $class, callable $fn): \Throwable
{
    try {
        $fn();
    } catch (\Throwable $e) {
        if (!($e instanceof $class)) {
            throw new \RuntimeException(sprintf('want %s, got %s: %s', $class, $e::class, $e->getMessage()));
        }
        return $e;
    }
    throw new \RuntimeException("want {$class}, nothing was thrown");
}

// ---- fixtures -------------------------------------------------------------

$keypair = sodium_crypto_sign_keypair();
$secretKey = sodium_crypto_sign_secretkey($keypair);
$publicKey = sodium_crypto_sign_publickey($keypair);
const ISSUER = 'https://anubis.test';
const APP = 'billing-api';

$mint = static function (array $claims, ?string $key = null) use ($secretKey): string {
    $body = json_encode(array_merge([
        'iss' => ISSUER,
        'aud' => [APP],
        'exp' => time() + 600,
        'iat' => time(),
    ], $claims), JSON_THROW_ON_ERROR);
    $footer = json_encode(['kid' => 'k1'], JSON_THROW_ON_ERROR);
    $m2 = Paseto::pae([Paseto::HEADER, $body, $footer, '']);
    $sig = sodium_crypto_sign_detached($m2, $key ?? $secretKey);

    return Paseto::HEADER . Paseto::b64urlEncode($body . $sig) . '.' . Paseto::b64urlEncode($footer);
};

$keysDocument = [
    'issuer' => ISSUER,
    'keys' => [['kid' => 'k1', 'alg' => 'Ed25519', 'public_key' => Paseto::b64urlEncode($publicKey)]],
];

$newVerifier = static fn (): Verifier => new Verifier(
    issuer: ISSUER,
    audience: APP,
    staticKeys: $GLOBALS['keysDocument'],
);
$GLOBALS['keysDocument'] = $keysDocument;

/** A fake Anubis, wired in where curl would be. */
final class FakeTransport implements Transport
{
    /** @var array<string,int> */
    public array $calls = [];
    public array $decision = ['allow' => true];
    public string $liveRefresh = 'anb_rt_1';
    /** @var array<string,bool> */
    public array $consumed = [];
    /** @var array<string,array{challenge:string,redirectUri:string,clientId:string}> */
    public array $codes = [];

    public function __construct(private readonly \Closure $mint)
    {
    }

    public function send(string $method, string $url, array $headers, string $body): array
    {
        $path = (string) parse_url($url, PHP_URL_PATH);
        $this->calls[$path] = ($this->calls[$path] ?? 0) + 1;
        $json = static fn (array $v, int $status = 200): array => [
            'status' => $status,
            'headers' => [],
            'body' => json_encode($v, JSON_THROW_ON_ERROR),
        ];

        return match ($path) {
            '/anubis.v1.AuthzService/Authorize' => $json($this->decision),
            '/anubis.v1.AuthService/Refresh' => $this->refresh($body, $json),
            '/anubis.v1.TokenService/Introspect' => $json([
                'active' => true,
                'sub' => 'usr_1',
                // protojson renders int64 as a JSON STRING.
                'exp' => (string) (time() + 60),
            ]),
            '/v1/token' => $this->token($body, $json),
            default => $json(['error' => 'not_found', 'message' => $path], 404),
        };
    }

    private function refresh(string $body, callable $json): array
    {
        $presented = (string) (json_decode($body, true)['refresh_token'] ?? '');
        if ($presented !== $this->liveRefresh || isset($this->consumed[$presented])) {
            // Connect puts the domain code in a base64 protobuf ErrorInfo, so
            // the client's hand-rolled decoder is genuinely exercised.
            return [
                'status' => 401,
                'headers' => [],
                'body' => json_encode([
                    'code' => 'unauthenticated',
                    'message' => 'Token family revoked.',
                    'details' => [[
                        'type' => 'anubis.v1.ErrorInfo',
                        'value' => base64_encode(
                            self::field(1, 'refresh_token_reuse_detected') . self::field(2, 'req_test')
                        ),
                    ]],
                ], JSON_THROW_ON_ERROR),
            ];
        }
        $this->consumed[$presented] = true;
        $this->liveRefresh = 'anb_rt_' . bin2hex(random_bytes(4));

        return $json(['tokens' => [
            'accessToken' => ($this->mint)(['sub' => 'usr_1']),
            'refreshToken' => $this->liveRefresh,
            'tokenType' => 'Bearer',
            'expiresIn' => 600,
            'sessionId' => 'ses_1',
        ]]);
    }

    private function token(string $body, callable $json): array
    {
        parse_str($body, $form);
        $entry = $this->codes[$form['code'] ?? ''] ?? null;
        unset($this->codes[$form['code'] ?? '']);
        if ($entry === null) {
            return $json(['error' => 'invalid_pkce', 'message' => 'unknown code'], 400);
        }
        $challenge = Paseto::b64urlEncode(hash('sha256', (string) ($form['code_verifier'] ?? ''), true));
        if (!hash_equals($entry['challenge'], $challenge)) {
            return $json(['error' => 'invalid_pkce', 'message' => 'verifier mismatch'], 400);
        }
        // The browser endpoint answers snake_case, unlike every procedure above.
        return $json([
            'access_token' => ($this->mint)(['sub' => 'usr_1']),
            'refresh_token' => $this->liveRefresh,
            'token_type' => 'Bearer',
            'expires_in' => 600,
            'session_id' => 'ses_1',
        ]);
    }

    private static function field(int $n, string $v): string
    {
        return chr(($n << 3) | 2) . chr(strlen($v)) . $v;
    }
}

$newClient = static fn (FakeTransport $t, array $extra = []): Client => new Client(
    'https://anubis.test',
    array_merge(['clientId' => APP, 'apiKey' => 'anb_live_ab12cd34_s3cr3t', 'transport' => $t], $extra),
);

$principal = new Principal(
    Claims::fromArray(['iss' => ISSUER, 'sub' => 'usr_1', 'aud' => [APP], 'amr' => ['pwd'], 'auth_time' => 1]),
    'v4.public.test',
);

// ---- paseto ---------------------------------------------------------------

echo "paseto\n";
check('PAE matches the specification vectors', static function (): void {
    // The same golden table the Go and TypeScript implementations assert.
    // Drift here is a cross-implementation token break.
    assertSame('0000000000000000', bin2hex(Paseto::pae([])), 'empty list');
    assertSame('01000000000000000000000000000000', bin2hex(Paseto::pae([''])), 'one empty string');
    assertSame('0100000000000000040000000000000074657374', bin2hex(Paseto::pae(['test'])), 'test');
    assertSame(
        '02000000000000000400000000000000746573740000000000000000',
        bin2hex(Paseto::pae(['test', ''])),
        'two pieces',
    );
});

// ---- verifier -------------------------------------------------------------

echo "verifier\n";
check('verifies a well-formed token', static function () use ($mint, $newVerifier): void {
    $claims = $newVerifier()->verify($mint(['sub' => 'usr_1', 'roles' => ['billing.clerk']]));
    assertSame('usr_1', $claims->subject, 'subject');
    assertTrue($claims->hasRole('billing.clerk'), 'role missing');
});

check('refuses to be built without an audience', static function () use ($keysDocument): void {
    assertThrows(VerificationException::class, static fn () => new Verifier(
        issuer: ISSUER,
        audience: '',
        staticKeys: $keysDocument,
    ));
});

check('rejects a token minted for another application', static function () use ($mint, $newVerifier): void {
    assertThrows(
        VerificationException::class,
        static fn () => $newVerifier()->verify($mint(['sub' => 'u', 'aud' => ['hr-api']])),
    );
});

check('rejects expired and not-yet-valid tokens', static function () use ($mint, $newVerifier): void {
    assertThrows(VerificationException::class, static fn () => $newVerifier()->verify($mint(['exp' => time() - 3600])));
    assertThrows(VerificationException::class, static fn () => $newVerifier()->verify($mint(['nbf' => time() + 3600])));
});

check('rejects a token signed by the wrong key', static function () use ($mint, $newVerifier): void {
    $attacker = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
    assertThrows(
        VerificationException::class,
        static fn () => $newVerifier()->verify($mint(['sub' => 'u'], $attacker)),
    );
});

check('rejects malformed tokens', static function () use ($newVerifier): void {
    foreach (['', 'v4.public', 'v2.public.abc', 'v4.public.', 'v4.public.!!!', 'v4.public.AAAA'] as $bad) {
        assertThrows(VerificationException::class, static fn () => $newVerifier()->verify($bad));
    }
});

// ---- sign-in --------------------------------------------------------------

echo "login\n";
check('round trips through PKCE', static function () use ($mint, $newClient): void {
    $t = new FakeTransport(\Closure::fromCallable($mint));
    $c = $newClient($t);
    $begin = $c->beginLogin(['redirectUri' => 'https://app.example.com/callback']);

    parse_str((string) parse_url($begin['url'], PHP_URL_QUERY), $q);
    assertSame('S256', $q['code_challenge_method'], 'challenge method');
    assertTrue(!str_contains($begin['url'], 'code_verifier'), 'the verifier reached the URL bar');
    assertTrue(str_contains($begin['cookie'], 'HttpOnly'), 'login cookie is not HttpOnly');

    // Stand in for Anubis issuing a code against the challenge.
    $t->codes['code_1'] = [
        'challenge' => $q['code_challenge'],
        'redirectUri' => $q['redirect_uri'],
        'clientId' => $q['client_id'],
    ];
    $cookieValue = explode('=', explode(';', $begin['cookie'])[0], 2)[1];
    $tokens = $c->completeLogin(
        ['code' => 'code_1', 'state' => $begin['state']],
        [Client::LOGIN_COOKIE => $cookieValue],
    );
    assertTrue(str_starts_with($tokens->accessToken, 'v4.public.'), 'no access token');
    assertSame(600, $tokens->expiresIn, 'snake_case body did not decode');
});

check('refuses to exchange a code when the state does not match', static function () use ($mint, $newClient): void {
    $t = new FakeTransport(\Closure::fromCallable($mint));
    $c = $newClient($t);
    $begin = $c->beginLogin(['redirectUri' => 'https://app.example.com/callback']);
    parse_str((string) parse_url($begin['url'], PHP_URL_QUERY), $q);
    $t->codes['code_1'] = [
        'challenge' => $q['code_challenge'],
        'redirectUri' => $q['redirect_uri'],
        'clientId' => $q['client_id'],
    ];
    $cookieValue = explode('=', explode(';', $begin['cookie'])[0], 2)[1];

    assertThrows(StateMismatchException::class, static fn () => $c->completeLogin(
        ['code' => 'code_1', 'state' => 'attacker-chosen'],
        [Client::LOGIN_COOKIE => $cookieValue],
    ));
    assertSame(null, $t->calls['/v1/token'] ?? null, 'the code was exchanged despite a bad state');
});

check('refuses a callback with no login cookie', static function () use ($mint, $newClient): void {
    $c = $newClient(new FakeTransport(\Closure::fromCallable($mint)));
    assertThrows(
        StateMismatchException::class,
        static fn () => $c->completeLogin(['code' => 'a', 'state' => 'b'], []),
    );
});

// ---- decisions ------------------------------------------------------------

echo "authorize\n";
check('allows, and denies naming the failing axis', static function () use ($mint, $newClient, $principal): void {
    $t = new FakeTransport(\Closure::fromCallable($mint));
    $c = $newClient($t);
    $c->require($principal, 'billing:invoice:approve', ['org' => 'o1']);

    $t->decision = [
        'allow' => false,
        'reason' => 'scope_mismatch',
        'failingAxis' => 'customer',
        'message' => 'no grant',
    ];
    $e = assertThrows(
        DeniedException::class,
        static fn () => $c->require($principal, 'billing:invoice:approve'),
    );
    assertSame('customer', $e->failingAxis, 'failing axis');
});

check('surfaces step-up and builds the re-auth redirect', static function () use ($mint, $newClient, $principal): void {
    $t = new FakeTransport(\Closure::fromCallable($mint));
    $c = $newClient($t);
    $t->decision = [
        'allow' => false,
        'reason' => 'step_up_required',
        'requiredAmr' => ['otp'],
        'currentAmr' => ['pwd'],
        'maxAuthAge' => '2m',
    ];
    $e = assertThrows(
        StepUpRequiredException::class,
        static fn () => $c->require($principal, 'billing:invoice:approve'),
    );
    assertTrue($e->requiredAmr->has(AuthMethods::OTP), 'required amr');
    assertSame(120, $e->maxAuthAgeSeconds(), 'max auth age seconds');

    $redirect = $c->beginStepUp($e, ['redirectUri' => 'https://app.example.com/callback']);
    parse_str((string) parse_url($redirect['url'], PHP_URL_QUERY), $q);
    assertSame('login', $q['prompt'], 'prompt');
    assertSame('otp', $q['acr_values'], 'acr_values');
    assertSame('120', $q['max_age'], 'max_age');
});

// ---- rotation -------------------------------------------------------------

echo "rotation\n";
check('reuse is its own error, not an auth failure', static function () use ($mint, $newClient): void {
    $t = new FakeTransport(\Closure::fromCallable($mint));
    $c = $newClient($t);
    $c->refresh('anb_rt_1');
    $e = assertThrows(RefreshReuseException::class, static fn () => $c->refresh('anb_rt_1'));
    // The stable code survived the base64 protobuf error detail.
    assertTrue(str_contains($e->getMessage(), 'theft'), 'the message lost its meaning');
});

check('introspection decodes int64 fields sent as strings', static function () use ($mint, $newClient): void {
    $out = $newClient(new FakeTransport(\Closure::fromCallable($mint)))->introspect('v4.public.x');
    assertTrue($out['active'] === true, 'not active');
    assertTrue((int) $out['exp'] > 0, 'exp did not decode');
});

// ---- construction ---------------------------------------------------------

echo "construction\n";
check('refuses plain http, a bad api key, and two identities', static function (): void {
    assertThrows(\InvalidArgumentException::class, static fn () => new Client('http://anubis.test'));
    assertThrows(\InvalidArgumentException::class, static fn () => new Client('https://a.test', ['apiKey' => 'nope']));
    assertThrows(\InvalidArgumentException::class, static fn () => new Client('https://a.test', [
        'apiKey' => 'anb_live_ab12cd34_s3cr3t',
        'clientSecret' => 's',
    ]));
});

// ---- the vocabulary -------------------------------------------------------

echo "value types\n";
check('Permission knows its parts and both spellings', static function (): void {
    $p = Permission::of('billing:invoice:approve');
    assertSame('billing', $p->app(), 'app');
    assertSame('invoice', $p->resource(), 'resource');
    assertSame('approve', $p->action(), 'action');
    // A manifest declares permissions WITHOUT the application prefix;
    // everything else uses the full key. Both spellings, derivable.
    assertSame('invoice:approve', $p->manifest(), 'manifest form');
    assertTrue(Permission::from('billing', 'invoice', 'approve')->equals($p), 'round trip');
});

check('a malformed permission reports nothing rather than a plausible part', static function (): void {
    foreach (['', 'approve', 'invoice:approve', 'a:b:c:d', 'a::c'] as $bad) {
        $p = Permission::of($bad);
        assertTrue(!$p->isValid(), "{$bad} was accepted");
        assertSame('', $p->app(), "{$bad} returned an app");
    }
});

check('authorize refuses a malformed permission before spending a decision', static function () use ($mint, $newClient, $principal): void {
    $t = new FakeTransport(\Closure::fromCallable($mint));
    $c = $newClient($t);
    assertThrows(
        \InvalidArgumentException::class,
        static fn () => $c->authorize($principal, 'invoice:approve'),
    );
    assertSame(null, $t->calls['/anubis.v1.AuthzService/Authorize'] ?? null, 'a decision was spent');
});

check('Role separates the application prefix from the manifest name', static function (): void {
    $r = Role::of('billing.clerk');
    assertSame('billing', $r->app(), 'app');
    assertSame('clerk', $r->name(), 'name');
    assertTrue(Role::from('billing', 'clerk')->equals($r), 'round trip');
    // An unprefixed role reports no application rather than pretending.
    assertSame('', Role::of('clerk')->app(), 'bare role app');
});

check('Roles compares the full prefixed name', static function (): void {
    $rs = new Roles(['billing.clerk', 'billing.approver', 'hr.viewer']);
    assertTrue($rs->has('billing.clerk'), 'has prefixed');
    assertTrue(!$rs->has('clerk'), 'must not match the unprefixed manifest name');
    assertTrue($rs->hasAny('nope.none', 'hr.viewer'), 'hasAny');
    assertSame(2, count($rs->ofApp('billing')), 'ofApp');
});

check('Scopes are immutable and sorted', static function (): void {
    $base = new Scopes(['org' => 'o1']);
    $with = $base->with('customer', 'c1');
    assertSame(1, count($base), 'with() mutated the receiver');
    assertSame('c1', $with->node('customer'), 'node');
    // One printable form, which is also what keeps a cache from keying the
    // same question many ways.
    assertSame('customer=c1 org=o1', (string) $with, 'string form');
    $merged = $with->merge(['org' => 'o2', 'product' => 'p1']);
    assertSame('o2', $merged->node('org'), 'merge overrides');
    assertSame('c1', $merged->node('customer'), 'merge keeps');
    assertTrue((new Scopes())->isEmpty(), 'isEmpty');
});

check('Scopes::owner names the reserved axis', static function (): void {
    assertSame('usr_applicant', Scopes::owner('usr_applicant')->node(Scopes::OWNER_AXIS), 'owner');
    assertSame('_owner', Scopes::OWNER_AXIS, 'reserved axis');
});

check('AuthMethods::hasAll requires every method, not any', static function (): void {
    $m = new AuthMethods([AuthMethods::PASSWORD, AuthMethods::OTP]);
    assertTrue($m->has(AuthMethods::OTP), 'has');
    assertTrue($m->hasAll(AuthMethods::PASSWORD, AuthMethods::OTP), 'hasAll present');
    assertTrue(!$m->hasAll(AuthMethods::PASSWORD, AuthMethods::DEVICE_KEY), 'hasAll must require every method');
});

check('Permissions narrows by application', static function (): void {
    $ps = new Permissions(['billing:invoice:approve', 'billing:invoice:read', 'hr:person:read']);
    assertTrue($ps->has('billing:invoice:approve'), 'has');
    assertSame(2, count($ps->ofApp('billing')), 'ofApp');
});

echo "identity\n";
check('a principal answers who and what without claim-set spelunking', static function (): void {
    $authTime = time() - 2400;
    $p = new \Anubis\Principal(Claims::fromArray([
        'iss' => ISSUER, 'sub' => 'usr_1', 'aud' => [APP],
        'exp' => time() + 600, 'iat' => $authTime, 'auth_time' => $authTime,
        'sid' => 'ses_9', 'tid' => 'tnt_impack', 'realm' => 'internal',
        'roles' => ['billing.clerk'], 'scopes' => ['org' => 'o1', 'customer' => 'c1'],
        'amr' => ['pwd'], 'ial' => 2,
    ]), 'v4.public.x');

    assertSame('usr_1', $p->subject(), 'subject');
    assertSame('ses_9', $p->session(), 'session');
    assertTrue($p->hasRole('billing.clerk'), 'hasRole');
    assertSame('c1', $p->scopes()->node('customer'), 'scopes');

    $id = $p->identity();
    assertTrue($id instanceof Identity, 'identity type');
    assertSame('o1', $id->activeScope('org'), 'activeScope');
    // Authentication time is not issue time: a refresh mints a token with no
    // fresh proof, which is exactly why step-up is decided against this.
    assertTrue($id->authenticatedAt !== null, 'authenticatedAt');
    assertTrue(!$id->isApplication(), 'usr_ is not an application');
    assertSame('usr_1 [customer=c1 org=o1]', (string) $id, 'string form');
});

check('a client-credentials subject is recognisable', static function (): void {
    $id = Claims::fromArray(['sub' => 'app_batch'])->identity();
    assertTrue($id->isApplication(), 'app_ subject');
});

check('tokens expose lifetime, expiry and whether they can rotate', static function (): void {
    $issued = time();
    $t = new \Anubis\Tokens(accessToken: 'a', refreshToken: 'r', expiresIn: 600, issuedAt: $issued);
    assertTrue($t->hasRefresh(), 'hasRefresh');
    assertSame($issued + 600, $t->expiresAt()?->getTimestamp(), 'expiresAt');
    // A client-credentials pair has no refresh token; it is re-minted instead.
    assertTrue(!(new \Anubis\Tokens(accessToken: 'a'))->hasRefresh(), 'no refresh');
});

echo "\n{$passed} passed, {$failed} failed\n";
exit($failed === 0 ? 0 : 1);
