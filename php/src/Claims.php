<?php

declare(strict_types=1);

namespace Anubis;

/**
 * The access-token claim set exactly as the token carries it.
 *
 * The properties mirror the wire because that is their job — the times are
 * unix seconds here because they are unix seconds in the token. Everything
 * derived from them is a method, and identity() assembles the whole thing into
 * the view most callers actually want.
 *
 * `scopes` is a map, never fixed fields: adding a scope axis must not change
 * the token format.
 */
final readonly class Claims
{
    /** @param list<string> $audience */
    public function __construct(
        public string $issuer,
        public string $subject,
        public array $audience,
        public int $expires,
        public int $issuedAt,
        public int $notBefore = 0,
        public string $tokenId = '',
        public string $session = '',
        public string $tenant = '',
        public Roles $roles = new Roles(),
        public Scopes $scopes = new Scopes(),
        public string $realm = '',
        public int $ial = 0,
        public AuthMethods $amr = new AuthMethods(),
        public int $authTime = 0,
        public int $epoch = 0,
        public int $version = 0,
    ) {
    }

    /** @param array<string, mixed> $c */
    public static function fromArray(array $c): self
    {
        $aud = $c['aud'] ?? [];
        return new self(
            issuer: (string) ($c['iss'] ?? ''),
            subject: (string) ($c['sub'] ?? ''),
            audience: is_array($aud) ? array_map('strval', $aud) : [(string) $aud],
            expires: (int) ($c['exp'] ?? 0),
            issuedAt: (int) ($c['iat'] ?? 0),
            notBefore: (int) ($c['nbf'] ?? 0),
            tokenId: (string) ($c['jti'] ?? ''),
            session: (string) ($c['sid'] ?? ''),
            tenant: (string) ($c['tid'] ?? ''),
            roles: new Roles((array) ($c['roles'] ?? [])),
            scopes: new Scopes((array) ($c['scopes'] ?? [])),
            realm: (string) ($c['realm'] ?? ''),
            ial: (int) ($c['ial'] ?? 0),
            amr: new AuthMethods((array) ($c['amr'] ?? [])),
            authTime: (int) ($c['auth_time'] ?? 0),
            epoch: (int) ($c['epoch'] ?? 0),
            version: (int) ($c['ver'] ?? 0),
        );
    }

    /**
     * The claim set as a caller wants to read it: who this is, what they hold,
     * and what they are scoped to right now.
     */
    public function identity(): Identity
    {
        return new Identity(
            subject: $this->subject,
            session: $this->session,
            tenant: $this->tenant,
            realm: $this->realm,
            roles: $this->roles,
            scopes: $this->scopes,
            methods: $this->amr,
            assurance: $this->ial,
            authenticatedAt: self::toDate($this->authTime),
            expiresAt: self::toDate($this->expires),
        );
    }

    /** When this token stops being accepted. */
    public function expiresAt(): ?\DateTimeImmutable
    {
        return self::toDate($this->expires);
    }

    /** When this token was minted. */
    public function issuedAtTime(): ?\DateTimeImmutable
    {
        return self::toDate($this->issuedAt);
    }

    /**
     * When the caller last proved who they were.
     *
     * Not the same as issuedAtTime(): a refresh mints a new token without any
     * fresh proof of identity, which is exactly why step-up rules with a
     * maximum age are decided against this and not against issuance.
     */
    public function authenticatedAt(): ?\DateTimeImmutable
    {
        return self::toDate($this->authTime);
    }

    public function hasRole(Role|string $role): bool
    {
        return $this->roles->has($role);
    }

    public function hasAuthMethod(string $method): bool
    {
        return $this->amr->has($method);
    }

    public function activeScope(string $axis): ?string
    {
        return $this->scopes->node($axis);
    }

    public static function toDate(int $seconds): ?\DateTimeImmutable
    {
        return $seconds === 0 ? null : new \DateTimeImmutable('@' . $seconds);
    }
}
