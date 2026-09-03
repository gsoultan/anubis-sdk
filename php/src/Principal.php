<?php

declare(strict_types=1);

namespace Anubis;

/**
 * What a verified request carries: the claim set, and the token it came from.
 *
 * The accessors are the ones a handler reaches for. $claims is still there for
 * anything they do not cover, but a handler reading $claims->authTime and
 * converting it by hand is doing work this class already did.
 */
final readonly class Principal
{
    public function __construct(
        public Claims $claims,
        public string $token,
    ) {
    }

    /** Who this caller is and what they hold. */
    public function identity(): Identity
    {
        return $this->claims->identity();
    }

    public function subject(): string
    {
        return $this->claims->subject;
    }

    /**
     * The signed-in device this token belongs to. Empty for a
     * client-credentials caller, which has no session by design.
     */
    public function session(): string
    {
        return $this->claims->session;
    }

    public function tenant(): string
    {
        return $this->claims->tenant;
    }

    /**
     * The roles this token was minted with, prefixed by the application that
     * defined them: "billing.clerk", not "clerk".
     */
    public function roles(): Roles
    {
        return $this->claims->roles;
    }

    /**
     * The ACTIVE scope — one node per axis, what this session is acting as
     * right now. Not everything the person is entitled to; that lives in
     * grants, on the admin plane.
     */
    public function scopes(): Scopes
    {
        return $this->claims->scopes;
    }

    public function methods(): AuthMethods
    {
        return $this->claims->amr;
    }

    public function authenticatedAt(): ?\DateTimeImmutable
    {
        return $this->claims->authenticatedAt();
    }

    public function expiresAt(): ?\DateTimeImmutable
    {
        return $this->claims->expiresAt();
    }

    public function hasRole(Role|string $role): bool
    {
        return $this->claims->hasRole($role);
    }
}
