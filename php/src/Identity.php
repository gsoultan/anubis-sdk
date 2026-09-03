<?php

declare(strict_types=1);

namespace Anubis;

/**
 * Who a caller is and what they hold, in one place.
 *
 * It answers the question every application asks first — who is this, what
 * roles do they have, what are they scoped to right now — without reaching
 * into a claim set and remembering which fields mean what.
 *
 * It is a VIEW OF A SESSION, not of a person. $roles and $scopes are what this
 * token was minted with: the roles held at issuance, and the ONE node per axis
 * the session is currently acting as. It is not the full set of nodes the
 * person is entitled to — that lives in grants, on the admin plane.
 */
final readonly class Identity implements \Stringable
{
    public function __construct(
        public string $subject,
        public string $session,
        public string $tenant,
        public string $realm,
        public Roles $roles,
        public Scopes $scopes,
        public AuthMethods $methods,
        public int $assurance = 0,
        public ?\DateTimeImmutable $authenticatedAt = null,
        public ?\DateTimeImmutable $expiresAt = null,
    ) {
    }

    /**
     * How long ago the caller authenticated.
     *
     * Measured from authentication, not issuance: a refresh mints a new token
     * with no fresh proof of identity, which is exactly why a step-up rule
     * with a maximum age is decided against this.
     */
    public function authAge(): ?\DateInterval
    {
        return $this->authenticatedAt?->diff(new \DateTimeImmutable());
    }

    /** A service acting as itself rather than a person: no session, no refresh. */
    public function isApplication(): bool
    {
        return str_starts_with($this->subject, 'app_');
    }

    /**
     * The cheap local check. It answers "does this token say so", which is not
     * the same question as "may they do this" — roles are an input to a
     * decision, not the decision. Reach for Client::require when it matters.
     */
    public function hasRole(Role|string $role): bool
    {
        return $this->roles->has($role);
    }

    /** The node this session is acting as on one axis. */
    public function activeScope(string $axis): ?string
    {
        return $this->scopes->node($axis);
    }

    public function __toString(): string
    {
        return $this->scopes->isEmpty() ? $this->subject : "{$this->subject} [{$this->scopes}]";
    }
}
