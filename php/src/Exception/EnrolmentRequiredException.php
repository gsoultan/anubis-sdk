<?php

declare(strict_types=1);

namespace Anubis\Exception;

use Anubis\AuthMethods;

/**
 * The realm requires a factor this member has not enrolled, and the deadline
 * has passed. No session was issued — but the refusal carries the means to
 * comply, which is what makes it enrol-or-deny rather than deny.
 *
 * Pass $grantToken to the TOTP enrolment calls in place of a session: the
 * session is exactly what the policy is withholding.
 */
final class EnrolmentRequiredException extends AnubisException
{
    public function __construct(
        public readonly AuthMethods $factors,
        public readonly int $deadline,
        public readonly string $grantToken,
    ) {
        parent::__construct(
            "anubis: enrolment required for [{$factors}] — use the grant token to enrol"
        );
    }

    /** When enforcement started. */
    public function deadlineAt(): ?\DateTimeImmutable
    {
        return $this->deadline === 0 ? null : new \DateTimeImmutable('@' . $this->deadline);
    }
}
