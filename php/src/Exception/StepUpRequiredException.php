<?php

declare(strict_types=1);

namespace Anubis\Exception;

use Anubis\AuthMethods;
use Anubis\Duration;
use Anubis\Permission;

/**
 * A denial the caller can do something about: the subject holds the permission
 * but has not authenticated strongly enough, or recently enough.
 *
 * Machine-readable so the application does not guess. Feed it to
 * Client::beginStepUp() and send the user back through sign-in; do not invent a
 * second factor of your own.
 *
 */
final class StepUpRequiredException extends AnubisException
{
    public function __construct(
        public readonly AuthMethods $requiredAmr,
        public readonly AuthMethods $currentAmr,
        public readonly string $maxAuthAge,
        public readonly string $authAge,
        public readonly ?Permission $permission = null,
    ) {
        parent::__construct(sprintf(
            'anubis: step-up required for %s: have [%s], need [%s]',
            $permission ?? '?',
            $currentAmr,
            $requiredAmr,
        ));
    }

    /**
     * How fresh the authentication has to be, in seconds. Anubis sends it as a
     * string; a caller comparing durations should not have to parse it.
     */
    public function maxAuthAgeSeconds(): ?int
    {
        return Duration::seconds($this->maxAuthAge);
    }
}
