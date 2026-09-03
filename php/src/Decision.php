<?php

declare(strict_types=1);

namespace Anubis;

use Anubis\Exception\DeniedException;
use Anubis\Exception\StepUpRequiredException;

/**
 * Anubis's answer.
 *
 * A denial is an answer, not a failure: the reason and the failing axis are
 * always populated on a refusal, because a deny nobody can explain is a support
 * ticket.
 */
final class Decision
{
    public function __construct(
        public readonly bool $allow,
        public readonly string $reason = '',
        public readonly string $failingAxis = '',
        public readonly string $message = '',
        public readonly AuthMethods $requiredAmr = new AuthMethods(),
        public readonly string $maxAuthAge = '',
        public readonly AuthMethods $currentAmr = new AuthMethods(),
        public readonly string $authAge = '',
        public readonly ?Permission $permission = null,
    ) {
    }

    /** @param array<string, mixed> $d */
    public static function fromArray(array $d, Permission $permission): self
    {
        return new self(
            allow: (bool) ($d['allow'] ?? false),
            reason: (string) ($d['reason'] ?? ''),
            failingAxis: (string) ($d['failingAxis'] ?? ''),
            message: (string) ($d['message'] ?? ''),
            requiredAmr: new AuthMethods((array) ($d['requiredAmr'] ?? [])),
            maxAuthAge: (string) ($d['maxAuthAge'] ?? ''),
            currentAmr: new AuthMethods((array) ($d['currentAmr'] ?? [])),
            authAge: (string) ($d['authAge'] ?? ''),
            permission: $permission,
        );
    }

    /**
     * How fresh the authentication has to be, in seconds. Anubis sends it as a
     * string; a caller comparing durations should not have to parse it.
     */
    public function maxAuthAgeSeconds(): ?int
    {
        return Duration::seconds($this->maxAuthAge);
    }

    public function needsStepUp(): bool
    {
        return $this->reason === 'step_up_required';
    }

    /** Throws the typed refusal, or returns cleanly when allowed. */
    public function orThrow(): void
    {
        if ($this->allow) {
            return;
        }
        if ($this->needsStepUp()) {
            throw new StepUpRequiredException(
                $this->requiredAmr,
                $this->currentAmr,
                $this->maxAuthAge,
                $this->authAge,
                $this->permission,
            );
        }
        throw new DeniedException($this->reason, $this->failingAxis, $this->message, $this->permission);
    }
}
