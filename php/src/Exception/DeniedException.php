<?php

declare(strict_types=1);

namespace Anubis\Exception;

use Anubis\Permission;

/**
 * Anubis answered, and the answer was no.
 *
 * $failingAxis is always named on a scope refusal: a deny nobody can explain is
 * a support ticket.
 */
final class DeniedException extends AnubisException
{
    public function __construct(
        public readonly string $reason,
        public readonly string $failingAxis,
        string $message,
        public readonly ?Permission $permission = null,
    ) {
        parent::__construct($message !== '' ? $message : $reason);
    }
}
