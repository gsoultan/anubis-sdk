<?php

declare(strict_types=1);

namespace Anubis\Exception;

/**
 * A consumed refresh token was presented again.
 *
 * Do not retry. Two parties held this token and one of them is an attacker; the
 * family and the session are already revoked. Drop the session, send the user
 * to sign in, and alert — this is a security event, not a transient failure. It
 * is the one exception here that carries no retry advice, because there is none.
 */
final class RefreshReuseException extends AnubisException
{
    public function __construct(public readonly ApiException $cause)
    {
        parent::__construct(
            'anubis: refresh token reuse detected — family and session revoked, this is theft'
        );
    }
}
