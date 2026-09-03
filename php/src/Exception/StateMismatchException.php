<?php

declare(strict_types=1);

namespace Anubis\Exception;

/**
 * The callback's state did not match the one this client issued.
 *
 * Treat it as an attack, not a bug: state binds the callback to the browser
 * that started the flow, and a mismatch is what CSRF against the sign-in flow
 * looks like. The code is not exchanged.
 */
final class StateMismatchException extends AnubisException
{
    public function __construct(string $reason)
    {
        parent::__construct("anubis: login state did not match ({$reason}) — refusing to exchange the code");
    }
}
