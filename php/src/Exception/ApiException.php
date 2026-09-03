<?php

declare(strict_types=1);

namespace Anubis\Exception;

/**
 * A refusal with no more specific type.
 *
 * $errorCode is the stable machine-readable string from the error envelope —
 * the same vocabulary on both transports — and $requestId correlates to
 * audit_log and traces, which is the first thing anyone asks for.
 *
 * It is not called $code because PHP's own Exception already owns that name as
 * an int, and a readonly string cannot redeclare it.
 */
class ApiException extends AnubisException
{
    /** @param array<string, string> $details */
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly string $requestId = '',
        public readonly int $status = 0,
        public readonly array $details = [],
    ) {
        parent::__construct($message !== '' ? $message : ($errorCode !== '' ? $errorCode : "http {$status}"));
    }
}
