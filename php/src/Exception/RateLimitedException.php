<?php

declare(strict_types=1);

namespace Anubis\Exception;

/**
 * The caller is asking faster than its limits allow. Nothing was done, so
 * repeating after $retryAfter seconds is safe.
 *
 * Limits apply per IP, per account and per tenant. Seeing this on a sign-in
 * path may mean somebody is attacking that account rather than that your
 * traffic grew.
 */
final class RateLimitedException extends AnubisException
{
    public function __construct(
        public readonly int $retryAfter,
        public readonly ApiException $cause,
    ) {
        parent::__construct("anubis: rate limited, retry after {$retryAfter}s");
    }
}
