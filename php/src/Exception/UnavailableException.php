<?php

declare(strict_types=1);

namespace Anubis\Exception;

/**
 * Anubis could not be reached, or answered that it is not ready. Retry with
 * backoff.
 *
 * A readiness refusal is deliberate: an instance whose snapshot has outlived
 * its maximum age fails /readyz first, so it leaves the load balancer before it
 * starts denying decisions.
 */
final class UnavailableException extends AnubisException
{
}
