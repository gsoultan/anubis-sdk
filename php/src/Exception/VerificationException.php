<?php

declare(strict_types=1);

namespace Anubis\Exception;

/** A token was not acceptable: bad signature, wrong audience, expired, or a
 * kid this process does not hold. Comes off the offline path, so it carries no
 * request id — nothing was asked of Anubis. */
final class VerificationException extends AnubisException
{
}
