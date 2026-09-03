<?php

declare(strict_types=1);

namespace Anubis\Exception;

/** Base class, so a caller can catch everything this SDK throws. */
abstract class AnubisException extends \RuntimeException
{
}
