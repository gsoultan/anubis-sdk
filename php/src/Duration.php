<?php

declare(strict_types=1);

namespace Anubis;

/**
 * Durations Anubis expresses as strings ("2m").
 *
 * One parser, used by every refusal that carries one, so a caller comparing
 * durations never has to write the regex a second time.
 */
final readonly class Duration
{
    private function __construct()
    {
    }

    public static function seconds(string $value): ?int
    {
        if (preg_match('/^(\d+)(s|m|h)$/', trim($value), $m) !== 1) {
            return null;
        }
        return (int) $m[1] * match ($m[2]) { 's' => 1, 'm' => 60, 'h' => 3600 };
    }
}
