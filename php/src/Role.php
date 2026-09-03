<?php

declare(strict_types=1);

namespace Anubis;

/**
 * A granted role, which Anubis returns prefixed with the application that
 * defined it: a manifest declaring "clerk" for "billing" yields "billing.clerk".
 *
 * Comparing a returned role against the unprefixed manifest name is the
 * mistake this type exists to make visible.
 */
final readonly class Role implements \Stringable
{
    private function __construct(public string $value)
    {
    }

    public static function of(self|string $role): self
    {
        return $role instanceof self ? $role : new self($role);
    }

    public static function from(string $app, string $name): self
    {
        return new self("{$app}.{$name}");
    }

    /** The application that defined the role, or "" for an unprefixed one. */
    public function app(): string
    {
        $dot = strpos($this->value, '.');
        return $dot === false ? '' : substr($this->value, 0, $dot);
    }

    /** The role as the manifest declared it, without the prefix. */
    public function name(): string
    {
        $dot = strpos($this->value, '.');
        return $dot === false ? $this->value : substr($this->value, $dot + 1);
    }

    public function equals(self|string $other): bool
    {
        return $this->value === self::of($other)->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
