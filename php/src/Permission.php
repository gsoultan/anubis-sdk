<?php

declare(strict_types=1);

namespace Anubis;

/**
 * A full permission key: "app:resource:action".
 *
 * The full key is what tokens carry and what authorize() takes. Inside an
 * application manifest the same permission is written WITHOUT the application
 * prefix — "invoice:approve" — and that asymmetry has cost people real time.
 * manifest() makes the two forms convertible instead of a thing to remember.
 */
final readonly class Permission implements \Stringable
{
    /** @var list<string>|null the three parts, or null when malformed */
    private ?array $parts;

    private function __construct(public string $key)
    {
        $segments = explode(':', $key);
        $this->parts = count($segments) === 3 && !in_array('', $segments, true) ? $segments : null;
    }

    public static function of(self|string $key): self
    {
        return $key instanceof self ? $key : new self($key);
    }

    public static function from(string $app, string $resource, string $action): self
    {
        return new self("{$app}:{$resource}:{$action}");
    }

    /** The application slug the permission belongs to, or "" when malformed. */
    public function app(): string
    {
        return $this->parts[0] ?? '';
    }

    public function resource(): string
    {
        return $this->parts[1] ?? '';
    }

    public function action(): string
    {
        return $this->parts[2] ?? '';
    }

    /** Whether the key has the three non-empty parts Anubis requires. */
    public function isValid(): bool
    {
        return $this->parts !== null;
    }

    /** The permission as a manifest writes it: "resource:action", no prefix. */
    public function manifest(): string
    {
        return $this->parts === null ? $this->key : "{$this->parts[1]}:{$this->parts[2]}";
    }

    public function equals(self|string $other): bool
    {
        return $this->key === self::of($other)->key;
    }

    public function __toString(): string
    {
        return $this->key;
    }
}
