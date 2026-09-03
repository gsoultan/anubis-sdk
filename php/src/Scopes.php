<?php

declare(strict_types=1);

namespace Anubis;

/**
 * The target node on each axis an action touches.
 *
 * Supply every axis the action could be constrained on. Within an axis, any
 * granted node at or above the target satisfies it; across axes, all must
 * hold. On a strict axis an omitted axis is DENIED, not ignored — fail-closed
 * is the whole design, and "I forgot an axis" and "they may not do this" are
 * the same answer from outside.
 *
 * Immutable: with() and merge() return copies, so a scope set shared between
 * handlers cannot change underneath one of them.
 */
final readonly class Scopes implements \Stringable, \Countable
{
    /** The reserved axis for self-scoped access: the owner of the record. */
    public const OWNER_AXIS = '_owner';

    /** @var array<string, string> */
    private array $entries;

    /** @param array<string, string> $entries */
    public function __construct(array $entries = [])
    {
        $this->entries = array_map('strval', $entries);
    }

    /** @param self|array<string, string>|null $scopes */
    public static function of(self|array|null $scopes): self
    {
        if ($scopes instanceof self) {
            return $scopes;
        }
        return new self($scopes ?? []);
    }

    /**
     * The scope set for self-scoped access, naming the reserved axis so it
     * cannot be misspelt into a silent denial.
     */
    public static function owner(string $subject): self
    {
        return new self([self::OWNER_AXIS => $subject]);
    }

    public function with(string $axis, string $node): self
    {
        return new self([...$this->entries, $axis => $node]);
    }

    /** @param self|array<string, string> $other */
    public function merge(self|array $other): self
    {
        return new self([...$this->entries, ...self::of($other)->entries]);
    }

    public function node(string $axis): ?string
    {
        return $this->entries[$axis] ?? null;
    }

    /** The axes supplied, sorted, so a scope set has one printable form. */
    public function axes(): array
    {
        $axes = array_keys($this->entries);
        sort($axes);
        return $axes;
    }

    public function isEmpty(): bool
    {
        return $this->entries === [];
    }

    /** The plain map the API expects. @return array<string, string> */
    public function toWire(): array
    {
        return $this->entries;
    }

    public function count(): int
    {
        return count($this->entries);
    }

    public function __toString(): string
    {
        $parts = [];
        foreach ($this->axes() as $axis) {
            $parts[] = "{$axis}={$this->entries[$axis]}";
        }
        return implode(' ', $parts);
    }
}
