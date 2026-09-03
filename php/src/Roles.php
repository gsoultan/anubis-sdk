<?php

declare(strict_types=1);

namespace Anubis;

/**
 * The set of roles a caller holds.
 *
 * @implements \IteratorAggregate<int, Role>
 */
final readonly class Roles implements \IteratorAggregate, \Countable
{
    /** @var list<Role> */
    private array $items;

    /** @param iterable<Role|string> $roles */
    public function __construct(iterable $roles = [])
    {
        $out = [];
        foreach ($roles as $r) {
            $out[] = Role::of($r);
        }
        $this->items = $out;
    }

    public function has(Role|string $role): bool
    {
        $want = Role::of($role);
        foreach ($this->items as $r) {
            if ($r->equals($want)) {
                return true;
            }
        }
        return false;
    }

    public function hasAny(Role|string ...$roles): bool
    {
        foreach ($roles as $r) {
            if ($this->has($r)) {
                return true;
            }
        }
        return false;
    }

    /** Narrow to the roles one application defined. */
    public function ofApp(string $app): self
    {
        return new self(array_filter($this->items, static fn (Role $r): bool => $r->app() === $app));
    }

    /** @return list<string> */
    public function toStrings(): array
    {
        return array_map(static fn (Role $r): string => $r->value, $this->items);
    }

    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->items);
    }

    public function count(): int
    {
        return count($this->items);
    }
}
