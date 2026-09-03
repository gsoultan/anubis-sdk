<?php

declare(strict_types=1);

namespace Anubis;

/**
 * An effective permission set — what a caller may do, expanded from every role
 * they hold.
 *
 * @implements \IteratorAggregate<int, Permission>
 */
final readonly class Permissions implements \IteratorAggregate, \Countable
{
    /** @var list<Permission> */
    private array $items;

    /** @param iterable<Permission|string> $permissions */
    public function __construct(iterable $permissions = [])
    {
        $out = [];
        foreach ($permissions as $p) {
            $out[] = Permission::of($p);
        }
        $this->items = $out;
    }

    public function has(Permission|string $permission): bool
    {
        $want = Permission::of($permission);
        foreach ($this->items as $p) {
            if ($p->equals($want)) {
                return true;
            }
        }
        return false;
    }

    public function hasAny(Permission|string ...$permissions): bool
    {
        foreach ($permissions as $p) {
            if ($this->has($p)) {
                return true;
            }
        }
        return false;
    }

    /** Narrow to one application's permissions. */
    public function ofApp(string $app): self
    {
        return new self(array_filter($this->items, static fn (Permission $p): bool => $p->app() === $app));
    }

    /** @return list<string> */
    public function toStrings(): array
    {
        return array_map(static fn (Permission $p): string => $p->key, $this->items);
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
