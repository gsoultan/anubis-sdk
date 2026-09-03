<?php

declare(strict_types=1);

namespace Anubis;

/**
 * The methods a caller authenticated with — the "amr" claim.
 *
 * Step-up decisions turn on it, which is why it travels on every authorization
 * request.
 *
 * @implements \IteratorAggregate<int, string>
 */
final readonly class AuthMethods implements \IteratorAggregate, \Countable, \Stringable
{
    /**
     * The methods Anubis mints today. A realm may require others later, so the
     * type stays open — these are the ones worth having a name for.
     */
    public const PASSWORD = 'pwd';
    public const OTP = 'otp';
    public const DEVICE_KEY = 'device_key';

    /** @var list<string> */
    private array $items;

    /** @param iterable<string> $methods */
    public function __construct(iterable $methods = [])
    {
        $out = [];
        foreach ($methods as $m) {
            $out[] = (string) $m;
        }
        $this->items = $out;
    }

    public function has(string $method): bool
    {
        return in_array($method, $this->items, true);
    }

    /**
     * Every listed method was used — the local form of a step-up check,
     * answerable without asking Anubis.
     */
    public function hasAll(string ...$methods): bool
    {
        foreach ($methods as $m) {
            if (!$this->has($m)) {
                return false;
            }
        }
        return true;
    }

    /** @return list<string> */
    public function toStrings(): array
    {
        return $this->items;
    }

    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->items);
    }

    public function count(): int
    {
        return count($this->items);
    }

    public function __toString(): string
    {
        return implode(' ', $this->items);
    }
}
