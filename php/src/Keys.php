<?php

declare(strict_types=1);

namespace Anubis;

use Anubis\Exception\VerificationException;

/**
 * Fetches and caches the published key document.
 *
 * On an unknown kid it refetches at most once per $minRefetchSeconds — a stream
 * of garbage kids must not translate into a stream of outbound requests.
 */
final class Keys
{
    /**
     * kid is attacker-controlled input: it arrives inside tokens. It may only
     * ever index a bounded, pre-loaded, in-memory map — never a database query,
     * a filesystem path, or a per-token network fetch.
     */
    private const MAX_KEYS = 64;

    /** @var array<string, string>|null kid => raw 32-byte public key */
    private ?array $keys = null;
    private float $lastFetch = 0.0;

    public function __construct(
        private readonly string $url,
        private readonly int $minRefetchSeconds = 30,
        private readonly int $timeoutSeconds = 5,
    ) {
    }

    /** @param array<string, mixed> $document */
    public static function parseDocument(array $document): array
    {
        $entries = $document['keys'] ?? null;
        if (!is_array($entries)) {
            throw new VerificationException('anubis: keys document has no keys');
        }
        if (count($entries) > self::MAX_KEYS) {
            throw new VerificationException(
                sprintf('anubis: keys document has %d keys, max %d', count($entries), self::MAX_KEYS)
            );
        }
        $out = [];
        foreach ($entries as $entry) {
            if (($entry['alg'] ?? '') !== 'Ed25519') {
                continue; // pinned algorithm; nothing negotiable
            }
            $raw = Paseto::b64urlDecode((string) ($entry['public_key'] ?? ''));
            if (strlen($raw) !== Paseto::PUBLIC_KEY_BYTES) {
                throw new VerificationException('anubis: key ' . ($entry['kid'] ?? '?') . ': bad public key');
            }
            $out[(string) $entry['kid']] = $raw;
        }
        return $out;
    }

    /** @param array<string, string> $keys */
    public function pin(array $keys): void
    {
        $this->keys = $keys;
    }

    public function get(string $kid): string
    {
        if (isset($this->keys[$kid])) {
            return $this->keys[$kid];
        }
        if ($this->keys === null || (microtime(true) - $this->lastFetch) >= $this->minRefetchSeconds) {
            try {
                $this->refresh();
            } catch (VerificationException $e) {
                // Stale keys beat no keys; the unknown-kid rejection still stands.
                if ($this->keys === null) {
                    throw $e;
                }
            }
            if (isset($this->keys[$kid])) {
                return $this->keys[$kid];
            }
        }
        throw new VerificationException(sprintf('anubis: unknown kid "%s"', $kid));
    }

    private function refresh(): void
    {
        $this->lastFetch = microtime(true);
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($body === false || $status !== 200) {
            throw new VerificationException('anubis: keys fetch failed: ' . ($error ?: "status {$status}"));
        }
        $decoded = json_decode((string) $body, true);
        if (!is_array($decoded)) {
            throw new VerificationException('anubis: keys document is not JSON');
        }
        $this->keys = self::parseDocument($decoded);
    }
}
