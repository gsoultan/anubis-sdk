<?php

declare(strict_types=1);

namespace Anubis;

use Anubis\Exception\VerificationException;

/**
 * Fetches and caches the published key document.
 *
 * Two clocks govern refetching. The TTL bounds how stale the document may get,
 * so a key withdrawn upstream stops verifying. The min-refetch interval bounds
 * what an unknown kid can provoke inside that window — kid arrives inside
 * attacker-supplied tokens, so a stream of garbage kids must not become a
 * stream of outbound requests.
 */
final class Keys
{
    /**
     * kid is attacker-controlled input: it arrives inside tokens. It may only
     * ever index a bounded, pre-loaded, in-memory map — never a database query,
     * a filesystem path, or a per-token network fetch.
     */
    private const MAX_KEYS = 64;

    /** A keys document past this size is refused rather than buffered. */
    private const MAX_DOCUMENT_BYTES = 1048576;

    /**
     * How long a fetched document is treated as current, and so the upper bound
     * on how long a withdrawn key keeps verifying tokens. A cache that refetches
     * only on an unknown kid never notices a removal: rotation works, revocation
     * silently does not.
     */
    public const DEFAULT_TTL_SECONDS = 300;
    /** Floor between the fetches an unknown kid may provoke. */
    public const DEFAULT_MIN_REFETCH_SECONDS = 30;
    /** Floor between attempts after a failed fetch. Short: nothing verifies yet. */
    public const DEFAULT_MIN_RETRY_SECONDS = 1;

    /** @var array<string, array{key: string, nb: int, na: int}>|null */
    private ?array $keys = null;
    /** @var array<string, array{key: string, nb: int, na: int}>|null */
    private ?array $pinned = null;
    private float $lastFetch = 0.0;
    private float $nextFetch = 0.0;
    private ?string $lastError = null;

    public function __construct(
        private readonly string $url,
        private readonly string $issuer = '',
        private readonly int $ttlSeconds = self::DEFAULT_TTL_SECONDS,
        private readonly int $minRefetchSeconds = self::DEFAULT_MIN_REFETCH_SECONDS,
        private readonly int $minRetrySeconds = self::DEFAULT_MIN_RETRY_SECONDS,
        private readonly int $timeoutSeconds = 5,
    ) {
    }

    /**
     * Parses a published keys document.
     *
     * $issuer, when non-empty, must match the document's own issuer. A verifier
     * that loads whatever keys its URL happens to serve cannot notice it was
     * pointed at the wrong deployment. A document that omits the field is
     * accepted: the binding is only ever as good as what the issuer publishes.
     *
     * @param array<string, mixed> $document
     * @return array<string, array{key: string, nb: int, na: int}>
     */
    public static function parseDocument(array $document, string $issuer = ''): array
    {
        $entries = $document['keys'] ?? null;
        if (!is_array($entries)) {
            throw new VerificationException('anubis: keys document has no keys');
        }
        $published = (string) ($document['issuer'] ?? '');
        if ($issuer !== '' && $published !== '' && $published !== $issuer) {
            throw new VerificationException(sprintf(
                'anubis: keys document is issued by "%s", expected "%s"',
                $published,
                $issuer
            ));
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
            $out[(string) $entry['kid']] = [
                'key' => $raw,
                'nb' => (int) ($entry['not_before'] ?? 0),
                'na' => (int) ($entry['not_after'] ?? 0),
            ];
        }
        return $out;
    }

    /** @param array<string, array{key: string, nb: int, na: int}> $keys */
    public function pin(array $keys): void
    {
        $this->pinned = $keys;
    }

    public function get(string $kid, int $now): string
    {
        if ($this->pinned !== null) {
            $hit = self::lookup($this->pinned, $kid, $now);
            if ($hit !== null) {
                return $hit;
            }
            if ($this->url === '') {
                throw new VerificationException(sprintf('anubis: unknown kid "%s"', $kid));
            }
        }

        $clock = (float) $now;

        // The hot path: a current document holding the kid answers with no I/O.
        if ($this->keys !== null && ($clock - $this->lastFetch) < $this->ttlSeconds) {
            $hit = self::lookup($this->keys, $kid, $now);
            if ($hit !== null) {
                return $hit;
            }
        }

        // Missing, stale, or an unknown kid worth spending a fetch on.
        $had = $this->keys;
        if ($this->url !== '') {
            try {
                $this->refresh($clock);
            } catch (VerificationException $e) {
                // Stale keys beat no keys; the unknown-kid rejection still stands.
                if ($had === null) {
                    throw $e;
                }
            }
        }

        if ($this->keys !== null) {
            $hit = self::lookup($this->keys, $kid, $now);
            if ($hit !== null) {
                return $hit;
            }
        }
        throw new VerificationException(sprintf('anubis: unknown kid "%s"', $kid));
    }

    /**
     * Returns the key for $kid if $set holds it and $now falls inside its
     * published window. Either bound at zero is unbounded.
     *
     * not_after is when a verifier stops *trusting* the key, not when the issuer
     * stops signing with it: a token minted a second before the deadline is
     * rejected the moment it passes. Publish not_after at least one maximum
     * token lifetime after the key's last signing time, or a rotation rejects
     * tokens that are still live.
     *
     * @param array<string, array{key: string, nb: int, na: int}> $set
     */
    private static function lookup(array $set, string $kid, int $now): ?string
    {
        $held = $set[$kid] ?? null;
        if ($held === null) {
            return null;
        }
        if ($held['nb'] !== 0 && $now < $held['nb']) {
            return null;
        }
        if ($held['na'] !== 0 && $now >= $held['na']) {
            return null;
        }
        return $held['key'];
    }

    private function refresh(float $now): void
    {
        if ($now < $this->nextFetch) {
            // Surface why the last attempt failed rather than a bare "throttled".
            if ($this->lastError !== null) {
                throw new VerificationException($this->lastError);
            }
            return;
        }
        try {
            $this->keys = $this->fetch();
            $this->lastFetch = $now;
            $this->nextFetch = $now + $this->minRefetchSeconds;
            $this->lastError = null;
        } catch (VerificationException $e) {
            $this->nextFetch = $now + $this->minRetrySeconds;
            $this->lastError = $e->getMessage();
            throw $e;
        }
    }

    /** @return array<string, array{key: string, nb: int, na: int}> */
    private function fetch(): array
    {
        $body = '';
        $oversized = false;
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => false,
            // Stop reading rather than buffer an unbounded response: returning
            // a short count aborts the transfer.
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$oversized): int {
                $body .= $chunk;
                if (strlen($body) > self::MAX_DOCUMENT_BYTES) {
                    $oversized = true;
                    return 0;
                }
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        unset($ch); // curl_close has been a no-op since PHP 8.0 and is now deprecated

        if ($oversized) {
            throw new VerificationException(
                sprintf('anubis: keys document exceeds %d bytes', self::MAX_DOCUMENT_BYTES)
            );
        }
        if ($ok === false || $status !== 200) {
            throw new VerificationException('anubis: keys fetch failed: ' . ($error ?: "status {$status}"));
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new VerificationException('anubis: keys document is not JSON');
        }
        return self::parseDocument($decoded, $this->issuer);
    }
}
