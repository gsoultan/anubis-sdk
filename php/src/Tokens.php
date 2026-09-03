<?php

declare(strict_types=1);

namespace Anubis;

/**
 * An issued credential pair.
 *
 * The refresh token is single-use: every refresh returns a rotated pair and
 * kills the one presented. Store the new pair before discarding the old.
 */
final class Tokens
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $refreshToken = '',
        public readonly string $tokenType = 'Bearer',
        public readonly int $expiresIn = 0,
        public readonly string $sessionId = '',
        public readonly int $issuedAt = 0,
    ) {
    }

    /** @param array<string, mixed> $t Connect spelling (camelCase). */
    public static function fromConnect(array $t, int $now): self
    {
        return new self(
            accessToken: (string) ($t['accessToken'] ?? ''),
            refreshToken: (string) ($t['refreshToken'] ?? ''),
            tokenType: (string) ($t['tokenType'] ?? 'Bearer'),
            expiresIn: (int) ($t['expiresIn'] ?? 0),
            sessionId: (string) ($t['sessionId'] ?? ''),
            issuedAt: $now,
        );
    }

    /**
     * @param array<string, mixed> $t The browser token endpoint's spelling
     *   (snake_case). It writes its JSON by hand while every Connect procedure
     *   answers in protojson's camelCase — an asymmetry of the server that a
     *   client has to carry.
     */
    public static function fromHttp(array $t, int $now): self
    {
        return new self(
            accessToken: (string) ($t['access_token'] ?? ''),
            refreshToken: (string) ($t['refresh_token'] ?? ''),
            tokenType: (string) ($t['token_type'] ?? 'Bearer'),
            expiresIn: (int) ($t['expires_in'] ?? 0),
            sessionId: (string) ($t['session_id'] ?? ''),
            issuedAt: $now,
        );
    }

    /** When the access token stops being accepted. */
    public function expiresAt(): ?\DateTimeImmutable
    {
        if ($this->issuedAt === 0 || $this->expiresIn === 0) {
            return null;
        }
        return new \DateTimeImmutable('@' . ($this->issuedAt + $this->expiresIn));
    }

    /** How long the access token is good for. */
    public function lifetime(): \DateInterval
    {
        return new \DateInterval("PT{$this->expiresIn}S");
    }

    /**
     * Whether this pair can be rotated. A client-credentials token cannot: it
     * is re-minted from the application's own secret instead.
     */
    public function hasRefresh(): bool
    {
        return $this->refreshToken !== '';
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'access_token' => $this->accessToken,
            'refresh_token' => $this->refreshToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn,
            'session_id' => $this->sessionId,
            'issued_at' => $this->issuedAt,
        ];
    }
}
