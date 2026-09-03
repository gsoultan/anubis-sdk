<?php

declare(strict_types=1);

namespace Anubis;

use Anubis\Exception\VerificationException;

/**
 * Verifies v4.public access tokens offline.
 *
 * Zero I/O on the verify path, except a bounded, rate-limited key refetch when
 * a token names a kid this process has not seen.
 */
final class Verifier
{
    private readonly Keys $keys;

    /**
     * @param string $audience This service's identifier. Mandatory: a verifier
     *   without an audience accepts tokens minted for other services — the
     *   classic confused deputy. There is no flag to skip this check.
     * @param array<string, mixed>|null $staticKeys Pin keys directly, for
     *   air-gapped consumers and tests.
     * @param int $leewaySeconds Absorbs clock skew between services. Enforce NTP anyway.
     */
    public function __construct(
        private readonly string $issuer,
        private readonly string $audience,
        ?string $keysUrl = null,
        ?array $staticKeys = null,
        private readonly int $leewaySeconds = 60,
        private ?\Closure $now = null,
    ) {
        if ($audience === '') {
            throw new VerificationException(
                'anubis: a verifier requires an audience — refusing to skip the aud check'
            );
        }
        if ($keysUrl === null && $staticKeys === null) {
            throw new VerificationException('anubis: either a keys url or static keys is required');
        }
        $this->keys = new Keys($keysUrl ?? '');
        if ($staticKeys !== null) {
            $this->keys->pin(Keys::parseDocument($staticKeys));
        }
        $this->now ??= static fn (): int => time();
    }

    /**
     * Checks signature, expiry, nbf, issuer and audience.
     *
     * It does NOT check epoch or session revocation — those need state only
     * Anubis holds. Use introspection where instant revocation matters.
     */
    public function verify(string $token): Claims
    {
        // The kid rides in the footer, which the signature covers — but it has
        // to be read BEFORE verification to select the key. That
        // pre-verification read may only index the bounded key map.
        $parsed = Paseto::parse($token);
        $kid = '';
        if ($parsed['footer'] !== '') {
            $footer = json_decode($parsed['footer'], true);
            if (!is_array($footer)) {
                throw new VerificationException('anubis: token footer is not JSON');
            }
            $kid = (string) ($footer['kid'] ?? '');
        }
        $verified = Paseto::verify($this->keys->get($kid), $token);

        $decoded = json_decode($verified['message'], true);
        if (!is_array($decoded)) {
            throw new VerificationException('anubis: claims are not JSON');
        }
        $claims = Claims::fromArray($decoded);
        if ($claims->version !== 0 && $claims->version !== 1) {
            throw new VerificationException('anubis: unsupported token version');
        }
        $this->validate($claims);

        return $claims;
    }

    private function validate(Claims $c): void
    {
        $now = ($this->now)();
        if ($c->expires !== 0 && $now > $c->expires + $this->leewaySeconds) {
            throw new VerificationException('anubis: token expired');
        }
        if ($c->notBefore !== 0 && $now < $c->notBefore - $this->leewaySeconds) {
            throw new VerificationException('anubis: token not yet valid (check NTP)');
        }
        if ($this->issuer !== '' && $c->issuer !== $this->issuer) {
            throw new VerificationException('anubis: issuer mismatch');
        }
        if (!in_array($this->audience, $c->audience, true)) {
            throw new VerificationException('anubis: audience mismatch');
        }
    }

    /** Extracts the Authorization bearer credential. */
    public static function bearer(?string $authorization): ?string
    {
        if ($authorization === null || $authorization === '') {
            return null;
        }
        if (!preg_match('/^Bearer\s+(.+)$/i', trim($authorization), $m)) {
            return null;
        }
        return $m[1];
    }
}
