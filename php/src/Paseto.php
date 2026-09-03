<?php

declare(strict_types=1);

namespace Anubis;

use Anubis\Exception\VerificationException;

/**
 * PASETO v4.public — Ed25519-signed tokens — over ext-sodium alone.
 *
 * Token layout:
 *
 *     v4.public.<b64url(message || signature)>[.<b64url(footer)>]
 *
 * where signature = Ed25519-Sign(sk, PAE([h, m, f, i])). PAE is the spec's
 * Pre-Authentication Encoding; it makes the signed byte string injective over
 * its pieces, which is what stops a footer byte being reinterpreted as a
 * message byte.
 *
 * The primitive is never hand-rolled: sodium_crypto_sign_verify_detached does
 * the curve work. Only the format layer is written here.
 */
final class Paseto
{
    public const HEADER = 'v4.public.';
    private const SIGNATURE_BYTES = 64;
    public const PUBLIC_KEY_BYTES = 32;

    /** Strict base64url: a token is generated, never typed, so a stray
     * character means tampering rather than a formatting preference. */
    public static function b64urlDecode(string $s): string
    {
        if ($s !== '' && preg_match('/^[A-Za-z0-9_-]+$/', $s) !== 1) {
            throw new VerificationException('anubis: malformed token');
        }
        $decoded = base64_decode(strtr($s, '-_', '+/'), true);
        if ($decoded === false) {
            throw new VerificationException('anubis: malformed token');
        }
        return $decoded;
    }

    public static function b64urlEncode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /** LE64 with the most significant bit cleared, per the specification. */
    private static function le64(int $n): string
    {
        return pack('P', $n & 0x7FFFFFFFFFFFFFFF);
    }

    /** @param string[] $pieces */
    public static function pae(array $pieces): string
    {
        $out = self::le64(count($pieces));
        foreach ($pieces as $p) {
            $out .= self::le64(strlen($p)) . $p;
        }
        return $out;
    }

    /**
     * Split a token WITHOUT verifying it.
     *
     * The result is untrusted until verify() succeeds. It exists so the kid can
     * be read from the footer to select a key — a read that may only ever index
     * a bounded, already-loaded map.
     *
     * @return array{message: string, signature: string, footer: string}
     */
    public static function parse(string $token): array
    {
        if (!str_starts_with($token, self::HEADER)) {
            throw new VerificationException('anubis: not a v4.public token');
        }
        $rest = substr($token, strlen(self::HEADER));
        $footerPart = '';
        $dot = strpos($rest, '.');
        if ($dot !== false) {
            $bodyPart = substr($rest, 0, $dot);
            $footerPart = substr($rest, $dot + 1);
            if ($footerPart === '' || str_contains($footerPart, '.')) {
                throw new VerificationException('anubis: malformed token');
            }
        } else {
            $bodyPart = $rest;
        }
        $body = self::b64urlDecode($bodyPart);
        if (strlen($body) < self::SIGNATURE_BYTES) {
            throw new VerificationException('anubis: malformed token');
        }
        $footer = $footerPart === '' ? '' : self::b64urlDecode($footerPart);
        $cut = strlen($body) - self::SIGNATURE_BYTES;

        return [
            'message' => substr($body, 0, $cut),
            'signature' => substr($body, $cut),
            'footer' => $footer,
        ];
    }

    /**
     * Verify a token and return its parts.
     *
     * @return array{message: string, signature: string, footer: string}
     */
    public static function verify(string $publicKey, string $token, string $implicit = ''): array
    {
        if (strlen($publicKey) !== self::PUBLIC_KEY_BYTES) {
            throw new VerificationException('anubis: wrong key size');
        }
        $parsed = self::parse($token);
        $m2 = self::pae([self::HEADER, $parsed['message'], $parsed['footer'], $implicit]);
        if (!sodium_crypto_sign_verify_detached($parsed['signature'], $m2, $publicKey)) {
            throw new VerificationException('anubis: signature verification failed');
        }
        return $parsed;
    }
}
