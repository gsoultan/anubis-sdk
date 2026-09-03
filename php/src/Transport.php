<?php

declare(strict_types=1);

namespace Anubis;

use Anubis\Exception\UnavailableException;

/** @phpstan-type Response array{status:int, headers:array<string,string>, body:string} */
interface Transport
{
    /**
     * @param array<string, string> $headers
     * @return array{status:int, headers:array<string,string>, body:string}
     */
    public function send(string $method, string $url, array $headers, string $body): array;
}

final class CurlTransport implements Transport
{
    public function __construct(private readonly int $timeoutSeconds = 10)
    {
    }

    public function send(string $method, string $url, array $headers, string $body): array
    {
        $ch = curl_init($url);
        $out = [];
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            // A Connect procedure has no reason to redirect, and following one
            // would carry the credential to whatever host the Location names.
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => array_map(
                static fn (string $k, string $v): string => "{$k}: {$v}",
                array_keys($headers),
                array_values($headers),
            ),
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$out): int {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $out[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return strlen($line);
            },
        ]);
        $response = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            throw new UnavailableException("anubis: unavailable: {$error}");
        }
        return ['status' => $status, 'headers' => $out, 'body' => (string) $response];
    }
}
