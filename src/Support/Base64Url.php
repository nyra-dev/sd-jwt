<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Support;

use InvalidArgumentException;

/**
 * @internal Utility helpers for base64url encoding and decoding used across the SD-JWT implementation.
 */
final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder === 1) {
            throw new InvalidArgumentException('Invalid base64url string.');
        }

        if ($remainder > 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'), true) ?: '';
    }
}
