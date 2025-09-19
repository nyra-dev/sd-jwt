<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Support;

use JsonException;

/**
 * @internal Thin wrapper around json_encode/json_decode with consistent flags.
 */
final class Json
{
    /**
     * @throws JsonException
     */
    public static function encode(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * @return array<mixed>|scalar|null
     *
     * @throws JsonException
     */
    public static function decode(string $value): mixed
    {
        return json_decode($value, true, 512, JSON_THROW_ON_ERROR);
    }
}
