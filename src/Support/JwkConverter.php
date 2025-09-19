<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Support;

use Nyra\Jwt\Jwk\JwkConverter as JwtJwkConverter;
use Nyra\Jwt\Key;

/**
 * @deprecated use Nyra\\Jwt\\Jwk\\JwkConverter directly.
 */
final class JwkConverter
{
    /**
     * @param array<string,mixed> $jwk
     */
    public static function toKey(array $jwk, string $algorithm): Key
    {
        return JwtJwkConverter::toKey($jwk, $algorithm);
    }

    /**
     * @param array<string,mixed> $jwk
     */
    public static function toKeyMaterial(array $jwk): string
    {
        return JwtJwkConverter::toKeyMaterial($jwk);
    }
}
