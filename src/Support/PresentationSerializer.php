<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Support;

/**
 * Serialises SD-JWT compact presentations.
 */
final class PresentationSerializer
{
    /**
     * @param list<string> $disclosures
     */
    public static function sdJwt(string $issuerSignedJwt, array $disclosures): string
    {
        if ($disclosures === []) {
            return $issuerSignedJwt . '~';
        }

        return $issuerSignedJwt . '~' . implode('~', $disclosures) . '~';
    }

    /**
     * @param list<string> $disclosures
     */
    public static function sdJwtWithKeyBinding(string $issuerSignedJwt, array $disclosures, string $keyBindingJwt): string
    {
        if ($disclosures === []) {
            return $issuerSignedJwt . '~' . $keyBindingJwt;
        }

        return $issuerSignedJwt . '~' . implode('~', $disclosures) . '~' . $keyBindingJwt;
    }
}
