<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Claim;

/**
 * Convenience factory for selectively-disclosable values.
 */
final class SdClaim
{
    public static function disclose(mixed $value): DisclosableValue
    {
        return DisclosableValue::from($value);
    }
}
