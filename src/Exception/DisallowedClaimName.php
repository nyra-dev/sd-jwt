<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Exception;

/**
 * Raised when a disclosure attempts to introduce forbidden claim names such as _sd or ...
 * (Section 7.3 step 3.2.2).
 */
final class DisallowedClaimName extends SdJwtException
{
}
