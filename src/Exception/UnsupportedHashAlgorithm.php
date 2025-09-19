<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Exception;

/**
 * Thrown when a hash algorithm unsupported by Section 4.1.1 is requested.
 */
final class UnsupportedHashAlgorithm extends SdJwtException
{
}
