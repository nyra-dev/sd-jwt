<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Exception;

/**
 * Raised when the same digest appears more than once contrary to Section 4.1.
 */
final class DigestCollision extends SdJwtException
{
}
