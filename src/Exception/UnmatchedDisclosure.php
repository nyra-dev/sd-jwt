<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Exception;

/**
 * Thrown when a supplied disclosure does not match a digest within the SD-JWT (Section 7.3 step 5).
 */
final class UnmatchedDisclosure extends SdJwtException
{
}
