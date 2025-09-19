<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Exception;

/**
 * Raised when a disclosure tries to overwrite an existing claim (Section 7.3 step 3.2.3).
 */
final class DuplicateClaim extends SdJwtException
{
}
