<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Exception;

/**
 * Raised when the same disclosure is presented more than once (Section 4, Holder requirements).
 */
final class DuplicateDisclosure extends SdJwtException
{
}
