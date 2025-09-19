<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Exception;

/**
 * Raised when a serialized SD-JWT presentation does not follow Section 4 rules.
 */
final class InvalidPresentation extends SdJwtException
{
}
