<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Exception;

/**
 * Indicates the issuer-signed JWT could not be validated per Section 7.1.
 */
final class SignatureVerificationFailed extends SdJwtException
{
}
