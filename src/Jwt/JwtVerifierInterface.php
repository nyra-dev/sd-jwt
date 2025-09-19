<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Jwt;

use Nyra\SdJwt\Exception\SignatureVerificationFailed;

/**
 * Validates issuer-signed JWTs per Section 7.1.
 */
interface JwtVerifierInterface
{
    /**
     * @return JwtVerificationResult
     *
     * @throws SignatureVerificationFailed
     */
    public function verify(string $jwt): JwtVerificationResult;
}
