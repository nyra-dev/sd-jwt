<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Issuer;

/**
 * Options controlling issuance of SD-JWTs.
 */
final class IssuerOptions
{
    /**
     * @param array<string,mixed> $headers Additional protected headers for the issuer-signed JWT.
     */
    public function __construct(
        public readonly array $headers = [],
        public readonly ?string $hashAlgorithm = null,
        public readonly bool $includeHashClaim = true
    ) {
    }
}
