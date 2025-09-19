<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Jwt;

/**
 * Lightweight data transfer object for verified JWT header and payload.
 */
final class JwtVerificationResult
{
    /**
     * @param array<string,mixed> $header
     * @param array<string,mixed> $payload
     */
    public function __construct(
        private readonly array $header,
        private readonly array $payload
    ) {
    }

    /**
     * @return array<string,mixed>
     */
    public function header(): array
    {
        return $this->header;
    }

    /**
     * @return array<string,mixed>
     */
    public function payload(): array
    {
        return $this->payload;
    }
}
