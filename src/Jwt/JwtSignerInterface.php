<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Jwt;

/**
 * Abstracts signing of issuer-signed JWTs per Section 4.1.
 */
interface JwtSignerInterface
{
    /**
     * Signs the provided payload and returns a compact JWS.
     *
     * @param array<string,mixed> $payload
     * @param array<string,mixed> $headers
     */
    public function sign(array $payload, array $headers = []): string;

    public function algorithm(): string;
}
