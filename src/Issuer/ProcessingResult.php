<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Issuer;

/**
 * Result of traversing the claim set to produce the SD-JWT payload and disclosures.
 */
final class ProcessingResult
{
    /**
     * @param array<string,mixed> $payload
     * @param list<Disclosure> $disclosures
     */
    public function __construct(
        private readonly array $payload,
        private readonly array $disclosures
    ) {
    }

    /**
     * @return array<string,mixed>
     */
    public function payload(): array
    {
        return $this->payload;
    }

    /**
     * @return list<Disclosure>
     */
    public function disclosures(): array
    {
        return $this->disclosures;
    }
}
