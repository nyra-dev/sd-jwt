<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Verification;

/**
 * Result of verifying an SD-JWT presentation.
 */
final class VerifiedSdJwt
{
    /**
     * @param array<string,mixed> $header
     * @param array<string,mixed> $payload
     * @param list<string> $presentedDisclosures
     */
    public function __construct(
        private readonly string $issuerSignedJwt,
        private readonly array $header,
        private readonly array $payload,
        private readonly array $presentedDisclosures,
        private readonly string $hashAlgorithm,
        private readonly ?string $keyBindingJwt,
        private readonly ?array $keyBindingHeaders = null,
        private readonly ?array $keyBindingPayload = null
    ) {
    }

    public function issuerSignedJwt(): string
    {
        return $this->issuerSignedJwt;
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

    /**
     * @return list<string>
     */
    public function disclosures(): array
    {
        return $this->presentedDisclosures;
    }

    public function hashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    public function keyBindingJwt(): ?string
    {
        return $this->keyBindingJwt;
    }

    /**
     * @return array<string,mixed>|null
     */
    public function keyBindingHeaders(): ?array
    {
        return $this->keyBindingHeaders;
    }

    /**
     * @return array<string,mixed>|null
     */
    public function keyBindingPayload(): ?array
    {
        return $this->keyBindingPayload;
    }
}
