<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Issuer;

use Nyra\SdJwt\Support\PresentationSerializer;

use function array_map;

/**
 * Immutable value representing the issued SD-JWT artefacts.
 */
final class IssuedSdJwt
{
    /**
     * @param array<string,mixed> $payload
     * @param list<Disclosure> $disclosures
     */
    public function __construct(
        private readonly string $jwt,
        private readonly array $payload,
        private readonly array $disclosures,
        private readonly string $hashAlgorithm,
        private readonly ?string $keyBindingJwt = null
    ) {
    }

    public function jwt(): string
    {
        return $this->jwt;
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

    /**
     * @return array<string,Disclosure>
     */
    public function disclosuresByPath(): array
    {
        $map = [];

        foreach ($this->disclosures as $disclosure) {
            $map[$disclosure->pathString()] = $disclosure;
        }

        return $map;
    }

    public function hashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    public function keyBindingJwt(): ?string
    {
        return $this->keyBindingJwt;
    }

    public function withKeyBindingJwt(string $keyBindingJwt): self
    {
        return new self(
            $this->jwt,
            $this->payload,
            $this->disclosures,
            $this->hashAlgorithm,
            $keyBindingJwt
        );
    }

    /**
     * Serialises the SD-JWT following Section 4 with an optional Key Binding JWT.
     */
    public function toCompactPresentation(): string
    {
        $disclosures = array_map(static fn (Disclosure $disclosure): string => $disclosure->encoded(), $this->disclosures);

        if ($this->keyBindingJwt !== null) {
            return PresentationSerializer::sdJwtWithKeyBinding($this->jwt, $disclosures, $this->keyBindingJwt);
        }

        return PresentationSerializer::sdJwt($this->jwt, $disclosures);
    }
}
