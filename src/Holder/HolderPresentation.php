<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Holder;

use GhostZero\SdJwt\Support\PresentationSerializer;

/**
 * Holder-produced result ready for transmission.
 */
final class HolderPresentation
{
    /**
     * @param list<string> $disclosures
     */
    public function __construct(
        private readonly string $issuerSignedJwt,
        private readonly array $disclosures,
        private readonly ?string $keyBindingJwt = null
    ) {
    }

    public function issuerSignedJwt(): string
    {
        return $this->issuerSignedJwt;
    }

    /**
     * @return list<string>
     */
    public function disclosures(): array
    {
        return $this->disclosures;
    }

    public function keyBindingJwt(): ?string
    {
        return $this->keyBindingJwt;
    }

    public function toCompact(): string
    {
        if ($this->keyBindingJwt !== null) {
            return PresentationSerializer::sdJwtWithKeyBinding($this->issuerSignedJwt, $this->disclosures, $this->keyBindingJwt);
        }

        return PresentationSerializer::sdJwt($this->issuerSignedJwt, $this->disclosures);
    }
}
