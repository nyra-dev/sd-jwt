<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Verification;

use GhostZero\SdJwt\Exception\InvalidPresentation;

/**
 * Parses the compact SD-JWT presentation format defined in Section 4.
 */
final class Presentation
{
    /**
     * @param list<string> $disclosures
     */
    private function __construct(
        private readonly string $issuerSignedJwt,
        private readonly array $disclosures,
        private readonly ?string $keyBindingJwt
    ) {
    }

    public static function fromString(string $presentation): self
    {
        $parts = explode('~', $presentation);

        if (count($parts) < 2) {
            throw new InvalidPresentation('An SD-JWT MUST contain at least one tilde separator (Section 4).');
        }

        $keyBindingJwt = null;
        $last = array_pop($parts);
        if ($last !== '') {
            $keyBindingJwt = $last;
        }

        $issuerSignedJwt = array_shift($parts);
        if ($issuerSignedJwt === '' || $issuerSignedJwt === false) {
            throw new InvalidPresentation('Missing issuer-signed JWT in presentation.');
        }

        foreach ($parts as $index => $disclosure) {
            if ($disclosure === '') {
                throw new InvalidPresentation('Empty disclosure detected; holders MUST NOT send empty parts (Section 4).');
            }
        }

        /** @var list<string> $parts */
        $parts = array_values($parts);

        if ($keyBindingJwt === null && substr($presentation, -1) !== '~') {
            throw new InvalidPresentation('Presentations without a key binding JWT MUST end with a tilde (Section 4).');
        }

        return new self($issuerSignedJwt, $parts, $keyBindingJwt);
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
}
