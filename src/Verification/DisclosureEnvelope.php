<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Verification;

/**
 * Parsed disclosure ready to be merged into the payload.
 */
final class DisclosureEnvelope
{
    public function __construct(
        private readonly string $encoded,
        private readonly string $digest,
        private readonly DisclosureKind $kind,
        private readonly string $salt,
        private readonly ?string $claimName,
        private readonly mixed $value
    ) {
    }

    public function encoded(): string
    {
        return $this->encoded;
    }

    public function digest(): string
    {
        return $this->digest;
    }

    public function kind(): DisclosureKind
    {
        return $this->kind;
    }

    public function salt(): string
    {
        return $this->salt;
    }

    public function claimName(): ?string
    {
        return $this->claimName;
    }

    public function value(): mixed
    {
        return $this->value;
    }
}
