<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Claim;

/**
 * Marker wrapper indicating a claim is selectively disclosable per Section 4.2.
 */
final class DisclosableValue
{
    public function __construct(private readonly mixed $value)
    {
    }

    public static function from(mixed $value): self
    {
        return new self($value);
    }

    public function value(): mixed
    {
        return $this->value;
    }
}
