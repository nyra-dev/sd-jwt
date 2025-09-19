<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Verification;

/**
 * Placeholder inserted where a selectively-disclosable array element was omitted.
 */
final class ArrayPlaceholder
{
    public function __construct(private readonly string $digest)
    {
    }

    public function digest(): string
    {
        return $this->digest;
    }
}
