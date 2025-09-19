<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Random;

use GhostZero\SdJwt\Support\Base64Url;

/**
 * Generates 128-bit salts encoded for disclosures as required by Section 4.2.1.
 */
final class RandomSaltGenerator implements SaltGeneratorInterface
{
    public function __construct(private readonly int $bytes = 16)
    {
    }

    public function generate(): string
    {
        return Base64Url::encode(random_bytes($this->bytes));
    }
}
