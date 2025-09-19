<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Random;

/**
 * Generates salts for disclosures with sufficient entropy (Section 4.2.1, Section 9.3).
 */
interface SaltGeneratorInterface
{
    public function generate(): string;
}
