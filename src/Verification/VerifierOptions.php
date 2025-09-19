<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Verification;

use Firebase\JWT\Key;

/**
 * Options customising SD-JWT verification.
 */
final class VerifierOptions
{
    public function __construct(
        public readonly bool $requireKeyBinding = false,
        public readonly ?Key $keyBindingKey = null,
        public readonly ?string $expectedAudience = null,
        public readonly ?string $expectedNonce = null,
        public readonly int $maxIssuedAtFutureSkew = 60,
        public readonly int $maxIssuedAtPastSkew = 300,
        public readonly ?int $currentTime = null
    ) {
    }
}
