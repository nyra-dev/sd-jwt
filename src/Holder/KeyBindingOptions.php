<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Holder;

use InvalidArgumentException;

/**
 * Options required to create Key Binding JWTs per Section 4.3.
 */
final class KeyBindingOptions
{
    /**
     * @param array<string,mixed> $additionalClaims
     * @param array<string,mixed> $headers
     */
    public function __construct(
        public readonly string $audience,
        public readonly string $nonce,
        public readonly ?int $issuedAt = null,
        public readonly array $additionalClaims = [],
        public readonly array $headers = []
    ) {
        if ($audience === '') {
            throw new InvalidArgumentException('Key Binding audience must not be empty.');
        }

        if ($nonce === '') {
            throw new InvalidArgumentException('Key Binding nonce must not be empty.');
        }
    }
}
