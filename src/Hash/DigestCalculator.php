<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Hash;

use GhostZero\SdJwt\Exception\UnsupportedHashAlgorithm;
use GhostZero\SdJwt\Support\Base64Url;

/**
 * Computes disclosure digests per Section 4.2.3 using hash algorithms registered via Section 4.1.1.
 */
final class DigestCalculator
{
    /**
     * @var array<string,string>
     */
    private const HASH_ALIASES = [
        'sha-256' => 'sha256',
        'sha-384' => 'sha384',
        'sha-512' => 'sha512',
    ];

    public function __construct(private readonly string $default = 'sha-256')
    {
    }

    public function defaultAlgorithm(): string
    {
        return $this->default;
    }

    public function ensureSupported(string $algorithm): void
    {
        if (!isset(self::HASH_ALIASES[$algorithm])) {
            throw new UnsupportedHashAlgorithm(sprintf('Unsupported hash algorithm "%s".', $algorithm));
        }
    }

    public function calculate(string $algorithm, string $encodedDisclosure): string
    {
        $this->ensureSupported($algorithm);

        $binary = hash(self::HASH_ALIASES[$algorithm], $encodedDisclosure, true);

        return Base64Url::encode($binary);
    }
}
