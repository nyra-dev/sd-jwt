<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Issuer;

use GhostZero\SdJwt\Support\PathHelper;

/**
 * Encapsulates a disclosure string alongside its digest for issuance and presentation.
 */
final class Disclosure
{
    /**
     * @param list<int|string> $path
     */
    public function __construct(
        private readonly string $digest,
        private readonly string $encoded,
        private readonly DisclosureType $type,
        private readonly string $salt,
        private readonly array $path,
        private readonly ?string $claimName = null
    ) {
    }

    public function digest(): string
    {
        return $this->digest;
    }

    public function encoded(): string
    {
        return $this->encoded;
    }

    public function type(): DisclosureType
    {
        return $this->type;
    }

    public function salt(): string
    {
        return $this->salt;
    }

    /**
     * @return list<int|string>
     */
    public function path(): array
    {
        return $this->path;
    }

    public function pathString(): string
    {
        return PathHelper::toString($this->path);
    }

    public function claimName(): ?string
    {
        return $this->claimName;
    }

    public function __toString(): string
    {
        return $this->encoded;
    }
}
