<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Holder;

use Nyra\SdJwt\Hash\DigestCalculator;
use Nyra\SdJwt\Issuer\Disclosure;
use Nyra\SdJwt\Issuer\IssuedSdJwt;
use Nyra\SdJwt\Jwt\JwtSignerInterface;
use Nyra\SdJwt\Support\PathHelper;
use Nyra\SdJwt\Support\PresentationSerializer;
use InvalidArgumentException;

use function array_key_exists;
use function array_map;
use function count;
use function sprintf;
use function time;
use function usort;

/**
 * Holder helper that selects disclosures and optionally adds Key Binding.
 */
final class SdJwtHolder
{
    public function __construct(
        private readonly IssuedSdJwt $issued,
        private readonly DigestCalculator $digestCalculator = new DigestCalculator()
    ) {
    }

    /**
     * @return list<string>
     */
    public function availableDisclosurePaths(): array
    {
        return array_map(static fn (Disclosure $disclosure): string => $disclosure->pathString(), $this->issued->disclosures());
    }

    /**
     * Builds an SD-JWT or SD-JWT+KB presentation (Sections 4 and 4.3).
     */
    public function buildPresentation(
        ?array $paths = null,
        ?KeyBindingOptions $keyBindingOptions = null,
        ?JwtSignerInterface $keyBindingSigner = null
    ): HolderPresentation {
        $disclosureMap = $this->issued->disclosuresByPath();
        $selected = [];

        if ($paths !== null) {
            foreach ($paths as $path) {
                $canonical = $this->normalisePath($path);

                if (!array_key_exists($canonical, $disclosureMap)) {
                    throw new InvalidArgumentException(sprintf('Disclosure for path "%s" is not available.', $canonical));
                }

                $selected[$canonical] = $disclosureMap[$canonical];
            }
        }

        $selectedDisclosures = [];
        foreach ($this->issued->disclosures() as $disclosure) {
            $pathString = $disclosure->pathString();
            if ($paths === null || isset($selected[$pathString])) {
                $selectedDisclosures[] = $disclosure;
            }
        }

        usort(
            $selectedDisclosures,
            static fn (Disclosure $a, Disclosure $b): int => count($a->path()) <=> count($b->path())
        );

        $encodedDisclosures = array_map(static fn (Disclosure $disclosure): string => $disclosure->encoded(), $selectedDisclosures);

        $keyBindingJwt = null;
        if ($keyBindingOptions !== null) {
            if ($keyBindingSigner === null) {
                throw new InvalidArgumentException('Key Binding signer is required when Key Binding options are provided.');
            }

            $keyBindingJwt = $this->createKeyBindingJwt($encodedDisclosures, $keyBindingOptions, $keyBindingSigner);
        }

        return new HolderPresentation($this->issued->jwt(), $encodedDisclosures, $keyBindingJwt);
    }

    /**
     * @param list<string> $encodedDisclosures
     */
    private function createKeyBindingJwt(array $encodedDisclosures, KeyBindingOptions $options, JwtSignerInterface $signer): string
    {
        $serialized = PresentationSerializer::sdJwt($this->issued->jwt(), $encodedDisclosures);
        $sdHash = $this->digestCalculator->calculate($this->issued->hashAlgorithm(), $serialized);

        $issuedAt = $options->issuedAt ?? time();

        $payload = [
            'iat' => $issuedAt,
            'aud' => $options->audience,
            'nonce' => $options->nonce,
            'sd_hash' => $sdHash,
        ];

        foreach ($options->additionalClaims as $claim => $value) {
            if (array_key_exists($claim, $payload)) {
                throw new InvalidArgumentException(sprintf('Cannot override reserved Key Binding claim "%s".', $claim));
            }

            $payload[$claim] = $value;
        }

        $headers = ['typ' => 'kb+jwt'] + $options->headers;

        return $signer->sign($payload, $headers);
    }

    /**
     * @param string|array<int|string> $path
     */
    private function normalisePath(string|array $path): string
    {
        if (is_array($path)) {
            return PathHelper::toString($path);
        }

        return PathHelper::toString(PathHelper::fromString($path));
    }
}
