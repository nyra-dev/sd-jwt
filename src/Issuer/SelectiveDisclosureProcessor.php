<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Issuer;

use GhostZero\SdJwt\Claim\DisclosableValue;
use GhostZero\SdJwt\Exception\DigestCollision;
use GhostZero\SdJwt\Hash\DigestCalculator;
use GhostZero\SdJwt\Random\SaltGeneratorInterface;
use GhostZero\SdJwt\Support\Base64Url;
use GhostZero\SdJwt\Support\Json;
use InvalidArgumentException;
use JsonException;

use function sprintf;

/**
 * Traverses the claim set and produces disclosures and digests per Section 4.2.
 */
final class SelectiveDisclosureProcessor
{
    /**
     * @var array<string, true>
     */
    private array $digests = [];

    public function __construct(
        private readonly SaltGeneratorInterface $saltGenerator,
        private readonly DigestCalculator $digestCalculator,
        private readonly string $hashAlgorithm
    ) {
        $this->digestCalculator->ensureSupported($hashAlgorithm);
    }

    /**
     * @param array<string,mixed> $claims
     *
     * @throws JsonException
     */
    public function process(array $claims): ProcessingResult
    {
        $this->digests = [];
        $disclosures = [];
        $payload = $this->processObject($claims, $disclosures, []);

        return new ProcessingResult($payload, $disclosures);
    }

    /**
     * @param array<string,mixed> $object
     * @param array<int, Disclosure> $disclosures
     * @param list<int|string> $path
     *
     * @return array<string,mixed>
     *
     * @throws JsonException
     */
    private function processObject(array $object, array &$disclosures, array $path): array
    {
        $result = [];
        $sdDigests = [];

        foreach ($object as $key => $value) {
            if ($key === '_sd' || $key === '...') {
                throw new InvalidArgumentException('Claim names "_sd" and "..." are reserved for disclosures (Section 4).');
            }

            $childPath = [...$path, $key];

            if ($value instanceof DisclosableValue) {
                $processedValue = $this->processValue($value->value(), $disclosures, $childPath);

                $disclosure = $this->createObjectDisclosure($childPath, $key, $processedValue);
                $sdDigests[] = $disclosure->digest();
                $disclosures[] = $disclosure;
                continue;
            }

            $result[$key] = $this->processValue($value, $disclosures, $childPath);
        }

        if ($sdDigests !== []) {
            sort($sdDigests, SORT_STRING);
            $result['_sd'] = $sdDigests;
        }

        return $result;
    }

    /**
     * @param array<int,Disclosure> $disclosures
     * @param list<int|string> $path
     *
     * @throws JsonException
     */
    private function processValue(mixed $value, array &$disclosures, array $path): mixed
    {
        if ($value instanceof DisclosableValue) {
            // Disclosures must be explicit at the parent level to avoid ambiguity.
            throw new InvalidArgumentException('Nested DisclosableValue wrappers are not allowed without an enclosing claim name.');
        }

        if (is_array($value)) {
            if (array_is_list($value)) {
                return $this->processArray($value, $disclosures, $path);
            }

            return $this->processObject($value, $disclosures, $path);
        }

        return $value;
    }

    /**
     * @param list<mixed> $items
     * @param array<int,Disclosure> $disclosures
     * @param list<int|string> $path
     *
     * @return list<mixed>
     *
     * @throws JsonException
     */
    private function processArray(array $items, array &$disclosures, array $path): array
    {
        $result = [];

        foreach ($items as $index => $item) {
            $childPath = [...$path, $index];

            if ($item instanceof DisclosableValue) {
                $processed = $this->processValue($item->value(), $disclosures, $childPath);
                $disclosure = $this->createArrayDisclosure($childPath, $processed);
                $result[] = ['...' => $disclosure->digest()];
                $disclosures[] = $disclosure;
                continue;
            }

            $result[] = $this->processValue($item, $disclosures, $childPath);
        }

        return $result;
    }

    /**
     * @throws JsonException
     */
    private function createObjectDisclosure(array $path, string $name, mixed $value): Disclosure
    {
        $salt = $this->saltGenerator->generate();
        $encodedJson = Json::encode([$salt, $name, $value]);
        $encodedDisclosure = Base64Url::encode($encodedJson);

        $digest = $this->registerDigest($encodedDisclosure);

        return new Disclosure($digest, $encodedDisclosure, DisclosureType::Object, $salt, $path, $name);
    }

    /**
     * @throws JsonException
     */
    private function createArrayDisclosure(array $path, mixed $value): Disclosure
    {
        $salt = $this->saltGenerator->generate();
        $encodedJson = Json::encode([$salt, $value]);
        $encodedDisclosure = Base64Url::encode($encodedJson);

        $digest = $this->registerDigest($encodedDisclosure);

        return new Disclosure($digest, $encodedDisclosure, DisclosureType::ArrayElement, $salt, $path);
    }

    private function registerDigest(string $encodedDisclosure): string
    {
        $digest = $this->digestCalculator->calculate($this->hashAlgorithm, $encodedDisclosure);

        if (isset($this->digests[$digest])) {
            throw new DigestCollision(sprintf('Digest "%s" already exists in SD-JWT payload.', $digest));
        }

        $this->digests[$digest] = true;

        return $digest;
    }
}
