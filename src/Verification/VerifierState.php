<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Verification;

use Nyra\SdJwt\Exception\DigestCollision;
use Nyra\SdJwt\Exception\DuplicateDisclosure;
use Nyra\SdJwt\Exception\InvalidDisclosure;
use Nyra\SdJwt\Exception\UnmatchedDisclosure;
use Nyra\SdJwt\Hash\DigestCalculator;
use Nyra\SdJwt\Verification\Slot\ArraySlot;
use Nyra\SdJwt\Verification\Slot\ObjectSlot;
use Nyra\SdJwt\Verification\Slot\SlotInterface;

use function array_filter;
use function array_is_list;
use function array_key_exists;
use function array_values;
use function count;
use function is_array;
use function is_string;
use function sprintf;

/**
 * Maintains verification state while applying disclosures per Section 7.3.
 */
final class VerifierState
{
    /**
     * @var array<string, SlotInterface>
     */
    private array $slots = [];

    /**
     * @var array<string, true>
     */
    private array $resolvedDigests = [];

    /**
     * @var array<string, true>
     */
    private array $seenDisclosures = [];

    private readonly DisclosureParser $parser;

    /**
     * @param array<string,mixed> $payload
     */
    public function __construct(
        private array $payload,
        private readonly string $hashAlgorithm,
        private readonly DigestCalculator $digestCalculator
    ) {
        $this->parser = new DisclosureParser();
        $this->discover($this->payload, []);
    }

    /**
     * Computes the digest and parses the disclosure structure.
     */
    public function envelope(string $encodedDisclosure): DisclosureEnvelope
    {
        if (isset($this->seenDisclosures[$encodedDisclosure])) {
            throw new DuplicateDisclosure('Disclosures MUST NOT be repeated (Section 4).');
        }

        $digest = $this->digestCalculator->calculate($this->hashAlgorithm, $encodedDisclosure);
        $envelope = $this->parser->parse($encodedDisclosure, $digest);
        $this->seenDisclosures[$encodedDisclosure] = true;

        return $envelope;
    }

    public function apply(DisclosureEnvelope $envelope): void
    {
        $digest = $envelope->digest();

        if (!isset($this->slots[$digest])) {
            throw new UnmatchedDisclosure(sprintf('No digest slot found for disclosure "%s".', $digest));
        }

        if (isset($this->resolvedDigests[$digest])) {
            throw new DuplicateDisclosure(sprintf('Disclosure for digest "%s" already processed.', $digest));
        }

        $slot = $this->slots[$digest];
        unset($this->slots[$digest]);
        $slot->apply($this, $envelope);

        $this->resolvedDigests[$digest] = true;
    }

    public function finalise(): void
    {
        $this->cleanupPlaceholders($this->payload);
        unset($this->payload['_sd_alg']);
    }

    /**
     * @return array<string,mixed>
     */
    public function payload(): array
    {
        return $this->payload;
    }

    /**
     * @param list<int|string> $path
     */
    public function &getReference(array $path): mixed
    {
        $ref = &$this->payload;
        foreach ($path as $segment) {
            $ref = &$ref[$segment];
        }

        return $ref;
    }

    /**
     * @param list<int|string> $path
     */
    public function discover(mixed &$value, array $path): void
    {
        if (!is_array($value)) {
            return;
        }

        if (array_is_list($value)) {
            foreach ($value as $index => &$child) {
                if (is_array($child) && array_key_exists('...', $child)) {
                    if (count($child) !== 1) {
                        throw new InvalidDisclosure('Array digest placeholder MUST NOT contain additional keys (Section 4.2.4.2).');
                    }

                    $digest = $child['...'];
                    if (!is_string($digest)) {
                        throw new InvalidDisclosure('Array digest placeholder MUST be a string (Section 4.2.4.2).');
                    }
                    $placeholder = new ArrayPlaceholder($digest);
                    $pathCopy = $path;
                    $this->registerSlot($digest, new ArraySlot($pathCopy, $index));
                    $value[$index] = $placeholder;
                    continue;
                }

                $this->discover($child, [...$path, $index]);
            }
            unset($child);

            return;
        }

        if ($path !== [] && array_key_exists('_sd_alg', $value)) {
            throw new InvalidDisclosure('The _sd_alg claim MUST only appear at the top level (Section 4.1.1).');
        }

        if (array_key_exists('_sd', $value)) {
            $digests = $value['_sd'];
            if (!is_array($digests)) {
                throw new InvalidDisclosure('The _sd claim MUST be an array of strings (Section 4.2.4.1).');
            }

            foreach ($digests as $digest) {
                if (!is_string($digest)) {
                    throw new InvalidDisclosure('Disclosure digests MUST be strings (Section 4.2.4.1).');
                }

                $this->registerSlot($digest, new ObjectSlot($path));
            }

            unset($value['_sd']);
        }

        foreach ($value as $key => &$child) {
            $this->discover($child, [...$path, $key]);
        }
        unset($child);
    }

    private function registerSlot(string $digest, SlotInterface $slot): void
    {
        if (isset($this->slots[$digest]) || isset($this->resolvedDigests[$digest])) {
            throw new DigestCollision(sprintf('Digest "%s" encountered more than once (Section 4.1).', $digest));
        }

        $this->slots[$digest] = $slot;
    }

    private function cleanupPlaceholders(mixed &$value): void
    {
        if (!is_array($value)) {
            return;
        }

        if (array_is_list($value)) {
            $value = array_values(array_filter($value, static fn (mixed $item): bool => !$item instanceof ArrayPlaceholder));
            foreach ($value as &$child) {
                $this->cleanupPlaceholders($child);
            }
            unset($child);

            return;
        }

        foreach ($value as &$child) {
            $this->cleanupPlaceholders($child);
        }
        unset($child);
    }
}
