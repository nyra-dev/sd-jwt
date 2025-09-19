<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Verification\Slot;

use Nyra\SdJwt\Exception\InvalidDisclosure;
use Nyra\SdJwt\Verification\ArrayPlaceholder;
use Nyra\SdJwt\Verification\DisclosureEnvelope;
use Nyra\SdJwt\Verification\DisclosureKind;
use Nyra\SdJwt\Verification\VerifierState;

use function is_array;
use function sprintf;

/**
 * Slot representing an omitted array element placeholder (Section 4.2.4.2).
 */
final class ArraySlot implements SlotInterface
{
    /**
     * @param list<int|string> $path
     */
    public function __construct(private readonly array $path, private readonly int $index)
    {
    }

    public function apply(VerifierState $state, DisclosureEnvelope $envelope): void
    {
        if ($envelope->kind() !== DisclosureKind::ArrayElement) {
            throw new InvalidDisclosure('Disclosure type mismatch for array element.');
        }

        $array = &$state->getReference($this->path);
        if (!is_array($array)) {
            throw new InvalidDisclosure('Expected array when applying disclosure.');
        }

        if (!isset($array[$this->index]) || !$array[$this->index] instanceof ArrayPlaceholder) {
            throw new InvalidDisclosure(sprintf('No placeholder present at array index %d.', $this->index));
        }

        $array[$this->index] = $envelope->value();
        $state->discover($array[$this->index], [...$this->path, $this->index]);
    }
}
