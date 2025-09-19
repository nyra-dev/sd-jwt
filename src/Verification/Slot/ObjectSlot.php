<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Verification\Slot;

use GhostZero\SdJwt\Exception\DisallowedClaimName;
use GhostZero\SdJwt\Exception\DuplicateClaim;
use GhostZero\SdJwt\Exception\InvalidDisclosure;
use GhostZero\SdJwt\Verification\DisclosureEnvelope;
use GhostZero\SdJwt\Verification\DisclosureKind;
use GhostZero\SdJwt\Verification\VerifierState;

use function array_key_exists;
use function is_array;
use function sprintf;

/**
 * Slot for object properties referenced via _sd arrays (Section 4.2.4.1).
 */
final class ObjectSlot implements SlotInterface
{
    /**
     * @param list<int|string> $path path to the target object within the payload tree.
     */
    public function __construct(private readonly array $path)
    {
    }

    public function apply(VerifierState $state, DisclosureEnvelope $envelope): void
    {
        if ($envelope->kind() !== DisclosureKind::ObjectProperty) {
            throw new InvalidDisclosure('Disclosure type mismatch for object property.');
        }

        $claimName = $envelope->claimName();
        if ($claimName === null) {
            throw new InvalidDisclosure('Object property disclosures MUST include a claim name.');
        }

        if ($claimName === '_sd' || $claimName === '...') {
            throw new DisallowedClaimName('Disclosure MUST NOT introduce claims named "_sd" or "..." (Section 7.3 step 3.2.2).');
        }

        $object = &$state->getReference($this->path);
        if (!is_array($object)) {
            throw new InvalidDisclosure('Expected object when applying disclosure.');
        }

        if (array_key_exists($claimName, $object)) {
            throw new DuplicateClaim(sprintf('Claim "%s" already present at this level.', $claimName));
        }

        $object[$claimName] = $envelope->value();
        $state->discover($object[$claimName], [...$this->path, $claimName]);
    }
}
