<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Verification\Slot;

use GhostZero\SdJwt\Verification\DisclosureEnvelope;
use GhostZero\SdJwt\Verification\VerifierState;

interface SlotInterface
{
    public function apply(VerifierState $state, DisclosureEnvelope $envelope): void;
}
