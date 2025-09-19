<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Verification\Slot;

use Nyra\SdJwt\Verification\DisclosureEnvelope;
use Nyra\SdJwt\Verification\VerifierState;

interface SlotInterface
{
    public function apply(VerifierState $state, DisclosureEnvelope $envelope): void;
}
