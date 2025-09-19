<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Verification;

/**
 * Indicates whether a disclosure relates to an object property or array element.
 */
enum DisclosureKind: string
{
    case ObjectProperty = 'object';
    case ArrayElement = 'array';
}
