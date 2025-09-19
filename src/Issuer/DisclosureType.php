<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Issuer;

/**
 * Distinguishes disclosures for object properties vs array elements (Sections 4.2.1 and 4.2.2).
 */
enum DisclosureType: string
{
    case Object = 'object';
    case ArrayElement = 'array';
}
