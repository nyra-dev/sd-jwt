<?php

declare(strict_types=1);

use GhostZero\SdJwt\Claim\SdClaim;

return [
    'claims' => [
        'iss' => 'https://issuer.example.com',
        'iat' => 1683000000,
        'exp' => 1883000000,
        'sub' => 'structured-user-1',
        'address' => [
            'street_address' => SdClaim::disclose('Schulstr. 12'),
            'locality' => SdClaim::disclose('Schulpforta'),
            'region' => SdClaim::disclose('Sachsen-Anhalt'),
            'country' => SdClaim::disclose('DE'),
        ],
    ],
    'select' => [
        'address.street_address',
        'address.locality',
        'address.region',
        'address.country',
    ],
    'expected' => [
        'iss' => 'https://issuer.example.com',
        'iat' => 1683000000,
        'exp' => 1883000000,
        'sub' => 'structured-user-1',
        'address' => [
            'street_address' => 'Schulstr. 12',
            'locality' => 'Schulpforta',
            'region' => 'Sachsen-Anhalt',
            'country' => 'DE',
        ],
    ],
];
