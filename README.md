# SD-JWT (Selective Disclosure JWT) for PHP

A robust PHP library for handling **Selective Disclosure JSON Web Tokens (SD-JWT)**. SD-JWT allows users to selectively
reveal claims within a JWT, helping to preserve privacy and minimize data sharing in authentication, credentials, and
digital identity workflows.

## Features

- **Selective Disclosure**: Reveal only required claims.
- **Privacy-Preserving**: Share credentials with minimal data exposure.
- **Full SD-JWT Flow**: Issue, hold, present, and verify tokens.
- **PSR & Modern PHP**: Strict types, exceptions, and enums.
- **Extensible**: Works with custom JWT signers and verifiers.
- **Well-Documented**: Clear API and example usage.

## Installation

```bash
composer require nyra-dev/sd-jwt
```

## Quick Start

### 1. Issuing an SD-JWT

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Nyra\Jwt\Key;
use Nyra\SdJwt\Claim\SdClaim;
use Nyra\SdJwt\Issuer\SdJwtIssuer;
use Nyra\SdJwt\Jwt\NyraJwtSigner;

// Prepare claims (mark claims for selective disclosure with SdClaim::disclose())
$claims = [
    "name" => SdClaim::disclose("Alice"),
    "email" => "alice@example.com",
    "address" => [
        "street" => SdClaim::disclose("Main St"),
        "city" => SdClaim::disclose("Wonderland"),
    ],
];

// Create a signer (using Nyra JWT)
$key = new Key('secret-key', 'HS256');
$signer = new NyraJwtSigner($key, 'HS256');

// Issue SD-JWT
$issuer = new SdJwtIssuer($signer);
$issued = $issuer->issue($claims);

// Result: $issued is an IssuedSdJwt object
echo $issued->jwt(); // Raw SD-JWT string
```

### 2. Holding and Presenting

```php
use Nyra\SdJwt\Holder\SdJwtHolder;

// Select which claims to disclose (by their paths)
$holder = new SdJwtHolder($issued);
$paths = ['name', 'address.city']; // Only reveal name and city

$presentation = $holder->buildPresentation($paths);

// $presentation->issuerSignedJwt() is the original SD-JWT
// $presentation->disclosures() contains disclosure strings to present
print_r($presentation->disclosures());
```

### 3. Verification

```php
use Nyra\SdJwt\Verification\SdJwtVerifier;
use Nyra\SdJwt\Jwt\NyraJwtVerifier;
use Nyra\SdJwt\Exception\SdJwtException;
use Nyra\Jwt\Key;

// Set up verifier with public key
$publicKey = new Key('secret-key', 'HS256');
$jwtVerifier = new NyraJwtVerifier($publicKey);
$verifier = new SdJwtVerifier($jwtVerifier);

// Verify the presented SD-JWT and disclosures
try {
    $verified = $verifier->verify($presentation->toCompact());
    $claims = $verified->payload();
    print_r($claims); // Only disclosed claims available
} catch (SdJwtException $e) {
    echo "Verification failed!";
}
```

## API Overview

- **Issuer**: `SdJwtIssuer` – issues SD-JWT tokens from claims.
- **Holder**: `SdJwtHolder` – selects disclosures and builds presentations.
- **Verifier**: `SdJwtVerifier` – checks SD-JWT signatures and reconstructs disclosed claims.
- **JWT Integration**: Use with any JWT implementation compatible with `JwtSignerInterface` and `JwtVerifierInterface`.

## Use Cases

- Digital credentials (e.g. reveal age but not birthdate)
- Privacy-preserving logins
- Data minimization for compliance (GDPR, etc.)

## Development

```bash
git clone https://github.com/nyra-dev/sd-jwt.git
cd sd-jwt
composer install
composer run test
```

## License

MIT License. See [LICENSE](LICENSE).

## References

- [IETF SD-JWT Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- [Nyra JWT](https://github.com/nyra-dev/jwt)
