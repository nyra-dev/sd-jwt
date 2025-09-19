<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Tests\Unit;

use Nyra\SdJwt\Verification\VerifiedSdJwt;
use PHPUnit\Framework\TestCase;

final class VerifiedSdJwtTest extends TestCase
{
    public function testAccessorMethodsExposeVerificationResult(): void
    {
        $jwt = 'issuer.jwt';
        $header = ['alg' => 'HS256'];
        $payload = ['sub' => 'user-123'];
        $disclosures = ['abc', 'def'];
        $hashAlgorithm = 'sha-256';
        $keyBindingJwt = 'key.binding.jwt';
        $keyBindingHeaders = ['typ' => 'kb+jwt'];
        $keyBindingPayload = ['nonce' => 'xyz'];

        $verified = new VerifiedSdJwt(
            $jwt,
            $header,
            $payload,
            $disclosures,
            $hashAlgorithm,
            $keyBindingJwt,
            $keyBindingHeaders,
            $keyBindingPayload
        );

        self::assertSame($jwt, $verified->issuerSignedJwt());
        self::assertSame($header, $verified->header());
        self::assertSame($payload, $verified->payload());
        self::assertSame($disclosures, $verified->disclosures());
        self::assertSame($hashAlgorithm, $verified->hashAlgorithm());
        self::assertSame($keyBindingJwt, $verified->keyBindingJwt());
        self::assertSame($keyBindingHeaders, $verified->keyBindingHeaders());
        self::assertSame($keyBindingPayload, $verified->keyBindingPayload());
    }
}
