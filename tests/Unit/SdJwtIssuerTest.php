<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Tests\Unit;

use GhostZero\SdJwt\Claim\SdClaim;
use GhostZero\SdJwt\Issuer\IssuerOptions;
use GhostZero\SdJwt\Issuer\SdJwtIssuer;
use GhostZero\SdJwt\Jwt\FirebaseJwtSigner;
use PHPUnit\Framework\TestCase;

final class SdJwtIssuerTest extends TestCase
{
    public function testIssueCreatesDisclosuresAndPayloadPerDraft(): void
    {
        $signer = new FirebaseJwtSigner('test-secret', 'HS256');
        $issuer = new SdJwtIssuer($signer);

        $claims = [
            'iss' => 'https://issuer.example',
            'sub' => 'holder-123',
            'given_name' => 'Alice',
            'family_name' => SdClaim::disclose('Möbius'),
            'address' => [
                'locality' => 'Wonderland',
                'postal_code' => SdClaim::disclose('12345'),
            ],
            'nationalities' => ['DE', SdClaim::disclose('FR'), 'US'],
        ];

        $issued = $issuer->issue($claims, new IssuerOptions(headers: ['typ' => 'vc+sd-jwt']));

        self::assertArrayHasKey('_sd_alg', $issued->payload());
        self::assertSame('sha-256', $issued->hashAlgorithm());
        self::assertArrayHasKey('_sd', $issued->payload());
        self::assertCount(1, $issued->payload()['_sd']);

        $address = $issued->payload()['address'];
        self::assertArrayHasKey('_sd', $address);
        self::assertCount(1, $address['_sd']);

        $nationalities = $issued->payload()['nationalities'];
        self::assertIsArray($nationalities[1]);
        self::assertArrayHasKey('...', $nationalities[1]);
        self::assertIsString($nationalities[1]['...']);

        self::assertNotEmpty($issued->disclosures());
        $paths = array_map(static fn ($disclosure) => $disclosure->pathString(), $issued->disclosures());
        self::assertContains('family_name', $paths);
        self::assertContains('address.postal_code', $paths);
        self::assertContains('nationalities[1]', $paths);

        $digests = array_map(static fn ($disclosure) => $disclosure->digest(), $issued->disclosures());
        self::assertCount(count(array_unique($digests)), $digests, 'Digests MUST be unique.');

        $compact = $issued->toCompactPresentation();
        self::assertStringEndsWith('~', $compact);
    }
}
