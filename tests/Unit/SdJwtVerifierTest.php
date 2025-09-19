<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Tests\Unit;

use Firebase\JWT\Key;
use GhostZero\SdJwt\Claim\SdClaim;
use GhostZero\SdJwt\Exception\InvalidKeyBinding;
use GhostZero\SdJwt\Exception\MissingKeyBinding;
use GhostZero\SdJwt\Holder\KeyBindingOptions;
use GhostZero\SdJwt\Holder\SdJwtHolder;
use GhostZero\SdJwt\Issuer\IssuerOptions;
use GhostZero\SdJwt\Issuer\IssuedSdJwt;
use GhostZero\SdJwt\Issuer\SdJwtIssuer;
use GhostZero\SdJwt\Jwt\FirebaseJwtSigner;
use GhostZero\SdJwt\Jwt\FirebaseJwtVerifier;
use GhostZero\SdJwt\Support\Base64Url;
use GhostZero\SdJwt\Verification\SdJwtVerifier;
use GhostZero\SdJwt\Verification\VerifierOptions;
use PHPUnit\Framework\TestCase;

use function array_replace_recursive;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

final class SdJwtVerifierTest extends TestCase
{
    private SdJwtIssuer $issuer;

    private SdJwtVerifier $verifier;

    private FirebaseJwtSigner $holderSigner;

    private string $holderSecret = 'holder-secret';

    protected function setUp(): void
    {
        $issuerSigner = new FirebaseJwtSigner('issuer-secret', 'HS256');
        $this->issuer = new SdJwtIssuer($issuerSigner);

        $jwtKey = new Key('issuer-secret', 'HS256');
        $this->verifier = new SdJwtVerifier(new FirebaseJwtVerifier($jwtKey));

        $this->holderSigner = new FirebaseJwtSigner($this->holderSecret, 'HS256');
    }

    public function testHolderAvailableDisclosures(): void
    {
        $issued = $this->issueCredential();
        $holder = new SdJwtHolder($issued);

        $paths = $holder->availableDisclosurePaths();

        self::assertContains('family_name', $paths);
        self::assertContains('address.postal_code', $paths);
        self::assertContains('nationalities[1]', $paths);
    }

    public function testVerifierReconstructsDisclosedClaims(): void
    {
        $issued = $this->issueCredential();
        $holder = new SdJwtHolder($issued);

        $presentation = $holder->buildPresentation(['family_name', 'nationalities[1]']);

        $verified = $this->verifier->verify($presentation->toCompact());
        $payload = $verified->payload();

        self::assertSame('Möbius', $payload['family_name']);
        self::assertSame('Alice', $payload['given_name']);
        self::assertSame(['DE', 'FR', 'US'], $payload['nationalities']);
        self::assertArrayHasKey('address', $payload);
        self::assertArrayNotHasKey('postal_code', $payload['address']);
        self::assertArrayHasKey('locality', $payload['address']);
        self::assertArrayNotHasKey('_sd', $payload);
        self::assertArrayNotHasKey('_sd_alg', $payload);
        self::assertNull($verified->keyBindingJwt());
    }

    public function testHolderBuildsPresentationWithKeyBinding(): void
    {
        $issued = $this->issueCredential();
        $holder = new SdJwtHolder($issued);

        $issuedAt = 1_700_000_000;
        $keyBindingOptions = new KeyBindingOptions(
            audience: 'https://verifier.example',
            nonce: '123abc',
            issuedAt: $issuedAt
        );

        $presentation = $holder->buildPresentation(
            ['family_name', 'nationalities[1]'],
            $keyBindingOptions,
            $this->holderSigner
        );

        $options = new VerifierOptions(
            requireKeyBinding: true,
            keyBindingKey: new Key($this->holderSecret, 'HS256'),
            expectedAudience: 'https://verifier.example',
            expectedNonce: '123abc',
            currentTime: $issuedAt
        );

        $verified = $this->verifier->verify($presentation->toCompact(), $options);

        self::assertNotNull($verified->keyBindingJwt());
        $keyBindingPayload = $verified->keyBindingPayload();
        self::assertIsArray($keyBindingPayload);
        self::assertSame('https://verifier.example', $keyBindingPayload['aud']);
        self::assertSame('123abc', $keyBindingPayload['nonce']);
        self::assertSame($issuedAt, $keyBindingPayload['iat']);
        self::assertArrayHasKey('sd_hash', $keyBindingPayload);
    }

    public function testVerifierRejectsMissingKeyBindingWhenRequired(): void
    {
        $this->expectException(MissingKeyBinding::class);

        $issued = $this->issueCredential();
        $holder = new SdJwtHolder($issued);
        $presentation = $holder->buildPresentation(['family_name']);

        $options = new VerifierOptions(requireKeyBinding: true, keyBindingKey: new Key($this->holderSecret, 'HS256'));
        $this->verifier->verify($presentation->toCompact(), $options);
    }

    public function testVerifierRejectsKeyBindingNonceMismatch(): void
    {
        $this->expectException(InvalidKeyBinding::class);

        $issued = $this->issueCredential();
        $holder = new SdJwtHolder($issued);

        $presentation = $holder->buildPresentation(
            ['family_name'],
            new KeyBindingOptions('https://verifier.example', 'nonce-ok', issuedAt: 1_700_000_000),
            $this->holderSigner
        );

        $options = new VerifierOptions(
            requireKeyBinding: true,
            keyBindingKey: new Key($this->holderSecret, 'HS256'),
            expectedAudience: 'https://verifier.example',
            expectedNonce: 'nonce-ko',
            currentTime: 1_700_000_000
        );

        $this->verifier->verify($presentation->toCompact(), $options);
    }

    public function testHolderCanWithholdAllSelectiveClaims(): void
    {
        $issued = $this->issueCredential();
        $holder = new SdJwtHolder($issued);

        $presentation = $holder->buildPresentation([]);
        $verified = $this->verifier->verify($presentation->toCompact());

        $payload = $verified->payload();

        self::assertArrayNotHasKey('family_name', $payload);
        self::assertSame('Alice', $payload['given_name']);
        self::assertSame('https://issuer.example', $payload['iss']);
    }

    public function testVerifierAcceptsRsaKeyBindingFromJwk(): void
    {
        $rsa = $this->generateRsaKeyPair();

        $issued = $this->issueCredential([
            'cnf' => ['jwk' => $rsa['jwk']],
        ]);

        $holder = new SdJwtHolder($issued);

        $issuedAt = 1_700_100_000;
        $presentation = $holder->buildPresentation(
            ['family_name'],
            new KeyBindingOptions('https://verifier.example', 'nonce-rsa', $issuedAt),
            new FirebaseJwtSigner($rsa['private'], 'RS256')
        );

        $options = new VerifierOptions(
            requireKeyBinding: true,
            expectedAudience: 'https://verifier.example',
            expectedNonce: 'nonce-rsa',
            currentTime: $issuedAt
        );

        $verified = $this->verifier->verify($presentation->toCompact(), $options);

        self::assertNotNull($verified->keyBindingJwt());
        self::assertSame('RS256', $verified->keyBindingHeaders()['alg'] ?? null);
        self::assertSame('nonce-rsa', $verified->keyBindingPayload()['nonce'] ?? null);
    }

    public function testVerifierAcceptsEcKeyBindingFromJwk(): void
    {
        $ec = $this->generateEcKeyPair();

        $issued = $this->issueCredential([
            'cnf' => ['jwk' => $ec['jwk']],
        ]);

        $holder = new SdJwtHolder($issued);

        $issuedAt = 1_700_200_000;
        $presentation = $holder->buildPresentation(
            ['family_name', 'nationalities[1]'],
            new KeyBindingOptions('https://verifier.example', 'nonce-ec', $issuedAt),
            new FirebaseJwtSigner($ec['private'], 'ES256')
        );

        $options = new VerifierOptions(
            requireKeyBinding: true,
            expectedAudience: 'https://verifier.example',
            expectedNonce: 'nonce-ec',
            currentTime: $issuedAt
        );

        $verified = $this->verifier->verify($presentation->toCompact(), $options);

        self::assertSame('ES256', $verified->keyBindingHeaders()['alg'] ?? null);
        self::assertSame('nonce-ec', $verified->keyBindingPayload()['nonce'] ?? null);
    }

    public function testStructuredFixtureMatchesExpected(): void
    {
        $fixture = require __DIR__ . '/../Fixtures/StructuredExample.php';

        $issued = $this->issuer->issue($fixture['claims'], new IssuerOptions(headers: ['typ' => 'vc+sd-jwt']));
        $holder = new SdJwtHolder($issued);
        $presentation = $holder->buildPresentation($fixture['select']);

        $payload = $this->verifier->verify($presentation->toCompact())->payload();

        self::assertSame($fixture['expected'], $payload);
    }

    public function testRecursiveFixtureMatchesExpected(): void
    {
        $fixture = require __DIR__ . '/../Fixtures/RecursiveExample.php';

        $issued = $this->issuer->issue($fixture['claims'], new IssuerOptions(headers: ['typ' => 'vc+sd-jwt']));
        $holder = new SdJwtHolder($issued);
        $presentation = $holder->buildPresentation($fixture['select']);

        $payload = $this->verifier->verify($presentation->toCompact())->payload();

        self::assertSame($fixture['expected'], $payload);
    }

    private function issueCredential(array $overrides = []): IssuedSdJwt
    {
        $claims = $this->baseClaims();
        if ($overrides !== []) {
            $claims = array_replace_recursive($claims, $overrides);
        }

        return $this->issuer->issue($claims, new IssuerOptions(headers: ['typ' => 'vc+sd-jwt']));
    }

    /**
     * @return array<string,mixed>
     */
    private function baseClaims(): array
    {
        return [
            'iss' => 'https://issuer.example',
            'sub' => 'holder-123',
            'given_name' => 'Alice',
            'family_name' => SdClaim::disclose('Möbius'),
            'address' => [
                'locality' => 'Wonderland',
                'postal_code' => SdClaim::disclose('12345'),
            ],
            'nationalities' => ['DE', SdClaim::disclose('FR'), 'US'],
            'cnf' => [
                'jwk' => [
                    'kty' => 'oct',
                    'k' => Base64Url::encode($this->holderSecret),
                ],
            ],
        ];
    }

    /**
     * @return array{private: string, jwk: array<string,string>}
     */
    private function generateRsaKeyPair(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource, 'Failed to generate RSA key pair.');

        self::assertTrue(openssl_pkey_export($resource, $private));
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        return [
            'private' => $private,
            'jwk' => [
                'kty' => 'RSA',
                'n' => Base64Url::encode($details['rsa']['n']),
                'e' => Base64Url::encode($details['rsa']['e']),
            ],
        ];
    }

    /**
     * @return array{private: string, jwk: array<string,string>}
     */
    private function generateEcKeyPair(): array
    {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertNotFalse($resource, 'Failed to generate EC key pair.');

        self::assertTrue(openssl_pkey_export($resource, $private));
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $x = $details['ec']['x'] ?? null;
        $y = $details['ec']['y'] ?? null;
        self::assertIsString($x);
        self::assertIsString($y);

        return [
            'private' => $private,
            'jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => Base64Url::encode($x),
                'y' => Base64Url::encode($y),
            ],
        ];
    }
}
