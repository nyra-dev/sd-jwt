<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Tests\Unit;

use Nyra\Jwt\Key;
use Nyra\SdJwt\Claim\SdClaim;
use Nyra\SdJwt\Exception\InvalidKeyBinding;
use Nyra\SdJwt\Exception\MissingKeyBinding;
use Nyra\SdJwt\Holder\KeyBindingOptions;
use Nyra\SdJwt\Holder\SdJwtHolder;
use Nyra\SdJwt\Issuer\IssuerOptions;
use Nyra\SdJwt\Issuer\IssuedSdJwt;
use Nyra\SdJwt\Issuer\SdJwtIssuer;
use Nyra\SdJwt\Hash\DigestCalculator;
use Nyra\SdJwt\Jwt\JwtVerificationResult;
use Nyra\SdJwt\Jwt\JwtVerifierInterface;
use Nyra\SdJwt\Jwt\NyraJwtSigner;
use Nyra\SdJwt\Jwt\NyraJwtVerifier;
use Nyra\SdJwt\Support\Base64Url;
use Nyra\SdJwt\Support\Json;
use Nyra\SdJwt\Support\PresentationSerializer;
use Nyra\SdJwt\Verification\SdJwtVerifier;
use Nyra\SdJwt\Verification\VerifierOptions;
use PHPUnit\Framework\TestCase;

use function array_replace_recursive;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function str_starts_with;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

final class SdJwtVerifierTest extends TestCase
{
    private SdJwtIssuer $issuer;

    private SdJwtVerifier $verifier;

    private NyraJwtSigner $holderSigner;

    private string $holderSecret = 'holder-secret';

    private ?string $stubSdHash = null;

    protected function setUp(): void
    {
        $issuerSigner = new NyraJwtSigner('issuer-secret', 'HS256');
        $this->issuer = new SdJwtIssuer($issuerSigner);

        $jwtKey = new Key('issuer-secret', 'HS256');
        $this->verifier = new SdJwtVerifier(new NyraJwtVerifier($jwtKey));

        $this->holderSigner = new NyraJwtSigner($this->holderSecret, 'HS256');
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
            new NyraJwtSigner($rsa['private'], 'RS256')
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
            new NyraJwtSigner($ec['private'], 'ES256')
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

    public function testVerifierRejectsKeyBindingWhenTypMissing(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->makeUnsignedKeyBindingJwt(['alg' => 'HS256'], $this->keyBindingPayload());

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('Key Binding JWT MUST use typ "kb+jwt".');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                currentTime: 1_700_000_000
            )
        );
    }

    public function testVerifierRejectsKeyBindingWhenAlgorithmMissing(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->makeUnsignedKeyBindingJwt(['typ' => 'kb+jwt'], $this->keyBindingPayload());

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('Key Binding JWT MUST declare a signing algorithm.');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                currentTime: 1_700_000_000
            )
        );
    }

    public function testVerifierRejectsKeyBindingWhenAlgorithmIsNone(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->makeUnsignedKeyBindingJwt(['typ' => 'kb+jwt', 'alg' => 'none'], $this->keyBindingPayload());

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('MUST NOT be used for Key Binding');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                currentTime: 1_700_000_000
            )
        );
    }

    public function testVerifierRejectsWhenKeyBindingKeyCannotBeResolved(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->makeUnsignedKeyBindingJwt(
            ['typ' => 'kb+jwt', 'alg' => 'HS256'],
            $this->keyBindingPayload()
        );

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('Unable to resolve Key Binding verification key.');

        $verifier->verify($this->stubPresentation($jwt), new VerifierOptions(requireKeyBinding: true));
    }

    public function testVerifierRejectsInvalidKeyBindingJwk(): void
    {
        $payload = ['_sd_alg' => 'sha-256', 'cnf' => ['jwk' => ['kty' => 'oct']]];
        $verifier = $this->verifierWithStubPayload($payload);
        $jwt = $this->makeUnsignedKeyBindingJwt(
            ['typ' => 'kb+jwt', 'alg' => 'HS256'],
            $this->keyBindingPayload()
        );

        $this->expectException(InvalidKeyBinding::class);

        $verifier->verify($this->stubPresentation($jwt), new VerifierOptions(requireKeyBinding: true));
    }

    public function testVerifierRejectsKeyBindingWithMissingIatClaim(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->signKeyBindingJwt($this->keyBindingPayload(['iat' => null]));

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('MUST include integer iat claim');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(requireKeyBinding: true, keyBindingKey: new Key('binding-secret', 'HS256'))
        );
    }

    public function testVerifierRejectsKeyBindingWhenIatTooFarInFuture(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $currentTime = 1000;
        $jwt = $this->signKeyBindingJwt($this->keyBindingPayload(['iat' => $currentTime + 61]));

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('iat is too far in the future');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                currentTime: $currentTime
            )
        );
    }

    public function testVerifierRejectsKeyBindingWhenIatTooOld(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $currentTime = 1000;
        $jwt = $this->signKeyBindingJwt($this->keyBindingPayload(['iat' => $currentTime - 301]));

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('iat is too old');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                currentTime: $currentTime
            )
        );
    }

    public function testVerifierRejectsKeyBindingWithMissingAudience(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->signKeyBindingJwt($this->keyBindingPayload(['aud' => '']));

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('include non-empty aud claim');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                currentTime: 1_700_000_000
            )
        );
    }

    public function testVerifierRejectsKeyBindingWhenAudienceDoesNotMatch(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->signKeyBindingJwt($this->keyBindingPayload(['aud' => 'https://other.example']));

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('aud does not match expected audience');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                expectedAudience: 'https://verifier.example',
                currentTime: 1_700_000_000
            )
        );
    }

    public function testVerifierRejectsKeyBindingWithMissingNonce(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->signKeyBindingJwt($this->keyBindingPayload(['nonce' => '']));

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('include non-empty nonce');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                currentTime: 1_700_000_000
            )
        );
    }

    public function testVerifierRejectsKeyBindingWhenSdHashDiffers(): void
    {
        $verifier = $this->verifierWithStubPayload(['_sd_alg' => 'sha-256']);
        $jwt = $this->signKeyBindingJwt($this->keyBindingPayload(['sd_hash' => 'not-the-right-hash']));

        $this->expectException(InvalidKeyBinding::class);
        $this->expectExceptionMessage('sd_hash does not match');

        $verifier->verify(
            $this->stubPresentation($jwt),
            new VerifierOptions(
                requireKeyBinding: true,
                keyBindingKey: new Key('binding-secret', 'HS256'),
                currentTime: 1_700_000_000
            )
        );
    }

    private function stubIssuerJwt(): string
    {
        return 'stub-issuer.jwt';
    }

    private function stubPresentation(?string $keyBindingJwt = null): string
    {
        if ($keyBindingJwt === null) {
            return PresentationSerializer::sdJwt($this->stubIssuerJwt(), []);
        }

        return PresentationSerializer::sdJwtWithKeyBinding($this->stubIssuerJwt(), [], $keyBindingJwt);
    }

    private function stubSdHash(): string
    {
        if ($this->stubSdHash === null) {
            $serialized = PresentationSerializer::sdJwt($this->stubIssuerJwt(), []);
            $this->stubSdHash = (new DigestCalculator())->calculate('sha-256', $serialized);
        }

        return $this->stubSdHash;
    }

    /**
     * @param array<string,mixed> $overrides
     *
     * @return array<string,mixed>
     */
    private function keyBindingPayload(array $overrides = []): array
    {
        $payload = [
            'iat' => 1_700_000_000,
            'aud' => 'https://verifier.example',
            'nonce' => 'nonce-value',
            'sd_hash' => $this->stubSdHash(),
        ];

        return array_replace($payload, $overrides);
    }

    /**
     * @param array<string,mixed> $header
     * @param array<string,mixed> $payload
     */
    private function makeUnsignedKeyBindingJwt(array $header, array $payload): string
    {
        return Base64Url::encode(Json::encode($header))
            . '.' . Base64Url::encode(Json::encode($payload))
            . '.signature';
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function signKeyBindingJwt(array $payload, string $secret = 'binding-secret'): string
    {
        $signer = new NyraJwtSigner($secret, 'HS256');

        return $signer->sign($payload, ['typ' => 'kb+jwt']);
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function verifierWithStubPayload(array $payload): SdJwtVerifier
    {
        $jwtVerifier = new class($payload) implements JwtVerifierInterface {
            public function __construct(private array $payload)
            {
            }

            public function verify(string $jwt): JwtVerificationResult
            {
                return new JwtVerificationResult(['alg' => 'HS256'], $this->payload);
            }
        };

        return new SdJwtVerifier($jwtVerifier);
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

        $x = $this->normaliseEcCoordinate($x);
        $y = $this->normaliseEcCoordinate($y);

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

    private function normaliseEcCoordinate(string $coordinate): string
    {
        $length = strlen($coordinate);
        if ($length === 32) {
            return $coordinate;
        }

        if ($length < 32) {
            return str_pad($coordinate, 32, "\0", STR_PAD_LEFT);
        }

        if ($length > 32 && str_starts_with($coordinate, "\0")) {
            return substr($coordinate, -32);
        }

        self::fail('Generated EC coordinate has unexpected length.');
    }
}
