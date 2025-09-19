<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Tests\Unit;

use Firebase\JWT\JWT;
use Nyra\SdJwt\Support\Base64Url;
use Nyra\SdJwt\Support\JwkConverter;
use PHPUnit\Framework\TestCase;

use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

final class JwkConverterTest extends TestCase
{
    public function testConvertsRsaJwkToPublicKey(): void
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource, 'Failed to create RSA key');

        self::assertTrue(openssl_pkey_export($resource, $privateKey));
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $jwk = [
            'kty' => 'RSA',
            'n' => Base64Url::encode($details['rsa']['n']),
            'e' => Base64Url::encode($details['rsa']['e']),
        ];

        $token = JWT::encode(['sub' => 'rsa'], $privateKey, 'RS256');
        $decoded = JWT::decode($token, JwkConverter::toKey($jwk, 'RS256'));

        self::assertSame('rsa', $decoded->sub);
    }

    public function testConvertsEcJwkToPublicKey(): void
    {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertNotFalse($resource, 'Failed to create EC key');

        self::assertTrue(openssl_pkey_export($resource, $privateKey));
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $x = $details['ec']['x'] ?? null;
        $y = $details['ec']['y'] ?? null;
        self::assertIsString($x);
        self::assertIsString($y);

        $jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => Base64Url::encode($x),
            'y' => Base64Url::encode($y),
        ];

        $token = JWT::encode(['sub' => 'ec'], $privateKey, 'ES256');
        $decoded = JWT::decode($token, JwkConverter::toKey($jwk, 'ES256'));

        self::assertSame('ec', $decoded->sub);
    }
}
