<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Tests\Unit;

use InvalidArgumentException;
use Nyra\SdJwt\Holder\KeyBindingOptions;
use PHPUnit\Framework\TestCase;

final class KeyBindingOptionsTest extends TestCase
{
    public function testConstructorStoresValues(): void
    {
        $options = new KeyBindingOptions(
            audience: 'https://verifier.example',
            nonce: 'nonce-123',
            issuedAt: 1_700_000_000,
            additionalClaims: ['scope' => 'openid'],
            headers: ['kid' => 'holder-key']
        );

        self::assertSame('https://verifier.example', $options->audience);
        self::assertSame('nonce-123', $options->nonce);
        self::assertSame(1_700_000_000, $options->issuedAt);
        self::assertSame(['scope' => 'openid'], $options->additionalClaims);
        self::assertSame(['kid' => 'holder-key'], $options->headers);
    }

    public function testConstructorRejectsEmptyAudience(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key Binding audience must not be empty.');

        new KeyBindingOptions('', 'nonce');
    }

    public function testConstructorRejectsEmptyNonce(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key Binding nonce must not be empty.');

        new KeyBindingOptions('https://verifier.example', '');
    }
}
