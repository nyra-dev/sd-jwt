<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Tests\Unit;

use Nyra\SdJwt\Exception\InvalidPresentation;
use Nyra\SdJwt\Verification\Presentation;
use PHPUnit\Framework\TestCase;

final class PresentationTest extends TestCase
{
    public function testFromStringRejectsMissingTildeSeparator(): void
    {
        $this->expectException(InvalidPresentation::class);
        $this->expectExceptionMessage('An SD-JWT MUST contain at least one tilde separator');

        Presentation::fromString('issuer-only');
    }

    public function testFromStringRejectsMissingIssuerJwt(): void
    {
        $this->expectException(InvalidPresentation::class);
        $this->expectExceptionMessage('Missing issuer-signed JWT');

        Presentation::fromString('~disclosure~');
    }

    public function testFromStringRejectsEmptyDisclosure(): void
    {
        $this->expectException(InvalidPresentation::class);
        $this->expectExceptionMessage('Empty disclosure detected');

        Presentation::fromString('issuer.jwt~~key-binding');
    }

    public function testFromStringParsesKeyBindingWhenPresent(): void
    {
        $presentation = Presentation::fromString('issuer.jwt~disclosure~key-binding.jwt');

        self::assertSame('issuer.jwt', $presentation->issuerSignedJwt());
        self::assertSame(['disclosure'], $presentation->disclosures());
        self::assertSame('key-binding.jwt', $presentation->keyBindingJwt());
    }
}
