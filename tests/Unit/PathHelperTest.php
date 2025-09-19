<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Tests\Unit;

use InvalidArgumentException;
use Nyra\SdJwt\Support\PathHelper;
use PHPUnit\Framework\TestCase;

final class PathHelperTest extends TestCase
{
    public function testToStringHandlesNestedArrayIndexes(): void
    {
        $path = ['credentials', 'entries', 2, 1];

        self::assertSame('credentials.entries[2][1]', PathHelper::toString($path));
    }

    public function testToStringHandlesRootArray(): void
    {
        $path = [0, 'claims', 3];

        self::assertSame('[0].claims[3]', PathHelper::toString($path));
    }

    public function testToStringHandlesSingleProperty(): void
    {
        self::assertSame('family_name', PathHelper::toString(['family_name']));
    }

    public function testToStringRejectsEmptyPath(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Path cannot be empty.');

        PathHelper::toString([]);
    }

    public function testFromStringParsesComplexPath(): void
    {
        $parsed = PathHelper::fromString('address.aliases[3][1]');

        self::assertSame(['address', 'aliases', 3, 1], $parsed);
    }

    public function testFromStringParsesIndexedProperty(): void
    {
        self::assertSame(['nationalities', 1], PathHelper::fromString('nationalities[1]'));
    }

    public function testFromStringTrimsWhitespace(): void
    {
        self::assertSame(['address'], PathHelper::fromString('  address  '));
    }

    public function testFromStringRejectsInvalidSyntax(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid array index syntax');

        PathHelper::fromString('address[not-an-int]');
    }

    public function testFromStringRejectsEmptySegment(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Path contains empty segments.');

        PathHelper::fromString('address..postal_code');
    }

    public function testFromStringRejectsEmptyInput(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Path must not be empty.');

        PathHelper::fromString('   ');
    }
}
