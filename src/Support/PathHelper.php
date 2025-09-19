<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Support;

use InvalidArgumentException;

use function sprintf;

/**
 * Normalises claim paths for disclosure selection.
 */
final class PathHelper
{
    /**
     * @param list<int|string> $path
     */
    public static function toString(array $path): string
    {
        if ($path === []) {
            throw new InvalidArgumentException('Path cannot be empty.');
        }

        $parts = [];

        foreach ($path as $segment) {
            if (is_int($segment)) {
                if ($parts === []) {
                    $parts[] = sprintf('[%d]', $segment);
                    continue;
                }

                $parts[count($parts) - 1] .= sprintf('[%d]', $segment);
                continue;
            }

            if ($parts !== []) {
                $parts[] = (string) $segment;
                continue;
            }

            $parts[] = (string) $segment;
        }

        return implode('.', $parts);
    }

    /**
     * @return list<int|string>
     */
    public static function fromString(string $path): array
    {
        $path = trim($path);
        if ($path === '') {
            throw new InvalidArgumentException('Path must not be empty.');
        }

        $segments = [];
        $parts = explode('.', $path);

        foreach ($parts as $part) {
            if ($part === '') {
                throw new InvalidArgumentException('Path contains empty segments.');
            }

            $offset = 0;
            $length = strlen($part);

            if ($part[0] !== '[') {
                $bracketPos = strpos($part, '[');
                if ($bracketPos === false) {
                    $segments[] = $part;
                    continue;
                }

                $segments[] = substr($part, 0, $bracketPos);
                $offset = $bracketPos;
            }

            while ($offset < $length) {
                $slice = substr($part, $offset);
                if (!preg_match('/^\[([0-9]+)\]/', $slice, $matches)) {
                    throw new InvalidArgumentException(sprintf('Invalid array index syntax in path "%s".', $path));
                }

                $segments[] = (int) $matches[1];
                $offset += strlen($matches[0]);
            }
        }

        return $segments;
    }
}
