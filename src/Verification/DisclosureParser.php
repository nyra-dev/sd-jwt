<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Verification;

use Nyra\SdJwt\Exception\InvalidDisclosure;
use Nyra\SdJwt\Support\Base64Url;
use Nyra\SdJwt\Support\Json;
use JsonException;

/**
 * Validates disclosure structure per Sections 4.2.1 and 4.2.2.
 */
final class DisclosureParser
{
    /**
     * @throws InvalidDisclosure
     */
    public function parse(string $encoded, string $digest): DisclosureEnvelope
    {
        try {
            $json = Base64Url::decode($encoded);
            $data = Json::decode($json);
        } catch (JsonException $exception) {
            throw new InvalidDisclosure('Disclosure MUST be valid JSON (Section 4.2).', 0, $exception);
        }

        if (!is_array($data) || !array_is_list($data)) {
            throw new InvalidDisclosure('Disclosure MUST be a JSON array (Section 4.2).');
        }

        $count = count($data);
        if ($count === 3) {
            if (!is_string($data[0]) || !is_string($data[1])) {
                throw new InvalidDisclosure('Disclosure for object properties MUST contain string salt and claim name.');
            }

            return new DisclosureEnvelope($encoded, $digest, DisclosureKind::ObjectProperty, $data[0], $data[1], $data[2] ?? null);
        }

        if ($count === 2) {
            if (!is_string($data[0])) {
                throw new InvalidDisclosure('Disclosure for array elements MUST contain string salt.');
            }

            return new DisclosureEnvelope($encoded, $digest, DisclosureKind::ArrayElement, $data[0], null, $data[1] ?? null);
        }

        throw new InvalidDisclosure('Disclosure MUST contain two or three elements depending on its type (Section 4.2).');
    }
}
