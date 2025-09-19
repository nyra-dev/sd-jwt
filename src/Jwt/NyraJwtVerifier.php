<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Jwt;

use ArrayAccess;
use Nyra\Jwt\Exception\UnsupportedAlgorithm;
use Nyra\Jwt\Jwt;
use Nyra\Jwt\Key;
use Nyra\SdJwt\Exception\SignatureVerificationFailed;
use Nyra\SdJwt\Support\Json;
use stdClass;
use Throwable;

/**
 * Validates JWT signatures using the Nyra JWT implementation.
 */
final class NyraJwtVerifier implements JwtVerifierInterface
{
    /**
     * @param Key|array<string,Key>|ArrayAccess<string,Key> $keyOrKeys
     */
    public function __construct(private readonly Key|array|ArrayAccess $keyOrKeys)
    {
    }

    public function verify(string $jwt): JwtVerificationResult
    {
        try {
            $header = new stdClass();
            $payload = Jwt::decode($jwt, $this->keyOrKeys, $header);
        } catch (UnsupportedAlgorithm $exception) {
            throw new SignatureVerificationFailed($exception->getMessage(), (int) $exception->getCode(), $exception);
        } catch (Throwable $exception) {
            throw new SignatureVerificationFailed($exception->getMessage(), (int) $exception->getCode(), $exception);
        }

        if (!isset($header->alg) || $header->alg === 'none') {
            throw new SignatureVerificationFailed('The "none" algorithm is not permitted.');
        }

        return new JwtVerificationResult(
            $this->convertStdClassToArray($header),
            $this->convertStdClassToArray($payload)
        );
    }

    /**
     * @return array<string,mixed>
     */
    private function convertStdClassToArray(stdClass $object): array
    {
        $json = Json::encode($object);

        /** @var array<string,mixed> $decoded */
        $decoded = Json::decode($json);

        return $decoded;
    }
}
