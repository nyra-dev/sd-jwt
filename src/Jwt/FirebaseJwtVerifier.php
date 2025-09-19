<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Jwt;

use GhostZero\SdJwt\Exception\SignatureVerificationFailed;
use GhostZero\SdJwt\Support\Json;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;
use Throwable;

/**
 * Validates JWT signatures using firebase/php-jwt implementation.
 */
final class FirebaseJwtVerifier implements JwtVerifierInterface
{
    /**
     * @param Key|array<string,Key>|\ArrayAccess<string,Key> $keyOrKeys
     */
    public function __construct(private readonly Key|array|\ArrayAccess $keyOrKeys)
    {
    }

    public function verify(string $jwt): JwtVerificationResult
    {
        try {
            $header = new stdClass();
            $payload = JWT::decode($jwt, $this->keyOrKeys, $header);
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
