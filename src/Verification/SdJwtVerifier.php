<?php

declare(strict_types=1);

namespace GhostZero\SdJwt\Verification;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GhostZero\SdJwt\Exception\InvalidDisclosure;
use GhostZero\SdJwt\Exception\InvalidKeyBinding;
use GhostZero\SdJwt\Exception\KeyBindingVerificationFailed;
use GhostZero\SdJwt\Exception\MissingKeyBinding;
use GhostZero\SdJwt\Hash\DigestCalculator;
use GhostZero\SdJwt\Jwt\JwtVerifierInterface;
use GhostZero\SdJwt\Support\Base64Url;
use GhostZero\SdJwt\Support\Json;
use GhostZero\SdJwt\Support\JwkConverter;
use GhostZero\SdJwt\Support\PresentationSerializer;
use JsonException;
use stdClass;
use Throwable;

use function hash_equals;
use function is_array;
use function is_int;
use function is_string;
use function time;

/**
 * Verifies SD-JWT presentations in accordance with Section 7.
 */
final class SdJwtVerifier
{
    public function __construct(
        private readonly JwtVerifierInterface $jwtVerifier,
        private readonly DigestCalculator $digestCalculator = new DigestCalculator()
    ) {
    }

    public function verify(string $presentation, ?VerifierOptions $options = null): VerifiedSdJwt
    {
        $options ??= new VerifierOptions();
        $presentationParts = Presentation::fromString($presentation);

        $verification = $this->jwtVerifier->verify($presentationParts->issuerSignedJwt());
        $payload = $verification->payload();

        $hashAlgorithm = $payload['_sd_alg'] ?? $this->digestCalculator->defaultAlgorithm();
        if (!is_string($hashAlgorithm)) {
            throw new InvalidDisclosure('The _sd_alg claim MUST be a string when present (Section 4.1.1).');
        }
        $this->digestCalculator->ensureSupported($hashAlgorithm);

        $state = new VerifierState($payload, $hashAlgorithm, $this->digestCalculator);

        foreach ($presentationParts->disclosures() as $encodedDisclosure) {
            $envelope = $state->envelope($encodedDisclosure);
            $state->apply($envelope);
        }

        $state->finalise();

        $keyBindingJwt = $presentationParts->keyBindingJwt();
        $keyBindingHeaders = null;
        $keyBindingPayload = null;

        if ($keyBindingJwt === null) {
            if ($options->requireKeyBinding) {
                throw new MissingKeyBinding('Presentation is missing Key Binding JWT.');
            }
        } else {
            [$keyBindingHeaders, $keyBindingPayload] = $this->verifyKeyBinding(
                $keyBindingJwt,
                $payload,
                $presentationParts,
                $hashAlgorithm,
                $options
            );
        }

        return new VerifiedSdJwt(
            $presentationParts->issuerSignedJwt(),
            $verification->header(),
            $state->payload(),
            $presentationParts->disclosures(),
            $hashAlgorithm,
            $keyBindingJwt,
            $keyBindingHeaders,
            $keyBindingPayload
        );
    }

    /**
     * @return array{0: array<string,mixed>, 1: array<string,mixed>}
     */
    private function verifyKeyBinding(
        string $keyBindingJwt,
        array $sdJwtPayload,
        Presentation $presentation,
        string $hashAlgorithm,
        VerifierOptions $options
    ): array {
        $header = $this->decodeHeader($keyBindingJwt);

        if (!isset($header['typ']) || $header['typ'] !== 'kb+jwt') {
            throw new InvalidKeyBinding('Key Binding JWT MUST use typ "kb+jwt".');
        }

        if (!isset($header['alg']) || !is_string($header['alg'])) {
            throw new InvalidKeyBinding('Key Binding JWT MUST declare a signing algorithm.');
        }

        if ($header['alg'] === 'none') {
            throw new InvalidKeyBinding('The "none" algorithm MUST NOT be used for Key Binding.');
        }

        $key = $this->resolveKeyBindingKey($sdJwtPayload, $options, $header['alg']);

        try {
            $headersObj = new stdClass();
            $payloadObj = JWT::decode($keyBindingJwt, $key, $headersObj);
        } catch (Throwable $exception) {
            throw new KeyBindingVerificationFailed($exception->getMessage(), (int) $exception->getCode(), $exception);
        }

        $headerArray = $this->convertStdClassToArray($headersObj);
        $payloadArray = $this->convertStdClassToArray($payloadObj);

        $this->validateKeyBindingClaims($payloadArray, $presentation, $hashAlgorithm, $options);

        return [$headerArray, $payloadArray];
    }

    /**
     * @return array<string,mixed>
     */
    private function decodeHeader(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new InvalidKeyBinding('Key Binding JWT MUST contain three components.');
        }

        try {
            /** @var array<string,mixed> $header */
            $header = Json::decode(Base64Url::decode($parts[0]));
        } catch (JsonException $exception) {
            throw new InvalidKeyBinding('Key Binding JWT header is not valid JSON.', 0, $exception);
        }

        return $header;
    }

    private function resolveKeyBindingKey(array $sdJwtPayload, VerifierOptions $options, string $algorithm): Key
    {
        if ($options->keyBindingKey instanceof Key) {
            return $options->keyBindingKey;
        }

        if (isset($sdJwtPayload['cnf']) && is_array($sdJwtPayload['cnf'])) {
            $confirmation = $sdJwtPayload['cnf'];
            if (isset($confirmation['jwk']) && is_array($confirmation['jwk'])) {
                return $this->keyFromJwk($confirmation['jwk'], $algorithm);
            }
        }

        throw new InvalidKeyBinding('Unable to resolve Key Binding verification key.');
    }

    /**
     * @param array<string,mixed> $jwk
     */
    private function keyFromJwk(array $jwk, string $algorithm): Key
    {
        try {
            $keyMaterial = JwkConverter::toKeyMaterial($jwk);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidKeyBinding($exception->getMessage(), 0, $exception);
        }

        return new Key($keyMaterial, $algorithm);
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function validateKeyBindingClaims(
        array $payload,
        Presentation $presentation,
        string $hashAlgorithm,
        VerifierOptions $options
    ): void {
        if (!isset($payload['iat']) || !is_int($payload['iat'])) {
            throw new InvalidKeyBinding('Key Binding JWT MUST include integer iat claim.');
        }

        $now = $options->currentTime ?? time();
        if ($payload['iat'] > $now + $options->maxIssuedAtFutureSkew) {
            throw new InvalidKeyBinding('Key Binding JWT iat is too far in the future.');
        }

        if ($payload['iat'] < $now - $options->maxIssuedAtPastSkew) {
            throw new InvalidKeyBinding('Key Binding JWT iat is too old.');
        }

        if (!isset($payload['aud']) || !is_string($payload['aud']) || $payload['aud'] === '') {
            throw new InvalidKeyBinding('Key Binding JWT MUST include non-empty aud claim.');
        }

        if ($options->expectedAudience !== null && $payload['aud'] !== $options->expectedAudience) {
            throw new InvalidKeyBinding('Key Binding JWT aud does not match expected audience.');
        }

        if (!isset($payload['nonce']) || !is_string($payload['nonce']) || $payload['nonce'] === '') {
            throw new InvalidKeyBinding('Key Binding JWT MUST include non-empty nonce.');
        }

        if ($options->expectedNonce !== null && $payload['nonce'] !== $options->expectedNonce) {
            throw new InvalidKeyBinding('Key Binding JWT nonce does not match expected nonce.');
        }

        if (!isset($payload['sd_hash']) || !is_string($payload['sd_hash'])) {
            throw new InvalidKeyBinding('Key Binding JWT MUST include sd_hash claim.');
        }

        $expected = $this->digestCalculator->calculate(
            $hashAlgorithm,
            PresentationSerializer::sdJwt($presentation->issuerSignedJwt(), $presentation->disclosures())
        );

        if (!hash_equals($expected, $payload['sd_hash'])) {
            throw new InvalidKeyBinding('Key Binding sd_hash does not match presentation contents.');
        }
    }

    /**
     * @return array<string,mixed>
     */
    private function convertStdClassToArray(stdClass $object): array
    {
        try {
            /** @var array<string,mixed> $decoded */
            $decoded = Json::decode(Json::encode($object));
        } catch (JsonException $exception) {
            throw new InvalidKeyBinding('Failed to decode Key Binding JWT.', 0, $exception);
        }

        return $decoded;
    }
}
