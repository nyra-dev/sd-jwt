<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Issuer;

use Nyra\SdJwt\Hash\DigestCalculator;
use Nyra\SdJwt\Jwt\JwtSignerInterface;
use Nyra\SdJwt\Random\RandomSaltGenerator;
use Nyra\SdJwt\Random\SaltGeneratorInterface;
use JsonException;

/**
 * Issues SD-JWTs following the draft's issuance algorithm (Section 5.1).
 */
final class SdJwtIssuer
{
    private readonly SaltGeneratorInterface $saltGenerator;
    private readonly DigestCalculator $digestCalculator;

    public function __construct(
        private readonly JwtSignerInterface $signer,
        ?SaltGeneratorInterface $saltGenerator = null,
        ?DigestCalculator $digestCalculator = null
    ) {
        $this->saltGenerator = $saltGenerator ?? new RandomSaltGenerator();
        $this->digestCalculator = $digestCalculator ?? new DigestCalculator();
    }

    /**
     * @param array<string,mixed> $claims
     *
     * @throws JsonException
     */
    public function issue(array $claims, ?IssuerOptions $options = null): IssuedSdJwt
    {
        $options ??= new IssuerOptions();
        $hashAlgorithm = $options->hashAlgorithm ?? $this->digestCalculator->defaultAlgorithm();

        $processor = new SelectiveDisclosureProcessor($this->saltGenerator, $this->digestCalculator, $hashAlgorithm);
        $result = $processor->process($claims);

        $payload = $result->payload();

        if ($options->includeHashClaim) {
            $payload['_sd_alg'] = $hashAlgorithm; // Section 4.1.1
        }

        $jwt = $this->signer->sign($payload, $options->headers);

        return new IssuedSdJwt($jwt, $payload, $result->disclosures(), $hashAlgorithm);
    }
}
