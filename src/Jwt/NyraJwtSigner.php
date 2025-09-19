<?php

declare(strict_types=1);

namespace Nyra\SdJwt\Jwt;

use InvalidArgumentException;
use Nyra\Jwt\Jwt;
use Nyra\Jwt\Key;

/**
 * Signs JWTs using the Nyra JWT implementation while honouring Section 7.1 algorithm requirements.
 */
final class NyraJwtSigner implements JwtSignerInterface
{
    public function __construct(
        private readonly Key|string $key,
        private readonly string $algorithm,
        private readonly ?string $keyId = null
    ) {
        if ($algorithm === 'none') {
            throw new InvalidArgumentException('The "none" algorithm MUST NOT be used (Section 7.3 step 2.1).');
        }
    }

    public function sign(array $payload, array $headers = []): string
    {
        $headers = $headers === [] ? null : $headers;

        return Jwt::encode($payload, $this->key, $this->algorithm, $this->keyId, $headers);
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }
}
