<?php

declare(strict_types=1);

namespace Polaris\Http\Jwks;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Token\JwkSet;

/**
 * Domain behind `GET /auth/.well-known/jwks.json`: serves the public signing key as a
 * JWK Set keyed by `kid`, so resource servers can verify access tokens.
 *
 * The endpoint is public (no secrets are exposed — only the public key) and depends only
 * on the validated {@see Secrets} and {@see AuthConfig} bound at boot.
 */
final class JwksEndpoint extends Endpoint
{
    public function __construct(
        private readonly Secrets $secrets,
        private readonly AuthConfig $config,
    ) {
    }

    /**
     * @inheritDoc
     */
    #[Override]
    public function __invoke(Input $input): Result
    {
        $keys = [$this->secrets->jwtKid => $this->secrets->jwtPublicKey];
        if ($this->secrets->jwtPreviousPublicKey !== null && $this->secrets->jwtPreviousKid !== null) {
            // Rotation overlap: the retiring key stays verifiable for one access-TTL window.
            $keys[$this->secrets->jwtPreviousKid] = $this->secrets->jwtPreviousPublicKey;
        }

        return $this->respond(200, JwkSet::fromPublicKeys($keys, $this->config->accessToken->signer));
    }
}
