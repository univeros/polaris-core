<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\SocialException;
use Polaris\Social\SocialService;

/**
 * `POST /social/{provider}/token`: a provider access token for the caller, refreshed when expiring.
 */
final class TokenEndpoint extends SocialEndpoint
{
    public function __construct(private readonly SocialService $social)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        try {
            $issued = $this->social->token($this->actorId($token), self::provider($input));
        } catch (SocialException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $issued]);
    }
}
