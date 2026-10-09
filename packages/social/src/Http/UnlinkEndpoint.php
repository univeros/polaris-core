<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\SocialException;
use Polaris\Social\SocialService;

/**
 * `DELETE /social/{provider}`: unlinks the provider from the caller's account.
 */
final class UnlinkEndpoint extends SocialEndpoint
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
            $this->social->unlink($this->actorId($token), self::provider($input));
        } catch (SocialException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => ['status' => 'unlinked']]);
    }
}
