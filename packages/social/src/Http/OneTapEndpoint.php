<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\SocialException;
use Polaris\Social\SocialService;

/**
 * `POST /social/google/one-tap`: the credential Google One Tap handed the page, for the session.
 */
final class OneTapEndpoint extends SocialEndpoint
{
    public function __construct(private readonly SocialService $social)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $credential = self::text($input, 'credential');
        if ($credential === null) {
            return $this->invalid('credential is required.');
        }
        try {
            $envelope = $this->social->idTokenSignIn('google', $credential, $this->client($input));
        } catch (SocialException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $envelope]);
    }
}
