<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\SocialException;
use Polaris\Social\SocialService;

/**
 * `POST /social/exchange`: the hand-off code for the outcome (the session, or the linked account), once.
 */
final class ExchangeEndpoint extends SocialEndpoint
{
    public function __construct(private readonly SocialService $social)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $code = self::text($input, 'code');
        if ($code === null) {
            return $this->invalid('code is required.');
        }
        try {
            $outcome = $this->social->exchange($code);
        } catch (SocialException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $outcome]);
    }
}
