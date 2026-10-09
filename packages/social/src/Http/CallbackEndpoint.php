<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\SocialException;
use Polaris\Social\SocialService;

/**
 * `GET /social/{provider}/callback` (and `POST`, for a `form_post` provider such as Apple): the
 * provider's answer; the browser is sent on to the application with the hand-off code.
 */
class CallbackEndpoint extends SocialEndpoint
{
    public function __construct(private readonly SocialService $social)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $params = $input->all();
        unset($params['provider']);
        try {
            $url = $this->social->callback(self::provider($input), $params, $this->client($input));
        } catch (SocialException $exception) {
            return $this->refuse($exception);
        }

        return new Result(302, [], ['Location' => $url]);
    }
}
