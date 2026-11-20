<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\SocialException;
use Polaris\Social\SocialService;

use function array_filter;
use function array_key_exists;

use const ARRAY_FILTER_USE_BOTH;

/**
 * `GET /social/{provider}/callback` (and `POST`, for a `form_post` provider such as Apple): the
 * provider's answer; the browser that started the flow is sent on to the application with the hand-off
 * code.
 */
class CallbackEndpoint extends SocialEndpoint
{
    public function __construct(private readonly SocialService $social)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $cookies = self::cookies($input);
        // What the provider sent: the input without the route's provider and the cookies merged into it.
        $params = array_filter($input->all(), static fn(mixed $value, string|int $key): bool => $key !== 'provider' && (!array_key_exists($key, $cookies) || $cookies[$key] !== $value), ARRAY_FILTER_USE_BOTH);
        try {
            $url = $this->social->callback(self::provider($input), $params, $cookies, $this->client($input));
        } catch (SocialException $exception) {
            return $this->refuse($exception);
        }

        return new Result(302, [], ['Location' => $url]);
    }
}
