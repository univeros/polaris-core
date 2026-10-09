<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\SocialException;
use Polaris\Social\SocialService;

use function array_values;
use function array_filter;
use function is_array;

/**
 * `POST /social/{provider}/start`: where the browser goes to sign in with the provider.
 */
final class StartEndpoint extends SocialEndpoint
{
    public function __construct(private readonly SocialService $social)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scopes = $input->get('scopes');
        try {
            $started = $this->social->start(self::provider($input), self::text($input, 'redirect_uri'), is_array($scopes) ? array_values(array_filter($scopes, 'is_string')) : [], null);
        } catch (SocialException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $started]);
    }
}
