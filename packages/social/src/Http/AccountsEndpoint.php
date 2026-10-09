<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\Model\Account;
use Polaris\Social\SocialService;

use function array_map;

/**
 * `GET /social/accounts`: the caller's linked provider accounts.
 */
final class AccountsEndpoint extends SocialEndpoint
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

        return $this->respond(200, ['data' => array_map(static fn(Account $account): array => $account->toArray(), $this->social->accounts($this->actorId($token)))]);
    }
}
