<?php

declare(strict_types=1);

namespace Polaris\Passkey\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Model\User;
use Polaris\Passkey\PasskeyService;
use Polaris\Repository\UserRepository;

/**
 * `POST /passkey/register/options`: the creation options for `navigator.credentials.create()`.
 */
final class RegisterOptionsEndpoint extends PasskeyEndpoint
{
    public function __construct(private readonly PasskeyService $passkeys, private readonly UserRepository $users)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        $user = $token === null ? null : $this->users->find($this->actorId($token));
        if (!$user instanceof User) {
            return $this->unauthorized();
        }

        return $this->respond(200, ['data' => $this->passkeys->registerOptions($user)]);
    }
}
