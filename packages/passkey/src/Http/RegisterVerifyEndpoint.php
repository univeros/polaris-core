<?php

declare(strict_types=1);

namespace Polaris\Passkey\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Model\User;
use Polaris\Passkey\PasskeyException;
use Polaris\Passkey\PasskeyService;
use Polaris\Repository\UserRepository;

/**
 * `POST /passkey/register/verify`: stores the credential the browser created.
 */
final class RegisterVerifyEndpoint extends PasskeyEndpoint
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
        $credential = self::credential($input);
        if ($credential === null) {
            return $this->invalid('credential is required.');
        }
        try {
            $registered = $this->passkeys->register($user, $credential, self::name($input));
        } catch (PasskeyException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(201, ['data' => ['passkey' => $registered['passkey']->toArray(), 'recovery_codes' => $registered['recovery_codes']]]);
    }
}
