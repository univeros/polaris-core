<?php

declare(strict_types=1);

namespace Polaris\Passkey\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passkey\PasskeyException;
use Polaris\Passkey\PasskeyService;

/**
 * `DELETE /passkey/{id}`: removes a passkey and the factor it backs.
 */
final class DeleteEndpoint extends PasskeyEndpoint
{
    public function __construct(private readonly PasskeyService $passkeys)
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
            $this->passkeys->delete($this->actorId($token), (string) $input->get('id'));
        } catch (PasskeyException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}
