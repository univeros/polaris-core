<?php

declare(strict_types=1);

namespace Polaris\Username\Http;

use Override;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Username\UsernameException;
use Polaris\Username\Usernames;

use function is_string;

/**
 * `PATCH /username`: sets or changes the caller's username.
 */
final class UpdateEndpoint extends Endpoint
{
    public function __construct(private readonly Usernames $usernames)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $username = $input->get('username');
        $display = $input->get('display_username');
        if (!is_string($username) || ($display !== null && !is_string($display))) {
            return $this->problem(422, 'username/invalid', 'Invalid username', 'username is required.', ['errors' => ['username is required.']]);
        }
        try {
            $record = $this->usernames->set($this->actorId($token), $username, $display);
        } catch (UsernameException $exception) {
            return $exception->reason === UsernameException::TAKEN
                ? $this->problem(409, 'username/taken', 'Username taken', 'The username is taken.')
                : $this->problem(422, 'username/invalid', 'Invalid username', $exception->errors[0] ?? 'The username is not valid.', ['errors' => $exception->errors]);
        }

        return $this->respond(200, ['data' => $record->toArray()]);
    }
}
