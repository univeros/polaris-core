<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Flow;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Sso\Http\SsoEndpoint;
use Polaris\Sso\SsoException;
use Polaris\Sso\SsoService;

/**
 * `POST /sso/logout`: the caller's sessions end here; the IdP's single-logout URL to send the browser
 * to, when the organization's provider has one.
 */
final class LogoutEndpoint extends SsoEndpoint
{
    public function __construct(private readonly SsoService $sso, private readonly UserRepository $users)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $organizationId = self::text($input->get('organization_id')) ?? $this->actorOrg($token);
        $user = $this->users->find($this->actorId($token));
        if ($organizationId === null || !$user instanceof User) {
            return $this->problem(422, 'sso/invalid_input', 'Invalid input', 'organization_id is required when the session has no active organization.');
        }
        try {
            $url = $this->sso->logout($user, $organizationId, self::text($input->get('provider_id')), self::text($input->get('post_logout_uri')), $this->client($input));
        } catch (SsoException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => ['status' => 'logged_out', 'url' => $url]]);
    }
}
