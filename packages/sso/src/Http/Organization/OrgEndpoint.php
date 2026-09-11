<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Polaris\Contract\TokenInterface;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Http\SsoEndpoint;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;

/**
 * What the organization's self-service routes share: core's bearer and `org.update` gate the route
 * (the authorization middleware); the organization in the path must be the token's active one
 * (a superadmin excepted), then the provider must belong to it.
 */
abstract class OrgEndpoint extends SsoEndpoint
{
    /**
     * The token and the organization id when the caller may manage it; the problem otherwise.
     *
     * @return array{TokenInterface, string}|Result
     */
    protected function organization(Input $input): array|Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $organizationId = (string) $input->get('id');
        if ($organizationId === '' || $this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->problem(403, 'sso/forbidden', 'Forbidden', 'That organization is not your active organization.');
        }

        return [$token, $organizationId];
    }

    protected function provider(Providers $providers, Input $input, string $organizationId): Provider|Result
    {
        $provider = $providers->find((string) $input->get('providerId'));
        if (!$provider instanceof Provider || $provider->organizationId !== $organizationId) {
            return $this->problem(404, 'sso/not_found', 'Not found', 'The provider does not exist in this organization.');
        }

        return $provider;
    }

    /**
     * @param list<string> $errors
     */
    protected function invalid(string $detail, array $errors = []): Result
    {
        return $this->problem(422, 'sso/invalid_input', 'Invalid input', $detail, $errors === [] ? [] : ['errors' => $errors]);
    }
}
