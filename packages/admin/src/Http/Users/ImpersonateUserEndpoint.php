<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Users;

use LogicException;
use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Impersonation;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Exception\AuthorizationException;
use Polaris\Exception\UserNotFoundException;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /admin/users/{id}/impersonate`: an access token acting as the user for one token lifetime.
 */
final class ImpersonateUserEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Impersonation $impersonation, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Impersonate);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $userId = (string) $input->get('id');
        try {
            $token = $this->impersonation->start($userId, $principal);
        } catch (UserNotFoundException $exception) {
            return $this->missing($exception->getMessage());
        } catch (LogicException $exception) {
            return $this->conflict($exception->getMessage());
        } catch (AuthorizationException $exception) {
            return $this->problem(403, 'admin/impersonation_denied', 'Impersonation denied', $exception->getMessage());
        }
        $this->audit->record(AdminAudit::USER_IMPERSONATED, $principal, $userId, data: ['expires_in' => $token['expires_in']], client: $this->client($input));

        return $this->respond(201, ['data' => $token]);
    }
}
