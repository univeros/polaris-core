<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Authorization\MembershipService;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Exception\AuthorizationException;
use Polaris\Exception\LastOwnerException;
use Polaris\Exception\MemberNotFoundException;

/**
 * `DELETE /orgs/{id}/members/{userId}` — remove a member from the organization.
 *
 * Gated on `members.remove` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation and delegates the owner-protection / last-owner invariants to {@see MembershipService}.
 */
final class RemoveMemberEndpoint extends Endpoint
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::MEMBERS_REMOVE];

    public function __construct(private readonly MembershipService $members)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $organizationId = (string) $input->get('id');
        if ($this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->forbidden('That organization is not your active organization.');
        }

        $targetUserId = (string) $input->get('userId');
        if ($targetUserId === '') {
            return $this->unprocessable(['A target user is required.']);
        }

        try {
            $this->members->removeMember((string) $token->getMetadata('sub'), $organizationId, $targetUserId);
        } catch (MemberNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (LastOwnerException $exception) {
            return $this->respond(409, ['error' => 'conflict', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => ['removed' => true]]);
    }
}
