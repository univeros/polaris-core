<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Authorization\InvitationService;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Exception\InvitationNotFoundException;

/**
 * `DELETE /orgs/{id}/invites/{inviteId}` — revoke a pending invitation; its token becomes useless.
 *
 * Gated on `members.invite` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation (revoking another org's invitation is indistinguishable from an unknown one: 404).
 */
final class RevokeInviteEndpoint extends Endpoint
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::MEMBERS_INVITE];

    public function __construct(private readonly InvitationService $invitations)
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

        $inviteId = (string) $input->get('inviteId');
        if ($inviteId === '') {
            return $this->unprocessable(['An invitation id is required.']);
        }

        try {
            $this->invitations->revoke($organizationId, $inviteId);
        } catch (InvitationNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        }

        return $this->respond(200, ['data' => ['revoked' => true]]);
    }
}
