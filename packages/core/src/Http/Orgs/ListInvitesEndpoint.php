<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Authorization\InvitationService;
use Polaris\Authorization\PermissionCatalog;

/**
 * `GET /orgs/{id}/invites` — list the organization's pending invitations.
 *
 * Gated on `members.invite` by the AuthorizationMiddleware (whoever may send invitations may see
 * the outstanding ones); this domain enforces cross-tenant isolation.
 */
final class ListInvitesEndpoint extends Endpoint
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

        return $this->respond(200, ['data' => $this->invitations->listPending($organizationId)]);
    }
}
