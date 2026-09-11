<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Mfa;

use Override;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Users;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Mfa\MfaManagementService;
use Polaris\Model\MfaFactor;

use function array_map;

use const DATE_ATOM;

/**
 * `GET /admin/users/{id}/mfa`: the user's factors, without their secrets or destinations.
 */
final class ListFactorsEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Users $users, private readonly MfaManagementService $mfa)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $userId = (string) $input->get('id');
        if ($this->users->find($userId) === null) {
            return $this->missing('The user does not exist.');
        }

        return $this->respond(200, ['data' => array_map(self::shape(...), $this->mfa->list($userId))]);
    }

    /**
     * @return array<string, mixed>
     */
    public static function shape(MfaFactor $factor): array
    {
        return [
            'id' => $factor->id,
            'type' => $factor->type,
            'label' => $factor->label,
            'is_default' => $factor->isDefault,
            'confirmed_at' => $factor->confirmedAt?->format(DATE_ATOM),
            'last_used_at' => $factor->lastUsedAt?->format(DATE_ATOM),
            'created_at' => $factor->createdAt->format(DATE_ATOM),
        ];
    }
}
