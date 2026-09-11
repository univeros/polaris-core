<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Mfa;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Users;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\MfaFactorRemoved;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Repository\MfaFactorRepository;
use Polaris\Repository\RecoveryCodeRepository;
use Psr\EventDispatcher\EventDispatcherInterface;

use function count;

/**
 * `DELETE /admin/users/{id}/mfa`: removes every factor and recovery code, enforced MFA or not, so a
 * locked-out user can enrol again at their next sign-in.
 */
final class ResetMfaEndpoint extends AdminEndpoint
{
    public function __construct(
        private readonly Users $users,
        private readonly MfaFactorRepository $factors,
        private readonly RecoveryCodeRepository $recoveryCodes,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly EventDispatcherInterface $events,
        private readonly AdminAudit $audit,
    ) {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Manage);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $userId = (string) $input->get('id');
        if ($this->users->find($userId) === null) {
            return $this->missing('The user does not exist.');
        }
        $removed = [];
        foreach ($this->factors->findBy(['userId' => $userId]) as $factor) {
            $this->unitOfWork->remove($factor);
            $removed[] = $factor->id;
        }
        foreach ($this->recoveryCodes->findBy(['userId' => $userId]) as $code) {
            $this->unitOfWork->remove($code);
        }
        $this->unitOfWork->flush();
        foreach ($removed as $factorId) {
            $this->events->dispatch(new MfaFactorRemoved($userId, $factorId));
        }
        $this->audit->record(AdminAudit::MFA_RESET, $principal, $userId, data: ['factors' => count($removed)], client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'reset', 'factors' => count($removed)]]);
    }
}
