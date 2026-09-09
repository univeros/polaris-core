<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Model\MfaFactor;
use Polaris\Identity\MfaFactorView;
use Polaris\Mfa\MfaManagementService;

use function array_map;

/**
 * `GET /auth/mfa/factors` — list the authenticated user's MFA factors (type, label, masked
 * destination, confirmed, default), including still-pending ones (spec §8).
 */
final class MfaFactorsEndpoint extends Endpoint
{
    public function __construct(private readonly MfaManagementService $service)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        if ($userId === '') {
            return $this->unauthorized();
        }

        $factors = array_map(
            static fn(MfaFactor $factor): array => MfaFactorView::of($factor)->toManagementArray(),
            $this->service->list($userId),
        );

        return $this->respond(200, ['data' => ['factors' => $factors]]);
    }
}
